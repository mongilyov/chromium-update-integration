#!/usr/bin/env python3
"""
run_integration_testing.py -- drive the browser-under-test through one update scenario and
report/assert the outcome. Does NOT run the update server; point --server at an already-
running one (see test_update_server.py).

WHAT IT DOES
    Launches, once, identically on every platform:
        <browser> --update-silent --update-without-timeout --update-server='<server>/<variant>'
    The browser downloads, verifies, installs (dpkg on Linux, installer on Windows, folder
    swap on macOS -- all BEFORE relaunch), then relaunches into a live window.

    The install takes real time, so the test polls the installed version until it changes
    (bounded by --timeout) rather than sleeping a fixed amount.

PER-OS LOGIC LIVES IN Platform SUBCLASSES
    LinuxPlatform / WindowsPlatform / MacOSPlatform each own how to read the installed
    version, enumerate processes by executable path, kill them, and run the post-relaunch
    check -- plus their own constants. run_case() selects the class once.

    Version read:  Linux/macOS -> <browser> --version ; Windows -> registry "pv".
    Teardown:      close every process whose EXECUTABLE PATH is the browser we launched.
                   Your everyday browser lives elsewhere, so it's never touched; the
                   relaunched build runs the freshly installed binary at the same path.

USAGE
    python run_integration_testing.py \
        --browser /path/to/chrome \
        --server http://192.168.44.10:8080 \
        --variant ok \
        [--expect-version 999.0.0.0] [--timeout 120] [--poll-interval 1.0]
        [--relaunch-grace 5.0]
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import signal
import subprocess
import sys
import time


BROWSER_UPDATE_FLAGS = ["--update-silent", "--update-without-timeout"]
BROWSER_SERVER_FLAG = "--update-server"   # passed as --update-server='<server>/<variant>'
BROWSER_VERSION_FLAG = "--version"

RELAUNCH_GRACE_SECONDS = 5.0


# ----------------------------------------------------------------------------------------
# Shared helpers (platform-agnostic)
# ----------------------------------------------------------------------------------------

def parse_version_output(output):
    """Pull a dotted version out of `<browser> --version` output, e.g.
    'Chromium 999.0.0.0' -> '999.0.0.0'. Adjust if your build prints differently."""
    match = re.search(r"\d+(?:\.\d+)+", output)
    return match.group(0) if match else None


def _norm_path(path):
    path = path.strip()
    if path.endswith(" (deleted)"):        # Linux: shown once the binary is swapped in place
        path = path[: -len(" (deleted)")]
    return os.path.normcase(os.path.realpath(path))


def start_browser(browser_path, server_url, variant):
    """Launch the browser once (plain subprocess -- no process group; the relaunch escapes
    it anyway). Identical on every platform."""
    update_server = f"{server_url.rstrip('/')}/{variant}"
    command = [
        browser_path,
        *BROWSER_UPDATE_FLAGS,
        f"{BROWSER_SERVER_FLAG}={update_server}",
    ]
    print(f"launching: {' '.join(command)}", flush=True)
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


# ----------------------------------------------------------------------------------------
# Per-OS logic + constants. Each subclass owns everything specific to its platform.
# ----------------------------------------------------------------------------------------

class Platform:
    """Base: version via `<browser> --version`, POSIX signal-based kill, no post-relaunch
    check. Windows overrides the version read and the kill; each OS supplies process
    lookup."""

    def installed_version(self, browser_path):
        completed = subprocess.run([browser_path, BROWSER_VERSION_FLAG],
                                   capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError(
                f"'{browser_path} {BROWSER_VERSION_FLAG}' failed: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        output = (completed.stdout + completed.stderr).strip()
        version = parse_version_output(output)
        if version is None:
            raise RuntimeError(f"could not parse a version from: {output!r}")
        return version

    def read_version(self, browser_path):
        """installed_version() but None instead of raising, for polling."""
        try:
            return self.installed_version(browser_path)
        except RuntimeError:
            return None

    def pids_for_executable(self, exe_path):
        raise NotImplementedError(f"process lookup not implemented for {type(self).__name__}")

    def close_pids(self, pids):
        """POSIX: SIGTERM, then SIGKILL any survivors. Windows overrides."""
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        time.sleep(1.0)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    def post_relaunch_check(self, browser_path):
        return []


class LinuxPlatform(Platform):
    def pids_for_executable(self, exe_path):
        wanted = _norm_path(exe_path)
        pids = set()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                exe = os.readlink(f"/proc/{entry}/exe")
            except (OSError, PermissionError):
                continue
            if _norm_path(exe) == wanted:
                pids.add(int(entry))
        return pids


class MacOSPlatform(Platform):
    def pids_for_executable(self, exe_path):
        wanted = _norm_path(exe_path)
        output = subprocess.run(["ps", "-eo", "pid=,comm="],
                                capture_output=True, text=True).stdout
        pids = set()
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and _norm_path(parts[1]) == wanted:
                try:
                    pids.add(int(parts[0]))
                except ValueError:
                    pass
        return pids

    def post_relaunch_check(self, browser_path):
        # TODO: verify cleanup after relaunch (old version folder removed, new bundle in
        # place, staging/temp dirs gone). Return failure strings, or [] when clean.
        return []


class WindowsPlatform(Platform):
    # Registry location of the installed version (Omaha "pv"). Repoint to your fork's
    # branded key if needed; HKLM is tried as a fallback.
    PV_KEY = r"Software\Chromium"
    PV_VALUE = "pv"

    def installed_version(self, browser_path):
        """--version is a no-op on Windows, so read Omaha's "pv". browser_path is unused.
        Tries HKCU (per-user install) then HKLM (system-wide)."""
        import winreg

        hives = [
            ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER),
            ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE),
        ]
        tried = []
        for hive_name, hive in hives:
            try:
                with winreg.OpenKey(hive, self.PV_KEY) as key:
                    value, _ = winreg.QueryValueEx(key, self.PV_VALUE)
                    return str(value)
            except FileNotFoundError:
                tried.append(f"{hive_name}\\{self.PV_KEY}\\{self.PV_VALUE}")
        raise RuntimeError("registry version not found; tried: " + ", ".join(tried))

    def pids_for_executable(self, exe_path):
        """Enumerate processes via the Win32 API (psapi/kernel32) and return those whose
        full image path matches. Pure ctypes -- no subprocess, no PowerShell quoting."""
        import ctypes
        from ctypes import wintypes

        wanted = _norm_path(exe_path)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        psapi.EnumProcesses.restype = wintypes.BOOL
        psapi.EnumProcesses.argtypes = [
            ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

        capacity = 1024
        while True:
            buffer = (wintypes.DWORD * capacity)()
            needed = wintypes.DWORD()
            if not psapi.EnumProcesses(buffer, ctypes.sizeof(buffer), ctypes.byref(needed)):
                return set()
            if needed.value < ctypes.sizeof(buffer):
                found = needed.value // ctypes.sizeof(wintypes.DWORD)
                break
            capacity *= 2

        pids = set()
        for index in range(found):
            pid = buffer[index]
            if not pid:
                continue
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                continue
            try:
                name_buffer = ctypes.create_unicode_buffer(32768)
                size = wintypes.DWORD(len(name_buffer))
                if kernel32.QueryFullProcessImageNameW(handle, 0, name_buffer, ctypes.byref(size)):
                    if _norm_path(name_buffer.value) == wanted:
                        pids.add(pid)
            finally:
                kernel32.CloseHandle(handle)
        return pids

    def close_pids(self, pids):
        for pid in pids:
            try:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
            except OSError:
                pass


PLATFORMS = {
    "Linux": LinuxPlatform,
    "Windows": WindowsPlatform,
    "Darwin": MacOSPlatform,
}


def current_platform():
    system = platform.system()
    platform_class = PLATFORMS.get(system)
    if platform_class is None:
        raise NotImplementedError(f"no platform support for '{system}'")
    return platform_class()


# ----------------------------------------------------------------------------------------
# Teardown + polling (generic, driven by the chosen platform)
# ----------------------------------------------------------------------------------------

def close_browser_at_path(target, browser_path, launched_process):
    """Close every process running the browser at browser_path. Best-effort."""
    try:
        pids = target.pids_for_executable(browser_path)
    except Exception:
        pids = set()
    if launched_process.poll() is None:
        pids.add(launched_process.pid)
    if not pids:
        print(f"no browser processes to close (matched against {_norm_path(browser_path)})")
        return
    print(f"closing browser pids at {browser_path}: {sorted(pids)}")
    target.close_pids(pids)


def wait_for_update(target, browser_path, start_version, expect_version, timeout, poll_interval):
    """Poll until the version changes off start_version (or equals expect_version, if
    given), or timeout. Returns (changed, last_seen). Never blocks past `timeout`."""
    deadline = time.monotonic() + timeout
    last_seen = start_version
    while time.monotonic() < deadline:
        current = target.read_version(browser_path)
        if current is not None:
            last_seen = current
            if expect_version is not None:
                if current == expect_version:
                    return True, current
            elif current != start_version:
                return True, current
        time.sleep(poll_interval)
    return False, last_seen


# ----------------------------------------------------------------------------------------
# One test case
# ----------------------------------------------------------------------------------------

def run_case(browser_path, server_url, variant, expect_version, timeout, poll_interval,
             relaunch_grace):
    target = current_platform()                        # pick the OS class once

    start_version = target.read_version(browser_path)
    print(f"version before update: {start_version}")

    process = start_browser(browser_path, server_url, variant)
    try:
        changed, last_seen = wait_for_update(target, browser_path, start_version,
                                             expect_version, timeout, poll_interval)
        print(f"version after update: {last_seen}")

        failures = []
        if expect_version is not None:
            if last_seen != expect_version:
                failures.append(f"expected version {expect_version}, "
                                f"last saw {last_seen} within {timeout}s")
        elif not changed:
            failures.append(f"version never changed from {start_version} within {timeout}s")

        print(f"waiting {relaunch_grace:.1f}s for relaunch...")
        time.sleep(relaunch_grace)
        failures.extend(target.post_relaunch_check(browser_path))

        if failures:
            print("\nRESULT: FAIL")
            for failure in failures:
                print(f"  - {failure}")
            return 1
        print(f"\nRESULT: PASS (version {start_version} -> {last_seen})")
        return 0
    finally:
        close_browser_at_path(target, browser_path, process)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Drive the browser through one update scenario.")
    parser.add_argument("--browser", required=True, help="path to the browser executable")
    parser.add_argument("--server", required=True, help="base URL of a running update server")
    parser.add_argument("--variant", default="ok", help="server variant/role (ok, downgrade, ...)")
    parser.add_argument("--expect-version", default=None,
                        help="if given, wait for exactly this version; else wait for any change")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="hard timeout in seconds for the update to land")
    parser.add_argument("--poll-interval", type=float, default=1.0,
                        help="seconds between version polls")
    parser.add_argument("--relaunch-grace", type=float, default=RELAUNCH_GRACE_SECONDS,
                        help="seconds to wait for relaunch before closing the test browser")
    args = parser.parse_args(argv)

    try:
        return run_case(args.browser, args.server, args.variant,
                        args.expect_version, args.timeout, args.poll_interval,
                        args.relaunch_grace)
    except NotImplementedError as error:
        print(f"NOT IMPLEMENTED: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
