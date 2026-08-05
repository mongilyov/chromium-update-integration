#!/usr/bin/env python3
"""
integration_test.py -- drive the browser-under-test through one update scenario and
report/assert the outcome. Does NOT run the update server; point --server at an already-
running one (see test_update_server.py).

WHAT IT DOES
    Launches, once, identically on every platform:
        <browser> --update-and-exit --update-server='<server>/<variant>'
    The browser downloads, verifies, installs (dpkg on Linux, mini_installer on Windows,
    folder swap on macOS -- all BEFORE relaunch), then relaunches into a live window.

    We do NOT assume how the relaunch behaves (same process / new child / detached). The
    browser is started in its own process GROUP, so whatever it spawns is captured. The
    test:
      1. launches in its own process group,
      2. waits a bounded "settle" period for install+relaunch to finish,
      3. reads the installed version out-of-band (the update already happened on disk),
      4. kills the whole group so nothing lingers,
      5. prints what it observed about the process(es) so the relaunch behavior is
         visible from real output rather than guessed.
    If --expect-version is given, the discovered version is asserted against it.

POST-INSTALL CHECK
    Linux / macOS: <browser> --version. Windows: --version is a no-op, so read Omaha's
    "pv" value from the registry. Both are isolated in installed_version().

USAGE
    python integration_test.py \
        --browser /path/to/chrome \
        --server http://192.168.44.10:8080 \
        --variant ok \
        [--expect-version 999.0.0.0] [--settle 2.0] [--timeout 120]

WHAT YOU FILL IN
    - WINDOWS_PV_KEY / WINDOWS_PV_VALUE: registry location of your build's version.
      Defaulted to HKCU\\Software\\Chromium "pv"; HKLM tried as fallback.
    - parse_version_output(), if `<browser> --version` prints an unusual format.
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


BROWSER_UPDATE_FLAG = "--update-now"
BROWSER_SERVER_FLAG = "--update-server"   # passed as --update-server='<server>/<variant>'
BROWSER_VERSION_FLAG = "--version"

WINDOWS_PV_KEY = r"Software\Chromium"
WINDOWS_PV_VALUE = "pv"

IS_WINDOWS = platform.system() == "Windows"
BROWSER_PROCESS_NAMES = ("chrome", "chromium", "chromium-gost")


# ----------------------------------------------------------------------------------------
# Launch as a killable process group (captures the relaunch however it behaves)
# ----------------------------------------------------------------------------------------

def start_browser(browser_path, server_url, variant):
    update_server = f"{server_url.rstrip('/')}/{variant}"
    command = [
        browser_path,
        BROWSER_UPDATE_FLAG,
        f"{BROWSER_SERVER_FLAG}={update_server}",
    ]
    print(f"launching: {' '.join(command)}", flush=True)
    if IS_WINDOWS:
        return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True,
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)


def kill_process_group(process):
    """Tear down the browser and whatever it relaunched. Best-effort; never raises."""
    if process.poll() is not None and IS_WINDOWS:
        return
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                           capture_output=True)
        else:
            group = os.getpgid(process.pid)
            os.killpg(group, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(group, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


# ----------------------------------------------------------------------------------------
# Process observation (so the relaunch behavior is visible, not guessed)
# ----------------------------------------------------------------------------------------

def browser_pids():
    """Best-effort set of running browser PIDs, for before/after comparison. Never raises;
    returns an empty set if the platform tool isn't available."""
    try:
        if IS_WINDOWS:
            output = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                    capture_output=True, text=True).stdout
            pids = set()
            for line in output.splitlines():
                fields = [f.strip('"') for f in line.split('","')]
                if fields and any(n in fields[0].lower() for n in BROWSER_PROCESS_NAMES):
                    try:
                        pids.add(int(fields[1]))
                    except (IndexError, ValueError):
                        pass
            return pids
        output = subprocess.run(["ps", "-eo", "pid=,comm="],
                                capture_output=True, text=True).stdout
        pids = set()
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and any(n in parts[1].lower() for n in BROWSER_PROCESS_NAMES):
                try:
                    pids.add(int(parts[0]))
                except ValueError:
                    pass
        return pids
    except (FileNotFoundError, OSError):
        return set()


# ----------------------------------------------------------------------------------------
# Post-install check: read the installed version the OS-native way
# ----------------------------------------------------------------------------------------

def installed_version(browser_path):
    if IS_WINDOWS:
        return _installed_version_windows()
    return _installed_version_via_exe(browser_path)


def parse_version_output(output):
    """Pull a dotted version out of `<browser> --version` output, e.g.
    'Chromium 999.0.0.0' -> '999.0.0.0'. Adjust if your build prints differently."""
    match = re.search(r"\d+(?:\.\d+)+", output)
    return match.group(0) if match else None


def _installed_version_via_exe(browser_path):
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


def _installed_version_windows():
    """Read Omaha's 'pv' value. Tries HKCU (per-user install) then HKLM (system-wide)."""
    import winreg

    hives = [
        ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER),
        ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE),
    ]
    tried = []
    for hive_name, hive in hives:
        try:
            with winreg.OpenKey(hive, WINDOWS_PV_KEY) as key:
                value, _ = winreg.QueryValueEx(key, WINDOWS_PV_VALUE)
                return str(value)
        except FileNotFoundError:
            tried.append(f"{hive_name}\\{WINDOWS_PV_KEY}\\{WINDOWS_PV_VALUE}")
    raise RuntimeError("registry version not found; tried: " + ", ".join(tried))


# ----------------------------------------------------------------------------------------
# One test case
# ----------------------------------------------------------------------------------------

def run_case(browser_path, server_url, variant, expect_version, settle, timeout):
    before = browser_pids()
    process = start_browser(browser_path, server_url, variant)
    launched_pid = process.pid
    try:
        # Give install + relaunch a bounded moment to finish. Install precedes relaunch,
        # so the on-disk version is authoritative by the end of this window.
        time.sleep(min(settle, timeout))

        # Observe what actually happened to the process tree, and report it.
        original_alive = process.poll() is None
        after = browser_pids()
        new_pids = sorted(after - before - {launched_pid})
        print(f"launched pid: {launched_pid}")
        print(f"original process still alive after {settle:.1f}s: {original_alive}")
        print(f"new browser pids that appeared: {new_pids or 'none detected'}")

        try:
            found = installed_version(browser_path)
        except RuntimeError as error:
            print(f"\nRESULT: FAIL\n  - could not read installed version: {error}")
            return 1

        print(f"installed version: {found}")

        if expect_version is not None and found != expect_version:
            print(f"\nRESULT: FAIL\n  - expected {expect_version}, got {found}")
            return 1
        print("\nRESULT: PASS")
        return 0
    finally:
        kill_process_group(process)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Drive the browser through one update scenario.")
    parser.add_argument("--browser", required=True, help="path to the browser executable")
    parser.add_argument("--server", required=True, help="base URL of a running update server")
    parser.add_argument("--variant", default="ok", help="server variant/role (ok, downgrade, ...)")
    parser.add_argument("--expect-version", default=None,
                        help="if given, assert the installed version equals this")
    parser.add_argument("--settle", type=float, default=2.0,
                        help="seconds to wait for install+relaunch before reading the version")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="hard cap in seconds on the settle wait")
    args = parser.parse_args(argv)

    return run_case(args.browser, args.server, args.variant,
                    args.expect_version, args.settle, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
