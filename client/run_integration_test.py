#!/usr/bin/env python3
r"""
Run one browser-update scenario on a dedicated desktop test VM.

Run as the desktop test user (Linux polkit requires an active local session).
Use --browser for the actual installed executable. A fresh isolated profile is
created for every case; pre-existing browser processes at that path are rejected.
The live browser version is read from its local DevTools endpoint, so an installed
package/registry change alone cannot pass the test. macOS framework cleanup and
the Current symlink must also settle before success.

Versions default to the server /status values. A successful update is the default.
For corrupt/badjson/http500/truncated/hang, use --expect-no-update: the browser must
stay healthy throughout --timeout and its NetLog must show the update request.
Rejection messages are checked for the known error scenarios. Downgrade rejection
requires --require-log with the expected rejection diagnostic from the browser.
Logs, result.json and junit.xml remain in the printed results directory.
The profile is removed after successful cleanup unless --keep-profile is set.

Example:
    python run_integration_test.py --browser /opt/chromium-gost/chrome \
        --server http://test-server:8080 --target linux_deb \
        --expect-current-version 156.0.8078.96 --expect-version 999.0.0.0 \
        --results-dir /var/tmp/update-results
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import http.client
import os
from pathlib import Path
import platform
import plistlib
import signal
import subprocess
import sys
import shutil
import tempfile
import time
import urllib.parse

from ci_common import (SERVER_ENV_VARIABLE, TARGETS, capture_command, choose_target,
                       normalize_server_url, parse_version, positive_seconds, read_json,
                       run_reported, version, version_argument, wait_for_server,
                       windows_installed_version)


BROWSER_UPDATE_FLAGS = ["--update-silent", "--update-without-timeout"]
BROWSER_SERVER_FLAG = "--update-server"
BROWSER_VERSION_FLAG = "--version"

RELAUNCH_GRACE_SECONDS = 5.0


def _norm_path(path):
    path = path.strip().removesuffix(" (deleted)")
    return os.path.normcase(os.path.realpath(path))


def _bundle_path(executable_path):
    executable = Path(executable_path).resolve()
    for path in (executable, *executable.parents):
        if path.suffix == ".app":
            return str(path)
    raise RuntimeError(f"no .app bundle found above {executable_path}")


def start_browser(browser_path, server_url, variant, profile, report_dir, output, extra_flags=()):
    update_server = f"{server_url.rstrip('/')}/{variant}"
    command = [browser_path, *BROWSER_UPDATE_FLAGS, *extra_flags,
              "--no-first-run", "--no-default-browser-check",
              f"--user-data-dir={profile}", "--remote-debugging-port=0",
              "--remote-debugging-address=127.0.0.1", "--enable-logging",
              f"--log-file={report_dir / 'chromium.log'}",
              f"--log-net-log={report_dir / 'netlog.json'}",
              f"{BROWSER_SERVER_FLAG}={update_server}"]
    print(f"launching: {' '.join(command)}", flush=True)
    return subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)


class Platform:
    EXTRA_LAUNCH_FLAGS = []

    def installed_version(self, browser_path, timeout=10):
        completed = capture_command([browser_path, BROWSER_VERSION_FLAG], timeout=timeout)
        output = (completed.stdout + completed.stderr).strip()
        installed = parse_version(output)
        if installed is None:
            raise RuntimeError(f"could not parse a version from: {output!r}")
        return installed

    def read_version(self, browser_path, timeout=10):
        try:
            return self.installed_version(browser_path, timeout)
        except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired):
            return None

    def pids_for_executable(self, exe_path):
        raise NotImplementedError(f"process lookup not implemented for {type(self).__name__}")

    def close_pids(self, pids, browser_path):
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(1.0)
        for pid in pids & self.pids_for_executable(browser_path):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def post_relaunch_check(self, browser_path, start_version, expect_version):
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
            except OSError:
                continue
            if _norm_path(exe) == wanted:
                pids.add(int(entry))
        return pids


class MacOSPlatform(Platform):
    FRAMEWORK_VERSIONS_SUBPATH = "Contents/Frameworks/Chromium-Gost Framework.framework/Versions"
    EXTRA_LAUNCH_FLAGS = ["--use-mock-keychain", "--disable-features=DialMediaRouteProvider"]

    def installed_version(self, browser_path, timeout=10):
        info_path = os.path.join(_bundle_path(browser_path), "Contents", "Info.plist")
        with open(info_path, "rb") as handle:
            info = plistlib.load(handle)
        return version(info.get("CFBundleShortVersionString", info.get("CFBundleVersion")))

    def pids_for_executable(self, exe_path):
        wanted = _norm_path(exe_path)
        output = capture_command(["ps", "-eo", "pid=,comm="], timeout=5).stdout
        bundle = _norm_path(_bundle_path(exe_path)) + os.sep
        pids = set()
        for line in output.splitlines():
            parts = line.split(None, 1)
            # Include renderer/helper executables from this app bundle. The
            # preflight rejects these too, so cleanup cannot adopt an existing app.
            if len(parts) == 2 and (_norm_path(parts[1]) == wanted
                                    or _norm_path(parts[1]).startswith(bundle)):
                try:
                    pids.add(int(parts[0]))
                except ValueError:
                    pass
        return pids

    def post_relaunch_check(self, browser_path, start_version, expect_version):
        try:
            bundle_path = _bundle_path(browser_path)
        except RuntimeError as error:
            return [str(error)]

        versions_dir = os.path.join(bundle_path, self.FRAMEWORK_VERSIONS_SUBPATH)
        if not os.path.isdir(versions_dir):
            return [f"versions directory not found: {versions_dir}"]

        failures = []

        if os.path.isdir(os.path.join(versions_dir, start_version)):
            failures.append(f"old version folder still present: "
                            f"{os.path.join(versions_dir, start_version)}")

        current_link = os.path.join(versions_dir, "Current")
        try:
            current_target = os.path.basename(os.readlink(current_link))
        except OSError as error:
            return failures + [f"could not read Current symlink: {error}"]

        if current_target != expect_version:
            failures.append(f"Current points to {current_target}, expected {expect_version}")

        if not os.path.isdir(current_link):
            failures.append("Current does not resolve to an existing framework version")

        return failures


class WindowsPlatform(Platform):
    def __init__(self, system_level=False):
        self.system_level = system_level

    def installed_version(self, browser_path, timeout=10):
        return windows_installed_version(self.system_level)

    def pids_for_executable(self, exe_path):
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
                raise ctypes.WinError(ctypes.get_last_error())
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

    def close_pids(self, pids, browser_path):
        for pid in pids & self.pids_for_executable(browser_path):
            # A process can exit between enumeration and taskkill. The caller
            # re-enumerates afterward; surviving processes fail cleanup.
            capture_command(["taskkill", "/F", "/PID", str(pid)], timeout=5,
                            ok_codes=(0, 128))


PLATFORMS = {
    "Linux": LinuxPlatform,
    "Windows": WindowsPlatform,
    "Darwin": MacOSPlatform,
}


def current_platform(system_level=False):
    system = platform.system()
    platform_class = PLATFORMS.get(system)
    if platform_class is None:
        raise NotImplementedError(f"no platform support for '{system}'")
    if system == "Windows":
        return platform_class(system_level=system_level)
    if system_level:
        raise ValueError("--system-level is only supported on Windows")
    return platform_class()


VARIANTS = ("ok", "corrupt", "downgrade", "badjson", "http500", "truncated", "hang")
REJECTION_LOGS = {
    "corrupt": "Failed to verify update integrity",
    "badjson": "Failed to parse update response",
    "http500": "Failed to get response from server",
    "truncated": "Failed to get response from server",
}


def running_browser_version(profile, timeout=2):
    """Read the live browser's version, tied to this fresh profile's DevTools token."""
    lines = (Path(profile) / "DevToolsActivePort").read_text(encoding="utf-8").splitlines()
    if len(lines) != 2 or not lines[0].isdigit() or not lines[1].startswith("/devtools/browser/"):
        raise RuntimeError("invalid DevToolsActivePort file")
    port = int(lines[0])
    if not 1 <= port <= 65535:
        raise RuntimeError("invalid DevTools port")
    document = read_json(f"http://127.0.0.1:{port}/json/version", timeout, local=True)
    endpoint = urllib.parse.urlsplit(document.get("webSocketDebuggerUrl", ""))
    if (endpoint.scheme != "ws" or endpoint.hostname != "127.0.0.1"
            or endpoint.port != port or endpoint.path != lines[1]):
        raise RuntimeError("DevTools endpoint does not belong to the test profile")
    value = parse_version(document.get("Browser", ""))
    if value is None:
        raise RuntimeError("live browser did not report a four-part version")
    return value


def contains_text(paths, text):
    needle = text.encode("utf-8")
    for path in paths:
        try:
            with open(path, "rb") as handle:
                tail = b""
                while True:
                    chunk = handle.read(64 * 1024)
                    if not chunk:
                        break
                    combined = tail + chunk
                    if needle in combined:
                        return True
                    tail = combined[-max(1, len(needle)):]
        except FileNotFoundError:
            continue
    return False


def close_browser_at_path(target, browser_path, launched_process, timeout=10):
    """The caller refuses pre-existing browsers; all matches belong to this VM test."""
    deadline = time.monotonic() + timeout
    failures = []
    while time.monotonic() < deadline:
        try:
            pids = target.pids_for_executable(browser_path)
            if launched_process.poll() is None:
                pids.add(launched_process.pid)
            if not pids:
                launched_process.wait(timeout=1)  # Reap our direct child.
                return failures
            print(f"closing browser pids: {sorted(pids)}", flush=True)
            target.close_pids(pids, browser_path)
            if launched_process.poll() is None:
                launched_process.terminate()
            time.sleep(0.1)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            failures.append(f"browser cleanup failed: {error}")
            break
    if launched_process.poll() is None:
        launched_process.kill()
        try:
            launched_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            failures.append("launched process did not exit after kill")
    try:
        remaining = target.pids_for_executable(browser_path)
        if remaining:
            failures.append(f"browser processes survived cleanup: {sorted(remaining)}")
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        failures.append(f"cannot verify browser cleanup: {error}")
    return failures


def require_desktop_user():
    if platform.system() in ("Linux", "Darwin") and os.geteuid() == 0:
        raise RuntimeError("run the browser test as the desktop test user, not root")
    if platform.system() == "Linux" and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise RuntimeError("a desktop session with DISPLAY or WAYLAND_DISPLAY is required")


def read_browser_versions(args, target, profile, report, deadline):
    """Sample the installed version and the browser using this test's profile."""
    timeout = max(0.01, min(2, deadline - time.monotonic()))
    installed = target.read_version(args.browser, timeout=timeout)
    try:
        running = running_browser_version(profile, timeout=timeout)
    except (OSError, RuntimeError, ValueError, http.client.HTTPException):
        running = None
    previous = (report.data.get("installed_version"), report.data.get("running_version"))
    if (installed, running) != previous:
        print(f"observed installed={installed!r}, running={running!r}", flush=True)
    report.data.update(installed_version=installed, running_version=running)
    return installed, running


def observe_update(args, target, profile, start_version, expected_version, report):
    """Wait for the installed AND running versions, then for platform cleanup."""
    deadline = time.monotonic() + args.timeout
    stable_since = None
    last_problem = "no version observed"
    while time.monotonic() < deadline:
        installed, running = read_browser_versions(args, target, profile, report, deadline)
        if installed == running == expected_version:
            problems = target.post_relaunch_check(args.browser, start_version, expected_version)
        else:
            problems = [f"installed={installed!r}, running={running!r}"]
        if problems:
            last_problem = "; ".join(problems)
            stable_since = None
        else:
            if stable_since is None:
                stable_since = time.monotonic()
            if time.monotonic() - stable_since >= args.relaunch_grace:
                return
        time.sleep(min(args.poll_interval, max(0, deadline - time.monotonic())))
    raise RuntimeError(f"update observation timed out after {args.timeout}s; {last_problem}; "
                       f"expected running version {expected_version}")


def observe_no_update(args, target, profile, start_version, report):
    """Allow startup, then require an unchanged live browser for the full timeout."""
    startup_deadline = time.monotonic() + min(args.timeout, 30)
    observation_deadline = None
    while time.monotonic() < (observation_deadline or startup_deadline):
        deadline = observation_deadline or startup_deadline
        installed, running = read_browser_versions(args, target, profile, report, deadline)
        if installed is not None and installed != start_version:
            raise RuntimeError(f"unexpected installed version change: {start_version} -> {installed}")
        if running is not None and running != start_version:
            raise RuntimeError(f"unexpected running version: {running}")
        if installed == running == start_version:
            if observation_deadline is None:
                observation_deadline = time.monotonic() + args.timeout
        elif observation_deadline is not None:
            raise RuntimeError("browser/version became unavailable during the no-update observation")
        deadline = observation_deadline or startup_deadline
        time.sleep(min(args.poll_interval, max(0, deadline - time.monotonic())))
    if observation_deadline is None:
        raise RuntimeError("browser did not become ready for the no-update observation")


def check_test_setup(args, target, report):
    """Check arguments, server packages and installed baseline before launching."""
    if not os.path.isfile(args.browser):
        raise ValueError(f"browser executable does not exist: {args.browser}")
    require_desktop_user()
    if args.variant != "ok" and not args.expect_no_update:
        raise ValueError("rejection scenarios require --expect-no-update")
    if args.expect_no_update and args.expect_version is not None:
        raise ValueError("--expect-version and --expect-no-update are mutually exclusive")
    args.require_log = args.require_log or REJECTION_LOGS.get(args.variant)
    if args.expect_no_update and args.variant != "hang" and not args.require_log:
        raise ValueError("this rejection scenario requires --require-log with its expected error message")
    if args.relaunch_grace >= args.timeout:
        raise ValueError("--timeout must be greater than --relaunch-grace")

    role = "older" if args.variant == "downgrade" else "newer"
    status = wait_for_server(args.server, args.target, args.server_timeout, role=role, run_id=args.run_id)
    baseline = status["current_version"]
    expected = baseline if args.expect_no_update else status["newer_version"]
    if args.expect_current_version not in (None, baseline):
        raise ValueError("expected baseline does not match the server current_version")
    if args.expect_version not in (None, expected):
        raise ValueError("expected update does not match the server newer_version")
    start = version(target.installed_version(args.browser, timeout=args.command_timeout))
    report.data.update(target=args.target, variant=args.variant, run_id=status.get("run_id"),
                       start_version=start, expected_version=expected,
                       expect_no_update=args.expect_no_update)
    if start != baseline:
        raise RuntimeError(f"baseline is {start}, expected {baseline}; run preparation again")
    if not args.expect_no_update and start == expected:
        raise RuntimeError("baseline already has the expected update version")
    existing = target.pids_for_executable(args.browser)
    if existing:
        raise RuntimeError(f"browser is already running at this path: {sorted(existing)}")
    return status


@contextmanager
def browser_session(args, target, report):
    """Own the fresh profile, browser process and cleanup for one scenario."""
    profile = Path(tempfile.mkdtemp(prefix="profile-", dir=report.directory))
    report.data["profile"] = str(profile)
    process = None
    cleanup_issues = []
    try:
        with open(report.directory / "browser-output.log", "ab", buffering=0) as output:
            process = start_browser(args.browser, args.server, args.variant, profile,
                                    report.directory, output, target.EXTRA_LAUNCH_FLAGS)
            yield profile
    finally:
        if process is not None:
            try:
                cleanup_issues = close_browser_at_path(target, args.browser, process)
            except Exception as error:
                cleanup_issues = [f"cleanup raised: {error}"]
        report.data["cleanup_errors"] = cleanup_issues
        if args.keep_profile or cleanup_issues:
            print(f"profile preserved: {profile}", flush=True)
        else:
            # Remove only the fresh profile owned by this run.
            resolved = profile.resolve()
            if resolved.parent != report.directory.resolve() or not resolved.name.startswith("profile-"):
                raise RuntimeError(f"refusing to remove unexpected profile path: {resolved}")
            shutil.rmtree(resolved)
    if cleanup_issues:
        raise RuntimeError("; ".join(cleanup_issues))


def check_logs(args, report):
    """Check request/error evidence after closing the browser flushes its logs."""
    if args.expect_no_update:
        request_url = f"{args.server}/{args.variant}/update"
        if not contains_text([report.directory / "netlog.json"], request_url):
            raise RuntimeError("no evidence that the browser attempted the scenario's update request")
        report.data["update_request_observed"] = True
    logs = [report.directory / "chromium.log", report.directory / "browser-output.log"]
    if args.require_log and not contains_text(logs, args.require_log):
        raise RuntimeError(f"expected browser log message was not observed: {args.require_log!r}")


def check_server_unchanged(args, initial_status):
    role = "older" if args.variant == "downgrade" else "newer"
    final_status = wait_for_server(args.server, args.target, args.server_timeout, role=role,
                                   run_id=initial_status.get("run_id"))
    for field in ("current_version", "newer_version", "older_version", "run_id"):
        if final_status.get(field) != initial_status.get(field):
            raise RuntimeError(f"server {field} changed during the test")


def run_case(args, report):
    args.browser = os.path.abspath(args.browser)
    args.server = normalize_server_url(args.server)
    args.target = choose_target(args.target)
    target = current_platform(system_level=args.system_level)
    status = check_test_setup(args, target, report)

    with browser_session(args, target, report) as profile:
        if args.expect_no_update:
            observe_no_update(args, target, profile, status["current_version"], report)
        else:
            observe_update(args, target, profile, status["current_version"],
                           status["newer_version"], report)

    check_logs(args, report)
    check_server_unchanged(args, status)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--browser", required=True, help="actual installed browser executable, not a shell launcher")
    parser.add_argument("--server", default=os.environ.get(SERVER_ENV_VARIABLE))
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--variant", choices=VARIANTS, default="ok")
    parser.add_argument("--expect-current-version", type=version_argument)
    parser.add_argument("--expect-version", type=version_argument)
    parser.add_argument("--expect-no-update", action="store_true",
                        help="observe an unchanged live browser for the entire timeout")
    parser.add_argument("--require-log", help="required browser error/log text; mandatory for downgrade rejection")
    parser.add_argument("--timeout", type=positive_seconds, default=180)
    parser.add_argument("--poll-interval", type=positive_seconds, default=1)
    parser.add_argument("--relaunch-grace", type=positive_seconds, default=RELAUNCH_GRACE_SECONDS,
                        help="minimum healthy observation after relaunch (default: 5 seconds)")
    parser.add_argument("--server-timeout", type=positive_seconds, default=30)
    parser.add_argument("--command-timeout", type=positive_seconds, default=10)
    parser.add_argument("--system-level", action="store_true")
    parser.add_argument("--run-id", help="expected server run_id")
    parser.add_argument("--results-dir", help="parent for a unique results folder; default: system temp")
    parser.add_argument("--keep-profile", action="store_true", help="retain the test profile for diagnosis")
    args = parser.parse_args(argv)
    return run_reported(args.results_dir, "run-" + args.variant, lambda report: run_case(args, report))


if __name__ == "__main__":
    sys.exit(main())
