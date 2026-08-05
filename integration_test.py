#!/usr/bin/env python3
"""
integration_test.py -- drive the browser-under-test through one update scenario and
assert the outcome. This does NOT run the update server; point --server at an already-
running one (see test_update_server.py).

WHAT IT DOES
    Launches, once, identically on every platform:
        <browser> --update-and-exit --update-server='<server>/<variant>'
    waits (with a HARD timeout) for the browser to update and exit on its own, then runs
    the post-install check to confirm the install actually landed.

POST-INSTALL CHECK
    Linux / macOS: read the version the installed executable reports (<browser> --version).
    Windows: --version is a no-op there, so read Omaha's "pv" (product version) value from
    the registry instead. Both paths are isolated in installed_version(); only the Windows
    registry key/value and the --version parsing are things you may need to adjust.

USAGE
    python integration_test.py \
        --browser /path/to/chrome \
        --server http://192.168.44.10:8080 \
        --variant ok \
        [--expect-exit 0] [--expect-version 999.0.0.0] [--timeout 120]

WHAT YOU FILL IN
    - WINDOWS_PV_KEY / WINDOWS_PV_VALUE: the registry location of your build's version.
      Defaulted to HKCU\\Software\\Chromium "pv" (where you found it); if your fork is
      branded, repoint to its vendor/app-GUID key. HKLM is tried as a fallback.
    - If your browser signals update success by something other than exit code (a marker
      file, a stdout token, a log line), replace read_terminal_state().
    - If `<browser> --version` prints something other than a bare/space-separated dotted
      version, adjust parse_version_output().
"""

from __future__ import annotations

import argparse
import platform
import re
import subprocess
import sys


BROWSER_UPDATE_FLAG = "--update-and-exit"
BROWSER_SERVER_FLAG = "--update-server"   # passed as --update-server='<server>/<variant>'
BROWSER_VERSION_FLAG = "--version"

# Windows only: where the installed version lives (Omaha "pv"). Repoint to your fork's
# branded key if needed. The subkey path is relative to the hive (HKCU tried first,
# then HKLM).
WINDOWS_PV_KEY = r"Software\Chromium"
WINDOWS_PV_VALUE = "pv"


# ----------------------------------------------------------------------------------------
# Launch (identical on every platform)
# ----------------------------------------------------------------------------------------

class LaunchResult:
    def __init__(self, exit_code, stdout, stderr, timed_out):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


def launch_browser(browser_path, server_url, variant, timeout):
    """Run the browser once and wait for it to update-and-exit. Never blocks past
    `timeout` seconds; a timeout is itself a (failed) terminal state, not a hang."""
    update_server = f"{server_url.rstrip('/')}/{variant}"
    command = [
        browser_path,
        BROWSER_UPDATE_FLAG,
        f"{BROWSER_SERVER_FLAG}={update_server}",
    ]
    print(f"launching: {' '.join(command)}", flush=True)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return LaunchResult(completed.returncode, completed.stdout, completed.stderr, False)
    except subprocess.TimeoutExpired as expired:
        return LaunchResult(None,
                            expired.stdout or "",
                            expired.stderr or "",
                            True)


def read_terminal_state(result):
    """Reduce the launch to a verdict. Currently: the process exit code (0 == updated and
    exited cleanly). Swap this if your browser signals success another way."""
    if result.timed_out:
        return "timeout"
    if result.exit_code == 0:
        return "ok"
    return f"exit={result.exit_code}"


# ----------------------------------------------------------------------------------------
# Post-install check: read the installed version the OS-native way
# ----------------------------------------------------------------------------------------

def installed_version(browser_path):
    if platform.system() == "Windows":
        return _installed_version_windows()
    return _installed_version_via_exe(browser_path)


def parse_version_output(output):
    """Pull a dotted version out of `<browser> --version` output, e.g.
    'Chromium 999.0.0.0' -> '999.0.0.0'. Adjust if your build prints differently."""
    match = re.search(r"\d+(?:\.\d+)+", output)
    return match.group(0) if match else None


def _installed_version_via_exe(browser_path):
    completed = subprocess.run(
        [browser_path, BROWSER_VERSION_FLAG],
        capture_output=True,
        text=True,
    )
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
    """Read Omaha's 'pv' value. Tries HKCU (per-user install) then HKLM (system-wide,
    which a root/Administrator install often uses)."""
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

def run_case(browser_path, server_url, variant, expect_exit, expect_version, timeout):
    result = launch_browser(browser_path, server_url, variant, timeout)
    state = read_terminal_state(result)

    print(f"terminal state: {state}")
    if result.stdout.strip():
        print(f"stdout:\n{result.stdout.strip()}")
    if result.stderr.strip():
        print(f"stderr:\n{result.stderr.strip()}")

    failures = []

    if expect_exit is not None:
        if result.timed_out:
            failures.append(f"expected exit {expect_exit}, but the browser timed out "
                            f"after {timeout}s")
        elif result.exit_code != expect_exit:
            failures.append(f"expected exit {expect_exit}, got {result.exit_code}")

    if expect_version is not None:
        try:
            found = installed_version(browser_path)
            print(f"post-install version: {found}")
            if found != expect_version:
                failures.append(f"expected installed version {expect_version}, got {found}")
        except RuntimeError as error:
            failures.append(str(error))

    if failures:
        print("\nRESULT: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nRESULT: PASS")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Drive the browser through one update scenario.")
    parser.add_argument("--browser", required=True, help="path to the browser executable")
    parser.add_argument("--server", required=True, help="base URL of a running update server")
    parser.add_argument("--variant", default="ok", help="server variant/role (ok, downgrade, ...)")
    parser.add_argument("--expect-exit", type=int, default=0,
                        help="expected process exit code (default 0; pass -1 to skip)")
    parser.add_argument("--expect-version", default=None,
                        help="expected version from the post-install check (default: skip)")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="hard timeout in seconds for the browser launch")
    args = parser.parse_args(argv)

    expect_exit = None if args.expect_exit == -1 else args.expect_exit
    return run_case(args.browser, args.server, args.variant,
                    expect_exit, args.expect_version, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
