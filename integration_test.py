#!/usr/bin/env python3
"""
integration_test.py -- drive the browser-under-test through one update scenario and
assert the outcome. This does NOT run the update server; point --server at an already-
running one (see test_update_server.py).

WHAT IT DOES
    Launches, once, identically on every platform:
        <browser> --update-and-exit --update-server='<server>/<variant>'
    The browser downloads, verifies, installs (dpkg on Linux, mini_installer on Windows,
    folder swap on macOS -- all BEFORE relaunch), then relaunches into a live window.

    Because the install completes before relaunch, the test does NOT wait for the process
    to exit (the relaunched window would block forever -- it's not detached). Instead it:
      1. launches the browser in its OWN process group,
      2. polls the installed version out-of-band until it reaches the expected value
         (bounded by a HARD timeout),
      3. kills the whole process group to tear down the relaunched window.
    The polled version is the verdict; the process lifecycle is not.

POST-INSTALL CHECK
    Linux / macOS: <browser> --version. Windows: --version is a no-op, so read Omaha's
    "pv" value from the registry. Both are isolated in installed_version().

USAGE
    python integration_test.py \
        --browser /path/to/chrome \
        --server http://192.168.44.10:8080 \
        --variant ok \
        --expect-version 999.0.0.0 \
        [--timeout 120] [--poll-interval 1.0]

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
BROWSER_SERVER_FLAG = "--update-server"
BROWSER_VERSION_FLAG = "--version"

WINDOWS_PV_KEY = r"Software\Chromium"
WINDOWS_PV_VALUE = "pv"

IS_WINDOWS = platform.system() == "Windows"


# ----------------------------------------------------------------------------------------
# Launch as a killable process group (relaunch is NOT detached, so we own the whole tree)
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
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, creationflags=creationflags)
    # POSIX: start_new_session puts the browser (and anything it relaunches) in its own
    # process group/session, so we can kill the entire tree with one signal.
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)


def kill_process_group(process):
    """Tear down the browser and whatever it relaunched. Best-effort; never raises."""
    if process.poll() is not None:
        return  # already gone
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                           capture_output=True)
        else:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


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
# Poll the installed version until it settles (bounded by a hard timeout)
# ----------------------------------------------------------------------------------------

def wait_for_version(browser_path, expected_version, timeout, poll_interval):
    """Poll the OS-native version record until it equals expected_version or timeout.
    Returns (reached, last_seen). Never blocks past `timeout` seconds."""
    deadline = time.monotonic() + timeout
    last_seen = None
    last_error = None
    while time.monotonic() < deadline:
        try:
            last_seen = installed_version(browser_path)
            if last_seen == expected_version:
                return True, last_seen
        except RuntimeError as error:
            last_error = error
        time.sleep(poll_interval)
    if last_seen is None and last_error is not None:
        return False, f"<unreadable: {last_error}>"
    return False, last_seen


# ----------------------------------------------------------------------------------------
# One test case
# ----------------------------------------------------------------------------------------

def run_case(browser_path, server_url, variant, expect_version, timeout, poll_interval):
    process = start_browser(browser_path, server_url, variant)
    try:
        if expect_version is None:
            # No version to poll for -- give the browser a bounded moment to act, then
            # tear it down. (Mainly useful for negative cases; see notes.)
            time.sleep(min(timeout, 5.0))
            print("no --expect-version given; skipping version assertion")
            return 0

        reached, last_seen = wait_for_version(browser_path, expect_version,
                                              timeout, poll_interval)
        print(f"post-install version: {last_seen}")
        if reached:
            print("\nRESULT: PASS")
            return 0
        print(f"\nRESULT: FAIL")
        print(f"  - expected installed version {expect_version}, "
              f"last saw {last_seen} within {timeout}s")
        return 1
    finally:
        kill_process_group(process)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Drive the browser through one update scenario.")
    parser.add_argument("--browser", required=True, help="path to the browser executable")
    parser.add_argument("--server", required=True, help="base URL of a running update server")
    parser.add_argument("--variant", default="ok", help="server variant/role (ok, downgrade, ...)")
    parser.add_argument("--expect-version", default=None, help="version the install should reach, polled after launch")
    parser.add_argument("--timeout", type=float, default=60.0, help="hard timeout in seconds for the whole update+relaunch")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="seconds between version polls")
    args = parser.parse_args(argv)

    return run_case(args.browser, args.server, args.variant,
                    args.expect_version, args.timeout, args.poll_interval)


if __name__ == "__main__":
    sys.exit(main())
