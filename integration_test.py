#!/usr/bin/env python3
"""
integration_test.py -- drive the browser-under-test through one update scenario and
report/assert the outcome. Does NOT run the update server; point --server at an already-
running one (see test_update_server.py).

WHAT IT DOES
    Launches, once, identically on every platform:
        <browser> --update-now --update-server='<server>/<variant>'
    The browser downloads, verifies, installs (dpkg on Linux, mini_installer on Windows,
    folder swap on macOS -- all BEFORE relaunch), then relaunches into a live window.

    The install takes real time (download + verify + package tooling), so the test does
    NOT sleep a fixed amount and then look -- that races the updater. Instead it:
      1. records the version BEFORE launching,
      2. launches in its own process GROUP (so the relaunch, however it behaves -- same
         process / new child / detached -- is captured and killable),
      3. POLLS the installed version until it changes from the starting value (or matches
         --expect-version, if given), bounded by a HARD timeout,
      4. only then kills the whole group to tear down the relaunched window.
    The browser is never killed until the update has demonstrably landed or the timeout
    genuinely expires.

POST-INSTALL CHECK
    Linux / macOS: <browser> --version. Windows: --version is a no-op, so read Omaha's
    "pv" value from the registry. Both are isolated in installed_version().
    NOTE: if `<browser> --version` reports a fixed base-Chromium string that does not
    change on update (some forks do this), switch the Linux/macOS reader to the install
    record instead -- e.g. dpkg-query on your package. See installed_version().

USAGE
    python integration_test.py \
        --browser /path/to/chrome \
        --server http://192.168.44.10:8080 \
        --variant ok \
        [--expect-version 999.0.0.0] [--timeout 120] [--poll-interval 1.0]

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


def read_version_quietly(browser_path):
    """installed_version() but returns None instead of raising, for use while polling."""
    try:
        return installed_version(browser_path)
    except RuntimeError:
        return None


# ----------------------------------------------------------------------------------------
# Poll until the installed version changes (bounded by the hard timeout)
# ----------------------------------------------------------------------------------------

def wait_for_update(browser_path, start_version, expect_version, timeout, poll_interval):
    """Poll until the version changes off start_version (or equals expect_version, if
    given), or timeout. Returns (changed, last_seen). Never blocks past `timeout`."""
    deadline = time.monotonic() + timeout
    last_seen = start_version
    while time.monotonic() < deadline:
        current = read_version_quietly(browser_path)
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

def run_case(browser_path, server_url, variant, expect_version, timeout, poll_interval):
    start_version = read_version_quietly(browser_path)
    print(f"version before update: {start_version}")

    process = start_browser(browser_path, server_url, variant)
    try:
        changed, last_seen = wait_for_update(browser_path, start_version, expect_version,
                                              timeout, poll_interval)
        print(f"version after update: {last_seen}")

        if expect_version is not None:
            if last_seen == expect_version:
                print("\nRESULT: PASS")
                return 0
            print(f"\nRESULT: FAIL\n  - expected {expect_version}, "
                  f"last saw {last_seen} within {timeout}s")
            return 1

        if changed:
            print(f"\nRESULT: PASS (version moved {start_version} -> {last_seen})")
            return 0
        print(f"\nRESULT: FAIL\n  - version never changed from {start_version} "
              f"within {timeout}s")
        return 1
    finally:
        kill_process_group(process)


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
    args = parser.parse_args(argv)

    return run_case(args.browser, args.server, args.variant,
                    args.expect_version, args.timeout, args.poll_interval)


if __name__ == "__main__":
    sys.exit(main())
