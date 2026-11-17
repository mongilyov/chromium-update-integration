#!/usr/bin/env python3
r"""
Prepare a dedicated test VM for an update integration test.

Download the baseline before removing the installed browser, install it,
then verify the installed version. Run as root on Linux/macOS or administrator
on Windows. Package dependencies must already be installed/cached on Linux.
Windows removes both installation scopes; the new baseline is per-user unless
--system-level is supplied. Use the same Windows account for preparation and test.

Versions come from server /status, or --expect-version for a local --package.
The server URL can also be set through CHROMIUM_TEST_UPDATE_SERVER_URL.
Commands, result.json and junit.xml are retained in a unique results folder;
nothing is uploaded to GitLab.

Example:
    python prepare_integration_test.py --server http://test-server:8080 \
        --target linux_deb --results-dir /var/tmp/update-results
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
import platform
import plistlib
import time
import sys
import tempfile
import urllib.request

from ci_common import (SERVER_ENV_VARIABLE, TARGETS, capture_command, choose_target,
                       normalize_server_url, parse_version, positive_seconds,
                       run_command, run_reported, version, version_argument, wait_for_server,
                       windows_installed_version)


class Platform:

    TARGETS = ()
    DEFAULT_TARGET = None

    def __init__(self, target=None, command_timeout=300, log_path=None):
        if target is not None and target not in self.TARGETS:
            raise ValueError(f"{type(self).__name__} cannot handle target '{target}'; "
                             f"expected one of {self.TARGETS}")
        self.target = target or self.DEFAULT_TARGET
        self.command_timeout = command_timeout
        self.log_path = log_path

    def require_privileges(self):
        pass

    def remove(self):
        raise NotImplementedError(f"removal not implemented for {type(self).__name__}")

    def install(self, package_path):
        raise NotImplementedError(f"install not implemented for {type(self).__name__}")

    def _run(self, command, what, ok_codes=(0,)):
        environment = os.environ.copy()
        environment["DEBIAN_FRONTEND"] = "noninteractive"
        return run_command(command, what, self.log_path, self.command_timeout,
                           ok_codes=ok_codes, env=environment)

    def installed_version(self):
        raise NotImplementedError


class LinuxPlatform(Platform):
    TARGETS = ("linux_deb", "linux_rpm")
    DEFAULT_TARGET = "linux_deb"
    PACKAGE_NAME = "chromium-gost-stable"

    # target -> (query installed, remove, install)
    COMMANDS = {
        "linux_deb": (["dpkg-query", "-W", "-f=${Status}"],
                      ["apt-get", "remove", "-y"],
                      ["apt-get", "install", "-y", "--no-download"]),
        "linux_rpm": (["rpm", "-q"], ["dnf", "--cacheonly", "remove", "-y"],
                      ["dnf", "--cacheonly", "install", "-y"]),
    }

    def require_privileges(self):
        if os.geteuid() != 0:
            raise RuntimeError("must run as root (use sudo) -- package remove/install need it")

    def remove(self):
        query, remove, _ = self.COMMANDS[self.target]
        result = capture_command(query + [self.PACKAGE_NAME], timeout=self.command_timeout,
                                 ok_codes=(0, 1))
        if result.returncode == 1 or (self.target == "linux_deb" and "install ok installed" not in result.stdout):
            print(f"{self.PACKAGE_NAME} is not installed; nothing to remove")
            return
        self._run(remove + [self.PACKAGE_NAME], f"remove {self.PACKAGE_NAME}")

    def install(self, package_path):
        _, _, install = self.COMMANDS[self.target]
        self._run(install + [package_path], f"install {package_path}")

    def installed_version(self):
        command = (["dpkg-query", "-W", "-f=${Version}", self.PACKAGE_NAME]
                   if self.target == "linux_deb" else
                   ["rpm", "-q", "--qf", "%{VERSION}", self.PACKAGE_NAME])
        return parse_version(capture_command(command, timeout=self.command_timeout).stdout)


class WindowsPlatform(Platform):
    TARGETS = ("windows",)
    DEFAULT_TARGET = "windows"

    UNINSTALL_KEY = r"Software\Chromium"
    UNINSTALL_STRING_VALUE = "UninstallString"
    UNINSTALL_ARGS_VALUE = "UninstallArguments"

    UNINSTALL_FLAGS = ["--force-uninstall"]

    UNINSTALL_OK_CODES = {0, 19}  # Continue installing the baseline even if a reboot is requested.

    INSTALL_FLAGS = ["--silent", "--do-not-launch-chrome"]

    def __init__(self, target=None, system_level=False, **kwargs):
        super().__init__(target, **kwargs)
        self.system_level = system_level

    def require_privileges(self):
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError("preparation requires an administrator session on Windows")

    def installed_version(self):
        return windows_installed_version(self.system_level)

    def remove(self):
        self._remove_scope(system_level=True)
        self._remove_scope(system_level=False)

    def _remove_scope(self, system_level):
        import winreg

        hive = winreg.HKEY_LOCAL_MACHINE if system_level else winreg.HKEY_CURRENT_USER
        hive_name = "HKLM" if system_level else "HKCU"
        # Explicit views make discovery independent of Python's bitness.
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, self.UNINSTALL_KEY, 0,
                                    winreg.KEY_READ | view) as key:
                    uninstall_string, _ = winreg.QueryValueEx(key, self.UNINSTALL_STRING_VALUE)
                    try:
                        uninstall_args, _ = winreg.QueryValueEx(key, self.UNINSTALL_ARGS_VALUE)
                    except FileNotFoundError:
                        uninstall_args = ""
                break
            except FileNotFoundError:
                continue
        else:
            print(f"no uninstall entry at {hive_name}\\{self.UNINSTALL_KEY} "
                  "in either 64-bit or 32-bit registry view; nothing to remove")
            return

        parts = [uninstall_string, uninstall_args, *self.UNINSTALL_FLAGS]
        if system_level:
            parts.append("--system-level")
        command_line = " ".join(part for part in parts if part)
        result = self._run(command_line, f"uninstall ({hive_name})",
                           ok_codes=self.UNINSTALL_OK_CODES)
        if result == 19:
            print("uninstall requested a reboot (exit 19); continuing without reboot", flush=True)

    def install(self, package_path):
        flags = self.INSTALL_FLAGS + (["--system-level"] if self.system_level else [])
        self._run([package_path, *flags], f"install {package_path}")


class MacOSPlatform(Platform):
    TARGETS = ("macos",)
    DEFAULT_TARGET = "macos"

    APP_NAME = "Chromium-Gost.app"
    APP_PATH = "/Applications/Chromium-Gost.app"
    HELPER_LABEL = "ru.cryptopro.browser-update-helper"
    HELPER_BUNDLE_SUBDIR = "Contents/Library/LaunchServices"
    PRIVILEGED_HELPER_DIR = "/Library/PrivilegedHelperTools"

    def installed_version(self):
        with open(os.path.join(self.APP_PATH, "Contents", "Info.plist"), "rb") as handle:
            info = plistlib.load(handle)
        return version(info.get("CFBundleShortVersionString", info.get("CFBundleVersion")))

    def require_privileges(self):
        if os.geteuid() != 0:
            raise RuntimeError("must run as root (use sudo) -- "
                               "modifying /Applications and /Library needs it")

    def remove(self):
        if os.path.exists(self.APP_PATH):
            self._run(["rm", "-rf", self.APP_PATH], "remove app bundle")
        else:
            print(f"{self.APP_PATH} not present; nothing to remove")

    def install(self, package_path):
        with tempfile.TemporaryDirectory(prefix="mac-bundle-") as tmp:
            self._run(["tar", "-xzf", package_path, "-C", tmp], "extract tarball")
            extracted_app = os.path.join(tmp, self.APP_NAME)
            if not os.path.isdir(extracted_app):
                raise RuntimeError(f"{self.APP_NAME} not found at top level of the tarball")
            self._run(["ditto", extracted_app, self.APP_PATH], "install app bundle")

            helper_src = os.path.join(self.APP_PATH, self.HELPER_BUNDLE_SUBDIR, self.HELPER_LABEL)
            if not os.path.isfile(helper_src):
                raise RuntimeError(f"helper not found in bundle: {helper_src}")
            helper_dest = os.path.join(self.PRIVILEGED_HELPER_DIR, self.HELPER_LABEL)
            os.makedirs(self.PRIVILEGED_HELPER_DIR, exist_ok=True)
            self._run(["ditto", helper_src, helper_dest], "install privileged helper (in place)")


PLATFORMS = {
    "Linux": LinuxPlatform,
    "Windows": WindowsPlatform,
    "Darwin": MacOSPlatform,
}


def current_platform(target=None, system_level=False, **kwargs):
    target = choose_target(target)
    system = platform.system()
    platform_class = PLATFORMS.get(system)
    if platform_class is None:
        raise NotImplementedError(f"no platform support for '{system}'")
    if system == "Windows":
        return platform_class(target, system_level=system_level, **kwargs)
    if system_level:
        raise ValueError("--system-level is only supported on Windows")
    return platform_class(target, **kwargs)


def download_baseline(server_url, target, dest_dir, timeout):
    url = f"{server_url}/download-current/{target}"
    suffix = {"windows": ".exe", "macos": ".tgz", "linux_deb": ".deb", "linux_rpm": ".rpm"}[target]
    # Never turn a server-provided Content-Disposition into a filesystem path.
    path = os.path.join(dest_dir, "baseline" + suffix)
    deadline = time.monotonic() + timeout
    count = 0
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"download returned HTTP {response.status}")
            expected = response.headers.get("Content-Length")
            expected = int(expected) if expected is not None else None
            if expected is not None and expected <= 0:
                raise RuntimeError("baseline download is empty")
            with open(path, "xb") as handle:
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"baseline download exceeded {timeout}s")
                    chunk = response.read1(64 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    count += len(chunk)
        if count == 0 or (expected is not None and count != expected):
            raise RuntimeError(f"baseline download was truncated ({count}/{expected} bytes)")
    except BaseException:
        if os.path.isfile(path):
            os.unlink(path)
        raise
    print(f"downloaded {count} bytes -> {path}", flush=True)
    return path


def baseline_version(args, target):
    """Resolve the required baseline before downloading or changing the machine."""
    if args.package:
        if args.expect_version is None:
            raise ValueError("--package requires --expect-version")
        return args.expect_version
    args.server = normalize_server_url(args.server)
    status = wait_for_server(args.server, target, args.server_timeout, run_id=args.run_id)
    expected = status["current_version"]
    if args.expect_version not in (None, expected):
        raise ValueError(f"server baseline is {expected}, expected {args.expect_version}")
    return expected


@contextmanager
def baseline_package(args, target):
    """Use the local package, or download and own a temporary copy."""
    if args.package:
        yield os.path.abspath(args.package)
    else:
        with tempfile.TemporaryDirectory(prefix="prepare-baseline-") as directory:
            yield download_baseline(args.server, target, directory, args.timeout)


def prepare(args, report):
    target = current_platform(args.target, system_level=args.system_level,
                              command_timeout=args.command_timeout,
                              log_path=report.directory / "commands.log")
    target.require_privileges()
    expected = baseline_version(args, target.target)
    report.data.update(target=target.target, expected_version=expected, run_id=args.run_id)

    with baseline_package(args, target.target) as package:
        target.remove()
        target.install(package)

    installed = target.installed_version()
    report.data["installed_version"] = installed
    if installed != expected:
        raise RuntimeError(f"installed baseline is {installed!r}, expected {expected}")
    print(f"baseline prepared: {target.target} {expected}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=os.environ.get(SERVER_ENV_VARIABLE))
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--package", help="local baseline package; requires --expect-version")
    parser.add_argument("--expect-version", type=version_argument,
                        help="baseline version; defaults to server current_version")
    parser.add_argument("--timeout", type=positive_seconds, default=120,
                        help="download deadline and socket timeout, seconds (default: 120)")
    parser.add_argument("--server-timeout", type=positive_seconds, default=30)
    parser.add_argument("--command-timeout", type=positive_seconds, default=300,
                        help="timeout for each package-manager/installer command")
    parser.add_argument("--system-level", action="store_true",
                        help="Windows: install system-wide; both installation scopes are removed")
    parser.add_argument("--run-id", help="expected server run_id, if one was supplied")
    parser.add_argument("--results-dir", help="parent for a unique results folder; default: system temp")
    args = parser.parse_args(argv)
    return run_reported(args.results_dir, "prepare", lambda report: prepare(args, report))


if __name__ == "__main__":
    sys.exit(main())
