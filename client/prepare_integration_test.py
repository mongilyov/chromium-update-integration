#!/usr/bin/env python3
"""
prepare_integration_testing.py

Put the machine into a known baseline before the update test: remove the currently
installed browser, then install the "current" build fetched from the server's
/download-current/<target>. Each OS's remove/install logic and constants live in
its own Platform subclass; prepare() picks one and drives it through the shared steps.

Targets are the server's: windows, macos, linux_deb, linux_rpm. Each platform knows
which ones it can handle and defaults to one, so --target is only needed on Linux to
choose rpm over deb.

On Windows, run from an administrator PowerShell session: preparation removes
both the current user's and the machine-wide installs. The new baseline is
per-user by default; pass --system-level for a machine-wide baseline.

Usage:
    python prepare_integration_testing.py [--server <url>]
        [--target linux_rpm] [--package <path>] [--timeout 120] [--system-level]

URL can be passed as an environment variable.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request


SERVER_ENV_VARIABLE = 'CHROMIUM_TEST_UPDATE_SERVER_URL'

TARGETS = ("windows", "macos", "linux_deb", "linux_rpm")


class Platform:

    TARGETS = ()
    DEFAULT_TARGET = None

    def __init__(self, target=None):
        if target is not None and target not in self.TARGETS:
            raise ValueError(f"{type(self).__name__} cannot handle target '{target}'; "
                             f"expected one of {self.TARGETS}")
        self.target = target or self.DEFAULT_TARGET

    def require_privileges(self):
        pass

    def remove(self):
        raise NotImplementedError(f"removal not implemented for {type(self).__name__}")

    def install(self, package_path):
        raise NotImplementedError(f"install not implemented for {type(self).__name__}")

    @staticmethod
    def _run(command, what, ok_codes=(0,)):
        printable = command if isinstance(command, str) else " ".join(command)
        print(f"{what}: {printable}")
        result = subprocess.run(command, capture_output=True, text=True)
        sys.stdout.write(result.stdout or "")
        if result.returncode not in ok_codes:
            sys.stderr.write(result.stderr or "")
            raise RuntimeError(f"{what} failed (exit {result.returncode})")
        return result


class LinuxPlatform(Platform):
    TARGETS = ("linux_deb", "linux_rpm")
    DEFAULT_TARGET = "linux_deb"
    PACKAGE_NAME = "chromium-gost-stable"

    # target -> (query installed, remove, install)
    COMMANDS = {
        "linux_deb": (["dpkg", "-s"], ["apt", "remove", "-y"], ["apt", "install", "-y"]),
        "linux_rpm": (["rpm", "-q"], ["dnf", "remove", "-y"], ["dnf", "install", "-y"]),
    }

    def require_privileges(self):
        if os.geteuid() != 0:
            raise RuntimeError("must run as root (use sudo) -- package remove/install need it")

    def remove(self):
        query, remove, _ = self.COMMANDS[self.target]
        if subprocess.run(query + [self.PACKAGE_NAME], capture_output=True).returncode != 0:
            print(f"{self.PACKAGE_NAME} is not installed; nothing to remove")
            return
        self._run(remove + [self.PACKAGE_NAME], f"remove {self.PACKAGE_NAME}")

    def install(self, package_path):
        _, _, install = self.COMMANDS[self.target]
        self._run(install + [package_path], f"install {package_path}")


class WindowsPlatform(Platform):
    TARGETS = ("windows",)
    DEFAULT_TARGET = "windows"

    UNINSTALL_KEY = r"Software\Chromium"
    UNINSTALL_STRING_VALUE = "UninstallString"
    UNINSTALL_ARGS_VALUE = "UninstallArguments"

    UNINSTALL_FLAGS = ["--force-uninstall"]

    UNINSTALL_OK_CODES = {0, 19}  # 19 = reboot-required, still a successful uninstall

    INSTALL_FLAGS = ["--silent", "--do-not-launch-chrome"]

    def __init__(self, target=None, system_level=False):
        super().__init__(target)
        self.system_level = system_level

    def scope_flags(self):
        return ["--system-level"] if self.system_level else []

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

        command_line = uninstall_string
        if uninstall_args:
            command_line = f"{command_line} {uninstall_args}"
        uninstall_flags = self.UNINSTALL_FLAGS + (["--system-level"] if system_level else [])
        if uninstall_flags:
            command_line = f"{command_line} {' '.join(uninstall_flags)}"
        result = self._run(command_line, f"uninstall ({hive_name})",
                           ok_codes=self.UNINSTALL_OK_CODES)
        if result.returncode != 0:
            print(f"uninstall succeeded with exit {result.returncode} "
                  f"(reboot may be needed to finish removing files)")

    def install(self, package_path):
        self._run([package_path] + self.INSTALL_FLAGS + self.scope_flags(),
                  f"install {package_path}")


class MacOSPlatform(Platform):
    TARGETS = ("macos",)
    DEFAULT_TARGET = "macos"

    APP_NAME = "Chromium-Gost.app"
    APP_PATH = "/Applications/Chromium-Gost.app"
    HELPER_LABEL = "ru.cryptopro.browser-update-helper"
    HELPER_BUNDLE_SUBDIR = "Contents/Library/LaunchServices"
    PRIVILEGED_HELPER_DIR = "/Library/PrivilegedHelperTools"

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


def current_platform(target=None, system_level=False):
    system = platform.system()
    platform_class = PLATFORMS.get(system)
    if platform_class is None:
        raise NotImplementedError(f"no platform support for '{system}'")
    if system == "Windows":
        return platform_class(target, system_level=system_level)
    if system_level:
        raise ValueError("--system-level is only supported on Windows")
    return platform_class(target)


def normalize_server_url(server_url):
    if not server_url:
        return server_url
    if "://" not in server_url:
        return "http://" + server_url
    return server_url


def _filename_from_disposition(disposition):
    match = re.search(r'filename="?([^"]+)"?', disposition or "")
    return match.group(1) if match else None


def download_baseline(server_url, target, dest_dir, timeout):
    url = f"{server_url.rstrip('/')}/download-current/{target}"
    print(f"downloading baseline from {url} ...")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        disposition = response.headers.get("Content-Disposition", "")
        data = response.read()
    filename = _filename_from_disposition(disposition) or f"baseline-{target}"
    path = os.path.join(dest_dir, filename)
    with open(path, "wb") as handle:
        handle.write(data)
    print(f"saved {len(data)} bytes -> {path}")
    return path


def prepare(server_url, target, package, timeout, system_level=False):
    platform_target = current_platform(target, system_level=system_level)
    platform_target.require_privileges()

    platform_target.remove()

    if package:
        platform_target.install(os.path.abspath(package))
    else:
        if not server_url:
            raise ValueError(f"need --server (to fetch the baseline), env variable "
                             f"{SERVER_ENV_VARIABLE} or --package")
        with tempfile.TemporaryDirectory(prefix="prepare-baseline-") as tmp:
            baseline = download_baseline(server_url, platform_target.target, tmp, timeout)
            platform_target.install(baseline)
    print(f"baseline prepared ({platform_target.target})")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Remove the current browser and install the baseline for testing.")
    parser.add_argument("--server", default=os.environ.get(SERVER_ENV_VARIABLE),
                        help="base URL of the running update server (for /download-current). "
                        f"Can also be set via {SERVER_ENV_VARIABLE} envrionment variable")
    parser.add_argument("--target", default=None, choices=TARGETS,
                        help="artifact to fetch and install; defaults to this platform's "
                             "(only Linux has a choice: linux_deb or linux_rpm)")
    parser.add_argument("--package", default=None,
                        help="install this local package instead of fetching from --server")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="hard timeout for the baseline download")
    parser.add_argument("--system-level", action="store_true",
                        help="Windows: install the baseline system-wide instead of per-user; "
                             "both scopes are always removed first (requires administrator)")
    args = parser.parse_args(argv)

    server_url = normalize_server_url(args.server)
    try:
        prepare(server_url, args.target, args.package, args.timeout,
                system_level=args.system_level)
    except NotImplementedError as error:
        print(f"NOT IMPLEMENTED: {error}", file=sys.stderr)
        return 3
    except (RuntimeError, ValueError, OSError) as error:
        print(f"PREPARE FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
