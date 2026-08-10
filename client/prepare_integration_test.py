#!/usr/bin/env python3
"""
prepare_integration_testing.py

Put the machine into a known baseline before the update test: remove the currently
installed browser, then install the "current" build fetched from the server's
/download-current/<os>/<installer>. Each OS's remove/install logic and constants live in
its own Platform subclass; prepare() picks one and drives it through the shared steps.

Usage:
    python prepare_integration_testing.py [--server <url>]
        [--os linux] [--installer deb] [--package <path>] [--timeout 120]

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


SERVER_ENV_VARIABLE='CHROMIUM_TEST_UPDATE_SERVER_URL'


class Platform:

    OS_NAME = None
    DEFAULT_INSTALLER = None

    def require_privileges(self):
        pass

    def remove(self):
        raise NotImplementedError(f"removal not implemented for {type(self).__name__}")

    def install(self, package_path):
        raise NotImplementedError(f"install not implemented for {type(self).__name__}")


class LinuxPlatform(Platform):
    OS_NAME = "linux"
    DEFAULT_INSTALLER = "deb"
    PACKAGE_NAME = "chromium-gost-stable"

    def require_privileges(self):
        if os.geteuid() != 0:
            raise RuntimeError("must run as root (use sudo) -- apt remove/install need it")

    def remove(self):
        if not self._dpkg_installed(self.PACKAGE_NAME):
            print(f"{self.PACKAGE_NAME} is not installed; nothing to remove")
            return
        print(f"removing {self.PACKAGE_NAME} via apt...")
        result = subprocess.run(["apt", "remove", "-y", self.PACKAGE_NAME],
                                capture_output=True, text=True)
        sys.stdout.write(result.stdout)
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            raise RuntimeError(f"apt remove failed (exit {result.returncode})")

    def install(self, package_path):
        print(f"installing {package_path} via apt...")
        result = subprocess.run(["apt", "install", "-y", package_path],
                                capture_output=True, text=True)
        sys.stdout.write(result.stdout)
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            raise RuntimeError(f"apt install failed (exit {result.returncode})")

    @staticmethod
    def _dpkg_installed(package):
        result = subprocess.run(["dpkg", "-s", package], capture_output=True, text=True)
        return result.returncode == 0


class WindowsPlatform(Platform):
    OS_NAME = "windows"
    DEFAULT_INSTALLER = "exe"

    UNINSTALL_KEY = r"Software\Chromium"
    UNINSTALL_STRING_VALUE = "UninstallString"
    UNINSTALL_ARGS_VALUE = "UninstallArguments"

    UNINSTALL_FLAGS = ["--force-uninstall"]

    UNINSTALL_OK_CODES = {0, 19}  # 19 = reboot-required, still a successful uninstall

    INSTALL_FLAGS = ["--silent", "--do-not-launch-chrome"]

    def remove(self):
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.UNINSTALL_KEY) as key:
                uninstall_string, _ = winreg.QueryValueEx(key, self.UNINSTALL_STRING_VALUE)
                try:
                    uninstall_args, _ = winreg.QueryValueEx(key, self.UNINSTALL_ARGS_VALUE)
                except FileNotFoundError:
                    uninstall_args = ""
        except FileNotFoundError:
            print(f"no uninstall entry at HKCU\\{self.UNINSTALL_KEY}; nothing to remove")
            return

        command_line = uninstall_string
        if uninstall_args:
            command_line = f"{command_line} {uninstall_args}"
        if self.UNINSTALL_FLAGS:
            command_line = f"{command_line} {' '.join(self.UNINSTALL_FLAGS)}"
        print(f"running uninstall: {command_line}")
        result = subprocess.run(command_line, capture_output=True, text=True)
        sys.stdout.write(result.stdout or "")
        if result.returncode not in self.UNINSTALL_OK_CODES:
            sys.stderr.write(result.stderr or "")
            raise RuntimeError(f"uninstall failed (exit {result.returncode})")
        if result.returncode != 0:
            print(f"uninstall succeeded with exit {result.returncode} "
                  f"(reboot may be needed to finish removing files)")

    def install(self, package_path):
        command = [package_path] + self.INSTALL_FLAGS
        print(f"installing: {command}")
        result = subprocess.run(command, capture_output=True, text=True)
        sys.stdout.write(result.stdout or "")
        if result.returncode != 0:
            sys.stderr.write(result.stderr or "")
            raise RuntimeError(f"installer failed (exit {result.returncode})")


class MacOSPlatform(Platform):
    OS_NAME = "macos"
    DEFAULT_INSTALLER = "tar"

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
            self._run(["tar", "-xjf", package_path, "-C", tmp], "extract tarball")
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

    @staticmethod
    def _run(command, what):
        print(f"{what}: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True)
        sys.stdout.write(result.stdout or "")
        if result.returncode != 0:
            sys.stderr.write(result.stderr or "")
            raise RuntimeError(f"{what} failed (exit {result.returncode})")


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


def normalize_server_url(server_url):
    if not server_url:
        return server_url
    if "://" not in server_url:
        return "http://" + server_url
    return server_url


def _filename_from_disposition(disposition):
    match = re.search(r'filename="?([^"]+)"?', disposition or "")
    return match.group(1) if match else None


def download_baseline(server_url, os_name, installer, dest_dir, timeout):
    url = f"{server_url.rstrip('/')}/download-current/{os_name}/{installer}"
    print(f"downloading baseline from {url} ...")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        disposition = response.headers.get("Content-Disposition", "")
        data = response.read()
    filename = _filename_from_disposition(disposition) or f"baseline-{os_name}-{installer}"
    path = os.path.join(dest_dir, filename)
    with open(path, "wb") as handle:
        handle.write(data)
    print(f"saved {len(data)} bytes -> {path}")
    return path


def prepare(server_url, os_name, installer, package, timeout):
    target = current_platform()
    target.require_privileges()

    os_name = os_name or target.OS_NAME
    installer = installer or target.DEFAULT_INSTALLER

    target.remove()

    if package:
        target.install(os.path.abspath(package))
    else:
        if not server_url:
            raise ValueError("need --server (to fetch the baseline), env variable CHROMIUM_TEST_UPDATE_SERVER_URL or --package")
        if os_name is None or installer is None:
            raise ValueError("could not determine os/installer; pass --os and --installer")
        with tempfile.TemporaryDirectory(prefix="prepare-baseline-") as tmp:
            baseline = download_baseline(server_url, os_name, installer, tmp, timeout)
            target.install(baseline)
    print("baseline prepared")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Remove the current browser and install the baseline for testing.")
    parser.add_argument("--server", default=os.environ.get(SERVER_ENV_VARIABLE),
                        help="base URL of the running update server (for /download-current). "
                        f"Can also be set via {SERVER_ENV_VARIABLE} envrionment variable")
    parser.add_argument("--os", dest="os_name", default=None,
                        help="download-current os; defaults to this platform's")
    parser.add_argument("--installer", default=None,
                        help="download-current installer; defaults to this platform's")
    parser.add_argument("--package", default=None,
                        help="install this local package instead of fetching from --server")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="hard timeout for the baseline download")
    args = parser.parse_args(argv)

    server_url = normalize_server_url(args.server)
    try:
        prepare(server_url, args.os_name, args.installer, args.package, args.timeout)
    except NotImplementedError as error:
        print(f"NOT IMPLEMENTED: {error}", file=sys.stderr)
        return 3
    except (RuntimeError, ValueError, OSError) as error:
        print(f"PREPARE FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
