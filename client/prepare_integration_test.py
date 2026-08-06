#!/usr/bin/env python3
"""
prepare_integration_testing.py -- put the machine into a known baseline BEFORE the update
test: remove the currently-installed browser, then install the "current" build fetched
from the running test server's /download-current/<os>/<installer>.

Each OS's remove/install logic and constants live in its own Platform subclass
(LinuxPlatform / WindowsPlatform / MacOSPlatform). prepare() selects the class once and
drives it through the shared steps (privilege check -> remove -> download -> install).

Removal:  Linux (apt) and Windows (registry UninstallString + UninstallArguments, HKCU /
          per-user only) are implemented. macOS and system-wide Windows raise
          NotImplementedError.
Install:  Linux (apt) and Windows (run the .exe with --silent --do-not-launch-chrome) are
          implemented. macOS raises NotImplementedError.

Assumes elevated privileges (Linux: root/sudo; Windows: Administrator as your install
requires).

USAGE
    python prepare_integration_testing.py --server http://HOST:PORT
        [--os linux] [--installer deb] [--package /path/to/local.deb]

    --os/--installer  default to this platform (Linux -> linux/deb).
    --package  install this local file instead of fetching /download-current.
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


# ----------------------------------------------------------------------------------------
# Per-OS logic + constants. Each subclass owns everything specific to its platform.
# ----------------------------------------------------------------------------------------

class Platform:
    """Base interface. OS_NAME / DEFAULT_INSTALLER feed the /download-current URL."""

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
    PACKAGE_NAME = "chromium-gost-stable"   # apt package to remove / that the .deb provides

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
        # apt treats an absolute path ending in .deb as a local package file and resolves
        # dependencies.
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

    # Registry key (under HKCU for a per-user install) holding the uninstall command.
    # You found `pv` under HKCU\Software\Chromium; confirm UninstallString/UninstallArguments
    # live under this same key for your build, or repoint it.
    UNINSTALL_KEY = r"Software\Chromium"
    UNINSTALL_STRING_VALUE = "UninstallString"
    UNINSTALL_ARGS_VALUE = "UninstallArguments"

    INSTALL_FLAGS = ["--silent", "--do-not-launch-chrome"]

    def remove(self):
        """Read the uninstall command the browser registered under HKCU and run it verbatim
        (UninstallString + UninstallArguments). System-wide (HKLM) is not implemented."""
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

        # UninstallString bundles the (quoted) exe path with its own args. Passing the whole
        # command line as ONE string lets Windows' CreateProcess parse the quoting correctly
        # -- shlex would keep the quotes (posix=False) or mangle backslashes (posix=True).
        command_line = uninstall_string
        if uninstall_args:
            command_line = f"{uninstall_string} {uninstall_args}"
        print(f"running uninstall: {command_line}")
        result = subprocess.run(command_line, capture_output=True, text=True)
        sys.stdout.write(result.stdout or "")
        if result.returncode != 0:
            sys.stderr.write(result.stderr or "")
            raise RuntimeError(f"uninstall failed (exit {result.returncode})")

    def install(self, package_path):
        """Run the downloaded installer .exe silently, without launching the browser."""
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

    def remove(self):
        raise NotImplementedError("macOS removal not implemented yet")

    def install(self, package_path):
        raise NotImplementedError("macOS install not implemented yet")


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
# Shared steps (platform-agnostic)
# ----------------------------------------------------------------------------------------

def normalize_server_url(server_url):
    """Accept 'host:port' as well as 'http://host:port' -- urllib needs the scheme."""
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


# ----------------------------------------------------------------------------------------

def prepare(server_url, os_name, installer, package, timeout):
    target = current_platform()                       # pick the OS class once
    target.require_privileges()

    os_name = os_name or target.OS_NAME
    installer = installer or target.DEFAULT_INSTALLER

    target.remove()

    if package:
        target.install(os.path.abspath(package))
    else:
        if not server_url:
            raise ValueError("need --server (to fetch the baseline) or --package")
        if os_name is None or installer is None:
            raise ValueError("could not determine os/installer; pass --os and --installer")
        with tempfile.TemporaryDirectory(prefix="prepare-baseline-") as tmp:
            baseline = download_baseline(server_url, os_name, installer, tmp, timeout)
            target.install(baseline)
    print("baseline prepared")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Remove the current browser and install the baseline for testing.")
    parser.add_argument("--server", default=None,
                        help="base URL of the running update server (for /download-current)")
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
