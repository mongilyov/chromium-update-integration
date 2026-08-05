#!/usr/bin/env python3
"""
prepare_integration_testing.py -- put the machine into a known baseline BEFORE the update
test: remove the currently-installed browser, then install the "current" build fetched
from the running test server's /download-current/<target>.

Linux (apt/deb) is implemented. Windows and macOS raise NotImplementedError.

Assumes root/Administrator -- apt remove/install require it.

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


# Package to remove (and that the baseline install provides). Adjust to your package name.
PACKAGE_NAME = "chromium-gost-stable"

OS_BY_SYSTEM = {
    "Linux": "linux",
    "Windows": "windows",
    "Darwin": "macos",
}
DEFAULT_INSTALLER_BY_SYSTEM = {
    "Linux": "deb",
    "Windows": "exe",
    "Darwin": "tar",
}


def default_os():
    return OS_BY_SYSTEM.get(platform.system())


def default_installer():
    return DEFAULT_INSTALLER_BY_SYSTEM.get(platform.system())


def normalize_server_url(server_url):
    """Accept 'host:port' as well as 'http://host:port' -- urllib needs the scheme, so
    default a missing one to http://."""
    if not server_url:
        return server_url
    if "://" not in server_url:
        return "http://" + server_url
    return server_url


def require_root():
    """apt remove/install need root. Fail early and clearly if we're not root, rather
    than deep inside an apt call. No-op on platforms without geteuid (e.g. Windows)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        raise RuntimeError("must run as root (use sudo) -- apt remove/install need it")


# ----------------------------------------------------------------------------------------
# Remove the currently-installed browser
# ----------------------------------------------------------------------------------------

def remove_current():
    system = platform.system()
    if system == "Linux":
        return _remove_current_linux()
    if system == "Windows":
        raise NotImplementedError("Windows removal not implemented yet")
    if system == "Darwin":
        raise NotImplementedError("macOS removal not implemented yet")
    raise NotImplementedError(f"no removal implemented for platform '{system}'")


def _dpkg_installed(package):
    result = subprocess.run(["dpkg", "-s", package], capture_output=True, text=True)
    return result.returncode == 0


def _remove_current_linux():
    if not _dpkg_installed(PACKAGE_NAME):
        print(f"{PACKAGE_NAME} is not installed; nothing to remove")
        return
    print(f"removing {PACKAGE_NAME} via apt...")
    result = subprocess.run(["apt", "remove", "-y", PACKAGE_NAME],
                            capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise RuntimeError(f"apt remove failed (exit {result.returncode})")


# ----------------------------------------------------------------------------------------
# Fetch the baseline installer from the server
# ----------------------------------------------------------------------------------------

def _filename_from_disposition(disposition):
    match = re.search(r'filename="?([^"]+)"?', disposition or "")
    return match.group(1) if match else None


def download_baseline(server_url, os_name, installer, dest_dir, timeout):
    url = f"{server_url.rstrip('/')}/download-current/{os_name}/{installer}"
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


# ----------------------------------------------------------------------------------------
# Install the baseline
# ----------------------------------------------------------------------------------------

def install(package_path):
    system = platform.system()
    if system == "Linux":
        return _install_linux(package_path)
    if system == "Windows":
        raise NotImplementedError("Windows install not implemented yet")
    if system == "Darwin":
        raise NotImplementedError("macOS install not implemented yet")
    raise NotImplementedError(f"no install implemented for platform '{system}'")


def _install_linux(package_path):
    # apt treats an argument containing a slash and ending in .deb as a local package file
    # and resolves dependencies. package_path is absolute, so it qualifies.
    print(f"installing {package_path} via apt...")
    result = subprocess.run(["apt", "install", "-y", package_path],
                            capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise RuntimeError(f"apt install failed (exit {result.returncode})")


# ----------------------------------------------------------------------------------------

def prepare(server_url, os_name, installer, package, timeout):
    remove_current()
    if package:
        install(os.path.abspath(package))
    else:
        if not server_url:
            raise ValueError("need --server (to fetch the baseline) or --package")
        with tempfile.TemporaryDirectory(prefix="prepare-baseline-") as tmp:
            baseline = download_baseline(server_url, os_name, installer, tmp, timeout)
            install(baseline)
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

    os_name = args.os_name or default_os()
    installer = args.installer or default_installer()
    if (os_name is None or installer is None) and not args.package:
        print(f"could not determine os/installer for platform '{platform.system()}'; "
              f"pass --os and --installer", file=sys.stderr)
        return 2

    try:
        prepare(args.server, os_name, installer, args.package, args.timeout)
    except NotImplementedError as error:
        print(f"NOT IMPLEMENTED: {error}", file=sys.stderr)
        return 3
    except (RuntimeError, ValueError, OSError) as error:
        print(f"PREPARE FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
