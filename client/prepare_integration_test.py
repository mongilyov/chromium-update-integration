#!/usr/bin/env python3
"""
prepare_integration_testing.py -- put the machine into a known baseline BEFORE the update
test: remove the currently-installed browser, then install the "current" build fetched
from the running test server's /download-current/<target>.

Linux (apt/deb) is implemented. Windows and macOS raise NotImplementedError.

Assumes root/Administrator -- apt remove/install require it.

USAGE
    python prepare_integration_testing.py --server http://HOST:PORT
        [--target linux_deb] [--package /path/to/local.deb]

    --target   defaults to the current platform's target (Linux -> linux_deb).
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

TARGET_BY_SYSTEM = {
    "Linux": "linux_deb",
    "Windows": "windows",
    "Darwin": "macos",
}


def default_target():
    return TARGET_BY_SYSTEM.get(platform.system())


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

def prepare(server_url, target, package, timeout):
    remove_current()
    if package:
        install(os.path.abspath(package))
    else:
        if not server_url:
            raise ValueError("need --server (to fetch the baseline) or --package")
        with tempfile.TemporaryDirectory(prefix="prepare-baseline-") as tmp:
            baseline = download_baseline(server_url, target, tmp, timeout)
            install(baseline)
    print("baseline prepared")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Remove the current browser and install the baseline for testing.")
    parser.add_argument("--server", default=None,
                        help="base URL of the running update server (for /download-current)")
    parser.add_argument("--target", default=None,
                        help="download-current target; defaults to this platform's")
    parser.add_argument("--package", default=None,
                        help="install this local package instead of fetching from --server")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="hard timeout for the baseline download")
    args = parser.parse_args(argv)

    target = args.target or default_target()
    if target is None and not args.package:
        print(f"could not determine a target for platform '{platform.system()}'; "
              f"pass --target", file=sys.stderr)
        return 2

    try:
        prepare(args.server, target, args.package, args.timeout)
    except NotImplementedError as error:
        print(f"NOT IMPLEMENTED: {error}", file=sys.stderr)
        return 3
    except (RuntimeError, ValueError, OSError) as error:
        print(f"PREPARE FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
