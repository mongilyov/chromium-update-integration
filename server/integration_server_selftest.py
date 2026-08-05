#!/usr/bin/env python3
"""
selftest.py -- exercise every variant + /download-current against the test update server
with a plain HTTP client standing in for the browser.

    python selftest.py --demo            # generate throwaway fake artifacts, run all
    python selftest.py --artifacts DIR   # run against real artifacts in DIR
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import test_update_server as server
from test_update_server import (
    TARGETS,
    REQ_OS_FIELD,
    REQ_INSTALLER_FIELD,
    REQ_VERSION_FIELD,
    RESP_AVAILABLE_FIELD,
    RESP_URL_FIELD,
    RESP_VERSION_FIELD,
    payload_filename,
)

CLIENT_VERSION = "150.0.7871.212"
CLIENT_OS = "linux"
CLIENT_INSTALLER = "deb"

DEMO_VERSIONS = {
    "current": "150.0.7871.212",
    "newer":   "999.0.0.0",
    "older":   "124.0.6367.91",
}


def _write_demo_artifacts(root):
    for role, version in DEMO_VERSIONS.items():
        role_dir = os.path.join(root, role)
        os.makedirs(role_dir, exist_ok=True)
        with open(os.path.join(role_dir, "version.txt"), "w", encoding="utf-8") as handle:
            handle.write(version + "\n")
        for os_name, installer in TARGETS:
            filename = payload_filename(version, os_name, installer)
            with open(os.path.join(role_dir, filename), "wb") as handle:
                handle.write(f"{role}-{os_name}-{installer}-PAYLOAD-".encode() * 64)
    installers = sorted({installer for _, installer in TARGETS})
    return {
        "newer": {i: {"signature": f"DEMO-SIG-{i}", "timestamp": "15.05.2024"} for i in installers},
        "older": {i: {"signature": f"DEMO-SIG-{i}", "timestamp": "02.09.2023"} for i in installers},
    }


def _post(url, fields, timeout):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


def _get(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.status, response.read(), response.headers


def _check_bad_os(base_url):
    label = f"{'bad-os':<14}"
    try:
        _post(f"{base_url}/ok/update",
              {REQ_OS_FIELD: "nope", REQ_INSTALLER_FIELD: CLIENT_INSTALLER, REQ_VERSION_FIELD: CLIENT_VERSION}, timeout=5)
        print(f"{label} UNEXPECTED: accepted")
    except urllib.error.HTTPError as error:
        print(f"{label} HTTP {error.code} (bad target punished)")


def _check_download_current(base_url):
    label = f"{'download-current':<14}"
    url = f"{base_url}/download-current/{CLIENT_OS}/{CLIENT_INSTALLER}"
    try:
        _, payload, headers = _get(url, timeout=5)
        disposition = headers.get("Content-Disposition", "")
        print(f"{label} {len(payload)}B, {disposition}")
    except Exception as error:
        print(f"{label} FAILED: {type(error).__name__}: {error}")


def _check_variant(base_url, name, expect_version):
    check_url = f"{base_url}/{name}/update"
    fields = {REQ_OS_FIELD: CLIENT_OS, REQ_INSTALLER_FIELD: CLIENT_INSTALLER,
              REQ_VERSION_FIELD: CLIENT_VERSION}
    label = f"{name:<14}"

    if name == "hang":
        start_time = time.time()
        try:
            _post(check_url, fields, timeout=1.5)
            print(f"{label} UNEXPECTED: got a response")
        except Exception:
            print(f"{label} hung ~{time.time() - start_time:.1f}s then timed out (expected)")
        return
    if name == "http500":
        try:
            _post(check_url, fields, timeout=5)
            print(f"{label} UNEXPECTED: no error")
        except urllib.error.HTTPError as error:
            print(f"{label} HTTP {error.code} (expected)")
        return
    if name == "badjson":
        _, body = _post(check_url, fields, timeout=5)
        try:
            json.loads(body)
            print(f"{label} UNEXPECTED: parsed as JSON")
        except json.JSONDecodeError:
            print(f"{label} malformed JSON (expected)")
        return
    if name == "truncated":
        try:
            _, body = _post(check_url, fields, timeout=5)
            print(f"{label} got {len(body)} bytes (client-dependent)")
        except http.client.IncompleteRead as error:
            print(f"{label} IncompleteRead: {len(error.partial)} bytes (expected)")
        except Exception as error:
            print(f"{label} short read: {type(error).__name__} (expected)")
        return

    try:
        _, body = _post(check_url, fields, timeout=5)
    except urllib.error.HTTPError as error:
        print(f"{label} HTTP {error.code}: {error.read().decode('utf-8', 'replace').strip()}")
        return

    document = json.loads(body)
    if not document.get(RESP_AVAILABLE_FIELD, False):
        print(f"{label} no-update: {json.dumps(document)}")
        return

    version = document.get(RESP_VERSION_FIELD)
    try:
        _, payload, _ = _get(document.get(RESP_URL_FIELD), timeout=5)
        note = f"downloaded {len(payload)}B"
        if name == "corrupt":
            note += " (byte flipped vs signed original)"
        if name == "downgrade":
            note += " (server deliberately offered older)"
    except Exception as error:
        note = f"download FAILED: {type(error).__name__}"
    verdict = "" if version == expect_version else f"  [EXPECTED {expect_version}]"
    print(f"{label} update->{version}; {note}{verdict}")
    if name in ("ok", "downgrade"):
        print(json.dumps(document, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Exercise every variant against the test update server.")
    parser.add_argument("--artifacts", default=None)
    parser.add_argument("--demo", action="store_true",
                        help="generate throwaway fake payloads/sigs so all variants run")
    args = parser.parse_args(argv)

    temp_dir = None
    if args.demo:
        temp_dir = tempfile.mkdtemp(prefix="upd-demo-")
        server.CONFIG["artifacts_dir"] = temp_dir
        server.ARTIFACTS = _write_demo_artifacts(temp_dir)
    elif args.artifacts:
        server.CONFIG["artifacts_dir"] = args.artifacts

    update_server = server.UpdateServer(quiet=True)
    base_url = update_server.start()
    print(f"server: {base_url}")
    server.print_artifact_report()
    print(f"(client reports version {CLIENT_VERSION})\n")

    expectations = {
        "ok": DEMO_VERSIONS["newer"],
        "downgrade": DEMO_VERSIONS["older"],
        "corrupt": DEMO_VERSIONS["newer"],
    }
    order = ["ok", "downgrade", "corrupt", "truncated", "badjson", "http500", "hang"]
    try:
        for name in order:
            _check_variant(base_url, name, expectations.get(name))
        _check_download_current(base_url)
        _check_bad_os(base_url)
    finally:
        update_server.stop()
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
