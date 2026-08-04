#!/usr/bin/env python3
"""
selftest.py -- exercise every variant of the test update server with a plain HTTP client
standing in for the browser. Confirms the server works and shows the real response schema
without the full integration harness.

    python selftest.py --demo            # generate throwaway fake artifacts, run all variants
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
    OS_VALUES,
    REQ_OS_FIELD,
    REQ_VERSION_FIELD,
    RESP_AVAILABLE_FIELD,
    RESP_URL_FIELD,
    RESP_VERSION_FIELD,
)

CLIENT_VERSION = "125.0.6422.60"

DEMO_FILENAMES = {
    OS_VALUES[0]: "payload.exe",
    OS_VALUES[1]: "payload.zip",
    OS_VALUES[2]: "payload.deb",
}


def _write_demo_artifacts(root):
    plan = {
        "current": ("125.0.6422.60", b"CURRENT-PAYLOAD-" * 64, "10.01.2024"),
        "newer":   ("999.0.0.0",     b"NEWER-PAYLOAD-" * 64,   "15.05.2024"),
        "older":   ("124.0.6367.91", b"OLDER-PAYLOAD-" * 64,   "02.09.2023"),
    }
    artifacts = {}
    for role, (version, payload, timestamp) in plan.items():
        platforms = {}
        for os_name, filename in DEMO_FILENAMES.items():
            relative_path = os.path.join(role, os_name, filename)
            full_path = os.path.join(root, relative_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "wb") as file_handle:
                file_handle.write(payload)
            platforms[os_name] = {
                "file": relative_path,
                "signature": f"DEMO-SIG-OK-{os_name}",
                "timestamp": timestamp,
            }
        artifacts[role] = {"version": version, "platforms": platforms}
    return artifacts


def _post(url, fields, timeout):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


def _get(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.status, response.read()


def _check_bad_os(base_url):
    label = f"{'bad-os':<13}"
    try:
        _post(f"{base_url}/ok/update",
              {REQ_OS_FIELD: "nope", REQ_VERSION_FIELD: CLIENT_VERSION}, timeout=5)
        print(f"{label} UNEXPECTED: accepted")
    except urllib.error.HTTPError as error:
        print(f"{label} HTTP {error.code} (bad OS punished)")


def _check_variant(base_url, name):
    check_url = f"{base_url}/{name}/update"
    fields = {REQ_OS_FIELD: OS_VALUES[0], REQ_VERSION_FIELD: CLIENT_VERSION}
    label = f"{name:<13}"

    if name == "hang":
        start_time = time.time()
        try:
            _post(check_url, fields, timeout=1.5)
            print(f"{label} UNEXPECTED: got a response")
        except Exception:
            print(f"{label} hung ~{time.time() - start_time:.1f}s then client timed out (expected)")
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
        _, payload = _get(document.get(RESP_URL_FIELD), timeout=5)
        download_note = f"downloaded {len(payload)}B"
        if name == "corrupt":
            download_note += " (one byte flipped vs. signed original)"
        if name == "downgrade":
            download_note += " (server deliberately offered an older version)"
    except Exception as error:
        download_note = f"download FAILED: {type(error).__name__}"
    print(f"{label} update->{version}; {download_note}")
    if name in ("ok", "downgrade"):
        print(json.dumps(document, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Exercise every variant against the test update server.")
    parser.add_argument("--artifacts", default=None)
    parser.add_argument("--demo", action="store_true",
                        help="generate throwaway fake payloads/sigs so all variants run")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    temp_dir = None
    if args.demo:
        temp_dir = tempfile.mkdtemp(prefix="upd-demo-")
        server.CONFIG["artifacts_dir"] = temp_dir
        server.ARTIFACTS = _write_demo_artifacts(temp_dir)
    elif args.artifacts:
        server.CONFIG["artifacts_dir"] = args.artifacts

    update_server = server.UpdateServer(verbose=args.verbose)
    base_url = update_server.start()
    print(f"server: {base_url}")
    server.print_artifact_report()
    print(f"(client reports version {CLIENT_VERSION})\n")

    order = ["ok", "noupdate", "downgrade", "corrupt",
             "truncated", "badjson", "http500", "hang"]
    try:
        for name in order:
            _check_variant(base_url, name)
        _check_bad_os(base_url)
    finally:
        update_server.stop()
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
