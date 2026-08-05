#!/usr/bin/env python3
"""
test_update_server.py -- test update server for a Chromium-Gost auto-updater. Standard
library only. Serves pre-signed artifacts you drop on disk; signs nothing. The self-test
lives in selftest.py.

DISK LAYOUT (no paths hard-coded in this file -- only signatures)
    artifacts/
      <role>/
        version.txt                 the role's version, e.g. 150.0.7871.212
        <target>/<filename>         the installer, named by convention

    role     : current | newer | older
    target   : windows | linux_deb | linux_rpm | macos
    filename : chromium-gost-<version>-<suffix>, suffix by target:
                 windows   -> windows-amd64-installer.exe
                 linux_deb -> linux-amd64.deb
                 linux_rpm -> linux-amd64.rpm
                 macos     -> macos-arm64.tar.bz2
    Per release you edit version.txt, drop the (conventionally named) file, and -- for the
    check roles only -- paste the signature into ARTIFACTS below. Never a path here.

ENDPOINTS
    /<variant>/update                                   check (browser POSTs telemetry)
    /<variant>/download-update/<role>/<target>/<file>   payload for the check flow
    /download-current/<target>                          raw current installer (baseline
                                                        setup for integration tests)

VARIANTS (check flow)
    ok         newer version, valid            -> expect install
    downgrade  older version, valid (forced)   -> browser must reject
    corrupt    newer, one payload byte flipped -> signature check fails
    truncated / badjson / http500 / hang       misbehaving responses

    update_available is computed (offered > reported) except downgrade, which forces the
    offer. VERSION comes from version.txt; SIGNATURE + TIMESTAMP per check role/target
    live in ARTIFACTS below (can't be derived).

QUICK START
    python test_update_server.py                  # prints banner + preflight, serves
    python selftest.py --demo                      # exercise every variant with fakes
"""

# TODO: fill in ARTIFACTS signatures with your real signed files

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


REQ_OS_FIELD = "os"
REQ_VERSION_FIELD = "version"
REQ_ARCH_FIELD = "arch"
REQ_CHANNEL_FIELD = "channel"

RESP_AVAILABLE_FIELD = "update_available"
RESP_VERSION_FIELD = "version"
RESP_URL_FIELD = "download_url"
RESP_SIG_FIELD = "signature"
RESP_TS_FIELD = "signature_timestamp"

# target -> the trailing part of the standard filename
TARGET_SUFFIX = {
    "windows":   "windows-amd64-installer.exe",
    "linux_deb": "linux-amd64.deb",
    "linux_rpm": "linux-amd64.rpm",
    "macos":     "macos-arm64.tar.bz2",
}
OS_VALUES = tuple(TARGET_SUFFIX)

ALL_ROLES = ("current", "newer", "older")
VERSION_FILE = "version.txt"

CONFIG = {
    "artifacts_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts"),
    "hang_seconds": 3600,
}

# Signature + timestamp per check role/target. Versions and file paths are NOT here --
# versions come from artifacts/<role>/version.txt, filenames are derived by convention.
# `current` needs no signature (download-only), so it isn't listed.
ARTIFACTS = {
    "newer": {
        "windows": {
            "signature": "BC1DECA8C97114B1A8EC4A4E3C6F59CF290593F15D4D6EFC00F5ED83A57316A30B3AD96CE9FB50D0D1E80681A3922335DEE6B281B028E2533276DFAD2A649307",
            "timestamp": "05.08.2026",
        },
        "linux_deb": {
            "signature": "8B58311EC89DE57A5D4F8FB9D8DE9E8BFA6205B036F58AD46E884C40DD7263C1A2854B60E33A9F1ACC2B2331D10C89963C16A8B98F517D9459185153BBC09951",
            "timestamp": "03.08.2026",
        },
        "linux_rpm": {"signature": "", "timestamp": ""},
        "macos":     {"signature": "", "timestamp": ""},
    },
    "older": {
        "windows":   {"signature": "", "timestamp": ""},
        "linux_deb": {"signature": "", "timestamp": ""},
        "linux_rpm": {"signature": "", "timestamp": ""},
        "macos":     {"signature": "", "timestamp": ""},
    },
}

VARIANTS = {
    "ok":        {"role": "newer"},
    "downgrade": {"role": "older", "force_available": True},
    "corrupt":   {"role": "newer", "corrupt_payload": True},
    "truncated": {"misbehave": "truncate"},
    "badjson":   {"misbehave": "badjson"},
    "http500":   {"misbehave": "http500"},
    "hang":      {"misbehave": "hang"},
}

IS_WINDOWS = sys.platform.startswith("win")


class ConfigError(Exception):
    """Raised when a request needs artifact data that disk/ARTIFACTS doesn't provide."""


def _version_key(version):
    return tuple(int(part) for part in version.split("."))


def payload_filename(version, target):
    """chromium-gost-<version>-<suffix> for the given target."""
    return f"chromium-gost-{version}-{TARGET_SUFFIX[target]}"


def role_version(role):
    """The role's version, read from artifacts/<role>/version.txt."""
    path = os.path.join(CONFIG["artifacts_dir"], role, VERSION_FILE)
    if not os.path.isfile(path):
        raise ConfigError(f"missing version file: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        version = handle.read().strip()
    if not version:
        raise ConfigError(f"empty version file: {path}")
    return version


def payload_path(role, target):
    """Absolute path to the role/target installer, plus its filename. Validates both the
    target and that the file exists on disk."""
    if target not in TARGET_SUFFIX:
        raise ConfigError(f"unknown target '{target}'; expected one of {OS_VALUES}")
    version = role_version(role)
    filename = payload_filename(version, target)
    path = os.path.join(CONFIG["artifacts_dir"], role, target, filename)
    if not os.path.isfile(path):
        raise ConfigError(f"payload missing on disk: {path}")
    return path, filename


def signature_meta(role, target):
    role_meta = ARTIFACTS.get(role)
    if role_meta is None:
        raise ConfigError(f"no signature metadata for role '{role}'")
    meta = role_meta.get(target)
    if meta is None:
        raise ConfigError(f"no signature metadata for role '{role}', target '{target}'")
    return meta


def build_response(variant_name, variant, target, client_version, base_url):
    """Return the response document for a check. Edit THIS to match your real schema."""
    role = variant["role"]
    offered_version = role_version(role)
    available = (variant.get("force_available")
                 or _version_key(offered_version) > _version_key(client_version))
    if not available:
        return {RESP_AVAILABLE_FIELD: False}
    _, filename = payload_path(role, target)
    meta = signature_meta(role, target)
    quoted = urllib.parse.quote(filename)
    return {
        RESP_AVAILABLE_FIELD: True,
        RESP_VERSION_FIELD: offered_version,
        RESP_URL_FIELD: f"{base_url}/{variant_name}/download-update/{role}/{target}/{quoted}",
        RESP_SIG_FIELD: meta["signature"],
        RESP_TS_FIELD: meta["timestamp"],
    }


def _corrupt(data):
    if not data:
        return b"\x00"
    corrupted = bytearray(data)
    corrupted[len(corrupted) // 2] ^= 0xFF
    return bytes(corrupted)


def artifact_report():
    """(role, target, version, path, exists) for every role/target; version None if the
    role's version.txt is missing."""
    rows = []
    for role in ALL_ROLES:
        try:
            version = role_version(role)
        except ConfigError:
            version = None
        for target in OS_VALUES:
            if version is None:
                rows.append((role, target, None, None, False))
                continue
            filename = payload_filename(version, target)
            path = os.path.join(CONFIG["artifacts_dir"], role, target, filename)
            rows.append((role, target, version, path, os.path.isfile(path)))
    return rows


def print_artifact_report(file=sys.stdout):
    print(f"artifacts_dir = {CONFIG['artifacts_dir']}", file=file)
    rows = artifact_report()
    width = max((len(f"{role}/{target}") for role, target, *_ in rows), default=8)
    problems = 0
    for role, target, version, path, exists in rows:
        label = f"{role}/{target}".ljust(width)
        if version is None:
            print(f"  [NO VERSION] {label}  (missing {role}/{VERSION_FILE})", file=file)
            problems += 1
            continue
        status = "OK     " if exists else "MISSING"
        if not exists:
            problems += 1
        print(f"  [{status}] {label}  v{version}  {path}", file=file)
    if problems:
        print(f"  -> {problems} problem(s); those role/target requests will 500 until fixed.",
              file=file)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self._route()

    def do_GET(self):
        self._route()

    def _request_base_url(self):
        host_header = self.headers.get("Host")
        scheme = getattr(self.server, "scheme", "http")
        return f"{scheme}://{host_header}" if host_header else self.server.base_url

    def _route(self):
        path = urllib.parse.urlsplit(self.path).path.strip("/")
        parts = path.split("/") if path else []
        if not parts or not parts[0]:
            return self._plain(404, "expected /<variant>/update, "
                                    "/<variant>/download-update/<role>/<target>/<file>, "
                                    "or /download-current/<target>")

        if parts[0] == "download-current":
            if len(parts) < 2:
                return self._plain(404, "expected /download-current/<target>")
            return self._serve_current(parts[1])

        variant_name = parts[0]
        variant = VARIANTS.get(variant_name)
        if variant is None:
            return self._plain(404, f"unknown variant '{variant_name}'; "
                                    f"known: {', '.join(sorted(VARIANTS))}")
        endpoint = parts[1] if len(parts) > 1 else ""
        if endpoint == "update":
            misbehavior = variant.get("misbehave")
            if misbehavior:
                return self._misbehave(misbehavior)
            return self._serve_check(variant_name, variant)
        if endpoint == "download-update":
            if len(parts) < 4:
                return self._plain(404, "download path is "
                                        "/<variant>/download-update/<role>/<target>/<file>")
            return self._serve_download(variant, parts[2], parts[3])
        return self._plain(404, "expected /update or /download-update/<role>/<target>/<file>")

    def _serve_check(self, variant_name, variant):
        telemetry = self._read_telemetry()
        try:
            target = self._target(telemetry)
            client_version = self._client_version(telemetry)
            document = build_response(variant_name, variant, target, client_version,
                                      self._request_base_url())
        except ConfigError as error:
            self._log_resolution(variant_name, telemetry, error)
            return self._plain(500, f"artifact/config not ready: {error}")
        except ValueError as error:
            self._log_resolution(variant_name, telemetry, error)
            return self._plain(400, str(error))
        self._log_resolution(variant_name, telemetry, document)
        self._send(200, "application/json", json.dumps(document, indent=2).encode("utf-8"))

    def _serve_download(self, variant, role, target):
        try:
            path, filename = payload_path(role, target)
        except ConfigError as error:
            self._log_resolution(f"download role={role}", {"target": target}, error)
            return self._plain(500, f"artifact/config not ready: {error}")
        with open(path, "rb") as handle:
            data = handle.read()
        if variant.get("corrupt_payload"):
            data = _corrupt(data)
        self._log_resolution(f"download role={role}", {"target": target},
                             f"served {filename} ({len(data)}B)")
        self._serve_bytes(data, filename)

    def _serve_current(self, target):
        try:
            path, filename = payload_path("current", target)
        except ConfigError as error:
            self._log_resolution("download-current", {"target": target}, error)
            status = 400 if "unknown target" in str(error) else 500
            return self._plain(status, str(error))
        with open(path, "rb") as handle:
            data = handle.read()
        self._log_resolution("download-current", {"target": target},
                             f"served {filename} ({len(data)}B)")
        self._serve_bytes(data, filename)

    def _serve_bytes(self, data, filename):
        self._send(200, "application/octet-stream", data,
                   extra_headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    def _log_resolution(self, name, telemetry, outcome):
        sys.stderr.write(f"[server] {name} request={telemetry!r} -> {outcome!r}\n")

    def _misbehave(self, misbehavior):
        if misbehavior == "http500":
            return self._plain(500, "internal server error (simulated)")
        if misbehavior == "badjson":
            body = ('{"%s": true, "%s": "0.0.0.0", '
                    % (RESP_AVAILABLE_FIELD, RESP_VERSION_FIELD)).encode("utf-8")
            return self._send(200, "application/json", body)
        if misbehavior == "truncate":
            sample = {
                RESP_AVAILABLE_FIELD: True,
                RESP_VERSION_FIELD: "999.0.0.0",
                RESP_URL_FIELD: f"{self._request_base_url()}/ok/download-update/newer/{OS_VALUES[0]}/installer",
                RESP_SIG_FIELD: "AAAA",
                RESP_TS_FIELD: "01.01.2024",
            }
            full = json.dumps(sample, indent=2).encode("utf-8")
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(full)))
            self.end_headers()
            self._safe_write(full[: len(full) // 2])
            return
        if misbehavior == "hang":
            deadline = time.time() + CONFIG["hang_seconds"]
            stop_event = getattr(self.server, "stop_event", None)
            while time.time() < deadline:
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(0.2)
            self.close_connection = True
            return
        return self._plain(500, f"unknown misbehavior '{misbehavior}'")

    def _read_telemetry(self):
        fields = {}
        query = urllib.parse.urlsplit(self.path).query
        if query:
            fields.update(urllib.parse.parse_qs(query))
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            body = self.rfile.read(length)
            fields.update(urllib.parse.parse_qs(body.decode("utf-8", "replace")))
        return {key: value[0] for key, value in fields.items() if value}

    def _target(self, telemetry):
        value = telemetry.get(REQ_OS_FIELD)
        if value not in OS_VALUES:
            raise ValueError(f"missing or invalid '{REQ_OS_FIELD}'; expected one of {OS_VALUES}")
        return value

    def _client_version(self, telemetry):
        value = telemetry.get(REQ_VERSION_FIELD)
        if not value:
            raise ValueError(f"missing '{REQ_VERSION_FIELD}'")
        try:
            _version_key(value)
        except ValueError:
            raise ValueError(f"invalid '{REQ_VERSION_FIELD}': {value!r}")
        return value

    def _send(self, status, content_type, body, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self._safe_write(body)

    def _plain(self, status, message):
        self._send(status, "text/plain; charset=utf-8", (message + "\n").encode("utf-8"))

    def _safe_write(self, data):
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt, *args):
        if not getattr(self.server, "quiet", False):
            sys.stderr.write("[server] " + (fmt % args) + "\n")


def maybe_wrap_tls(sock, certfile, keyfile):
    if not certfile or not keyfile:
        return sock
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context.wrap_socket(sock, server_side=True)


class UpdateServer:
    """Loopback, ephemeral-port test update server.

        server = UpdateServer()
        base_url = server.start()
        server.stop()
    """

    def __init__(self, host="127.0.0.1", port=0, quiet=False,
                 tls_cert=None, tls_key=None):
        self.host = host
        self.port = port
        self.quiet = quiet
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.base_url = None
        self._http_server = None
        self._thread = None

    def start(self):
        http_server = ThreadingHTTPServer((self.host, self.port), _Handler)
        http_server.daemon_threads = True
        if self.tls_cert or self.tls_key:
            http_server.socket = maybe_wrap_tls(http_server.socket, self.tls_cert, self.tls_key)
        self.port = http_server.server_address[1]
        scheme = "https" if (self.tls_cert or self.tls_key) else "http"
        self.base_url = f"{scheme}://{self.host}:{self.port}"
        http_server.base_url = self.base_url
        http_server.scheme = scheme
        http_server.quiet = self.quiet
        http_server.stop_event = threading.Event()
        self._http_server = http_server
        self._thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self):
        if self._http_server is not None:
            self._http_server.stop_event.set()
            self._http_server.shutdown()
            self._http_server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Test update server for a Chromium-Gost updater.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--artifacts", default=None)
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the raw access-log line (per-request resolution "
                             "summary still prints)")
    args = parser.parse_args(argv)

    if args.artifacts:
        CONFIG["artifacts_dir"] = args.artifacts

    print(f"running: {os.path.abspath(__file__)}", flush=True)
    print(f"pid: {os.getpid()}", flush=True)

    server = UpdateServer(host=args.host, port=args.port, quiet=args.quiet,
                          tls_cert=args.tls_cert, tls_key=args.tls_key)
    base_url = server.start()
    print(base_url, flush=True)
    print("variants: " + ", ".join(sorted(VARIANTS)), flush=True)
    print("plus: /download-current/<target>", flush=True)
    print_artifact_report()
    print("Ctrl-C to stop.", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
