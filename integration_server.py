#!/usr/bin/env python3
"""
test_update_server.py -- a payload-agnostic test update server for a Chromium-fork
auto-updater. Standard library only. Serves pre-signed artifacts you upload; it does
NOT sign anything. The self-test lives in selftest.py.

WHO RUNS THIS
    A "manage everything" driver script imports UpdateServer, calls .start() to get the
    loopback URL, points the browser-under-test at it, then calls .stop(). You can also
    run it standalone (python test_update_server.py) to serve until Ctrl-C.

THE ONE PLACE THAT DEFINES YOUR WIRE FORMAT
    build_response() is the single authority for the response document. Field NAMES are
    the RESP_* constants. The signature and timestamp are strings you store in ARTIFACTS;
    the server echoes them verbatim.

AVAILABILITY IS COMPUTED (like production)
    The server reads the version the browser reports (REQ_VERSION_FIELD) and returns
    update_available only if the offered version is strictly newer. The one exception is
    the `downgrade` variant: it sets force_available so the server offers an OLDER version
    anyway (a downgrade offer is byte-identical to a normal one) -- that's what lets you
    test the browser's downgrade rejection, which a healthy server would never trigger.

RESPONSE SCHEMA (defaults -- rename freely via the RESP_* constants)
    update-available:
        {
          "update_available": true,
          "version": "999.0.0.0",
          "download_url": "http://127.0.0.1:PORT/ok/download-update/newer/windows/mini_installer_126.exe",
          "signature": "<the signature string stored in ARTIFACTS>",
          "signature_timestamp": "23.11.2023"
        }
    no-update:
        { "update_available": false }

REQUEST (telemetry)
    Browser POSTs (or GETs, with query params) to /<variant>/update. The OS value must be
    exactly one of OS_VALUES and the version must be a dotted number; anything else is a
    400. Query-string params not part of the schema are ignored.

VARIANTS (chosen by URL path prefix)
    ok            newer version, valid                    -> expect install
    noupdate      offers the reported version             -> expect no-op
    downgrade     OLDER version, valid (forced offer)     -> browser must reject
    corrupt       newer, one payload byte flipped after
                  signing (see note below)                -> signature check fails
    truncated     check response body cut short           -> HTTP robustness
    badjson       malformed JSON                          -> parse robustness
    http500       HTTP 500                                -> error handling
    hang          accept, never respond                   -> client hard-timeout

    The leading path segment IS the selector: point the browser at
    http://HOST:PORT/<variant>; it appends /update and follows the returned download
    link, all under the same /<variant> prefix. The downgrade test is just /downgrade.

QUICK START
    python test_update_server.py                  # prints banner + preflight, serves
    python selftest.py --demo                      # exercise every variant with fakes
"""

# TODO: fill in ARTIFACTS with your real signed files
# TODO: sign browser binaries

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

OS_VALUES = ("windows", "macOS", "linux")

CONFIG = {
    "artifacts_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts"),
    "hang_seconds": 3600,
}

ARTIFACTS = {
    "current": {
        "version": "125.0.6422.60",
        "platforms": {
            OS_VALUES[0]: {
                "file": "current/mini_installer_125.exe",
                "signature": "",
                "timestamp": "",
            },
            OS_VALUES[1]: {
                "file": "current/Browser-125.zip",
                "signature": "",
                "timestamp": "",
            },
            OS_VALUES[2]: {
                "file": "current/browser_125.deb",
                "signature": "",
                "timestamp": "",
            },
        },
    },
    "newer": {
        "version": "999.0.0.0",
        "platforms": {
            OS_VALUES[0]: {
                "file": "newer/mini_installer_126.exe",
                "signature": "",
                "timestamp": "",
            },
            OS_VALUES[1]: {
                "file": "newer/Browser-126.zip",
                "signature": "",
                "timestamp": "",
            },
            OS_VALUES[2]: {
                "file": "newer/chromium-gost-stable_999.0.0.0-1_amd64.deb",
                "signature": "8B58311EC89DE57A5D4F8FB9D8DE9E8BFA6205B036F58AD46E884C40DD7263C1A2854B60E33A9F1ACC2B2331D10C89963C16A8B98F517D9459185153BBC09951",
                "timestamp": "03.08.2026",
            },
        },
    },
    "older": {
        "version": "124.0.6367.91",
        "platforms": {
            OS_VALUES[0]: {
                "file": "older/mini_installer_124.exe",
                "signature": "",
                "timestamp": "",
            },
            OS_VALUES[1]: {
                "file": "older/Browser-124.zip",
                "signature": "",
                "timestamp": "",
            },
            OS_VALUES[2]: {
                "file": "older/browser_124.deb",
                "signature": "",
                "timestamp": "",
            },
        },
    },
}

VARIANTS = {
    "ok":           {"role": "newer"},
    "noupdate":     {"role": "current"},
    "downgrade":    {"role": "older", "force_available": True},
    # corrupts payload bytes, not the signature -- see NOTE in the module docstring
    "corrupt":      {"role": "newer", "corrupt_payload": True},
    "truncated":    {"misbehave": "truncate"},
    "badjson":      {"misbehave": "badjson"},
    "http500":      {"misbehave": "http500"},
    "hang":         {"misbehave": "hang"},
}


class ConfigError(Exception):
    """Raised when a variant needs an artifact that ARTIFACTS/disk doesn't provide."""


def _version_key(version):
    return tuple(int(part) for part in version.split("."))


def _platform(role, os_key):
    artifact = ARTIFACTS.get(role)
    if not artifact:
        raise ConfigError(f"no ARTIFACTS entry for role '{role}'")
    platform = artifact.get("platforms", {}).get(os_key)
    if not platform:
        raise ConfigError(f"no entry for role '{role}', os '{os_key}'")
    return artifact, platform


def _artifact_path(role, os_key):
    _, platform = _platform(role, os_key)
    relative_path = platform.get("file")
    if not relative_path:
        raise ConfigError(f"no file for role '{role}', os '{os_key}'")
    path = (relative_path if os.path.isabs(relative_path)
            else os.path.join(CONFIG["artifacts_dir"], relative_path))
    if not os.path.isfile(path):
        raise ConfigError(f"artifact file missing on disk: {path}")
    return path


def _filename(role, os_key):
    """The real filename (e.g. 'mini_installer_126.exe'), used both as the last URL
    segment and in the Content-Disposition header, so a saved download keeps its
    original name/extension instead of whatever the URL would otherwise end in."""
    _, platform = _platform(role, os_key)
    return os.path.basename(platform.get("file", "") or f"{role}-{os_key}")


def build_response(variant_name, variant, os_key, client_version, base_url):
    """Return the response document for a check. Edit THIS to match your real schema."""
    role = variant["role"]
    artifact, platform = _platform(role, os_key)
    offered_version = artifact["version"]
    available = (variant.get("force_available")
                 or _version_key(offered_version) > _version_key(client_version))
    if not available:
        return {RESP_AVAILABLE_FIELD: False}
    _artifact_path(role, os_key)
    filename = urllib.parse.quote(_filename(role, os_key))
    return {
        RESP_AVAILABLE_FIELD: True,
        RESP_VERSION_FIELD: offered_version,
        RESP_URL_FIELD: f"{base_url}/{variant_name}/download-update/{role}/{os_key}/{filename}",
        RESP_SIG_FIELD: platform["signature"],
        RESP_TS_FIELD: platform["timestamp"],
    }


def _corrupt(data):
    if not data:
        return b"\x00"
    corrupted = bytearray(data)
    corrupted[len(corrupted) // 2] ^= 0xFF
    return bytes(corrupted)


def artifact_report():
    """Return a list of (role, os_key, path, exists) for every configured artifact."""
    rows = []
    for role, artifact in ARTIFACTS.items():
        for os_key in OS_VALUES:
            platform = artifact.get("platforms", {}).get(os_key)
            if not platform:
                rows.append((role, os_key, None, False))
                continue
            relative_path = platform.get("file", "")
            path = (relative_path if os.path.isabs(relative_path)
                    else os.path.join(CONFIG["artifacts_dir"], relative_path))
            rows.append((role, os_key, path, os.path.isfile(path)))
    return rows


def print_artifact_report(file=sys.stdout):
    rows = artifact_report()
    width = max((len(f"{role}/{os_key}") for role, os_key, _, _ in rows), default=8)
    print(f"artifacts_dir = {CONFIG['artifacts_dir']}", file=file)
    for role, os_key, path, exists in rows:
        label = f"{role}/{os_key}".ljust(width)
        status = "OK     " if exists else "MISSING"
        print(f"  [{status}] {label}  {path}", file=file)
    missing = sum(1 for *_, exists in rows if not exists)
    if missing:
        print(f"  -> {missing} of {len(rows)} artifact file(s) missing. Requests for "
              f"those role/OS combinations will 500 until the files exist.", file=file)


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
            return self._plain(404, "expected /<variant>/update or "
                                    "/<variant>/download-update/<role>/<os>")
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
                return self._plain(404, "download path is /<variant>/download-update/<role>/<os>"
                                        "[/<filename>]")
            # parts[4:], if present, is just the real filename for URL/save-as purposes;
            # the actual file served is always resolved from role + os_key alone.
            return self._serve_download(variant, parts[2], parts[3])
        return self._plain(404, "expected /update or /download-update/<role>/<os>[/<filename>]")

    def _serve_check(self, variant_name, variant):
        telemetry = self._read_telemetry()
        try:
            os_key = self._os_key(telemetry)
            client_version = self._client_version(telemetry)
            document = build_response(variant_name, variant, os_key, client_version,
                                      self._request_base_url())
        except ConfigError as error:
            self._log_resolution(variant_name, telemetry, error)
            return self._plain(500, f"artifact/config not ready: {error}")
        except ValueError as error:
            self._log_resolution(variant_name, telemetry, error)
            return self._plain(400, str(error))
        self._log_resolution(variant_name, telemetry, document)
        self._send(200, "application/json", json.dumps(document, indent=2).encode("utf-8"))

    def _serve_download(self, variant, role, os_key):
        try:
            path = _artifact_path(role, os_key)
        except ConfigError as error:
            self._log_resolution(f"download role={role}", {"os": os_key}, error)
            return self._plain(500, f"artifact/config not ready: {error}")
        with open(path, "rb") as file_handle:
            data = file_handle.read()
        if variant.get("corrupt_payload"):
            data = _corrupt(data)
        filename = _filename(role, os_key)
        self._log_resolution(f"download role={role}", {"os": os_key}, f"served {filename} ({len(data)}B)")
        self._send(200, "application/octet-stream", data,
                   extra_headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    def _log_resolution(self, variant_name, telemetry, outcome):
        # Unconditional -- not gated by --quiet or --verbose. Every check and download
        # request prints exactly what the server parsed and what it decided, success or
        # failure, so nothing happens silently. --quiet suppresses only the framework's
        # separate raw access-log line (see log_message below).
        sys.stderr.write(f"[server] {variant_name} request={telemetry!r} -> {outcome!r}\n")

    def _misbehave(self, misbehavior):
        if misbehavior == "http500":
            return self._plain(500, "internal server error (simulated)")
        if misbehavior == "badjson":
            body = ('{"%s": true, "%s": "0.0.0.0", '
                    % (RESP_AVAILABLE_FIELD, RESP_VERSION_FIELD)).encode("utf-8")
            return self._send(200, "application/json", body)
        if misbehavior == "truncate":
            newer_version = ARTIFACTS["newer"]["version"]
            filename = urllib.parse.quote(_filename("newer", OS_VALUES[0]))
            sample = {
                RESP_AVAILABLE_FIELD: True,
                RESP_VERSION_FIELD: newer_version,
                RESP_URL_FIELD: f"{self._request_base_url()}/ok/download-update/newer/{OS_VALUES[0]}/{filename}",
                RESP_SIG_FIELD: "AAAA",
                RESP_TS_FIELD: "23.11.2023",
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

    def _os_key(self, telemetry):
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
        # On by default -- this is the standard "METHOD path HTTP/1.1" status line.
        # Pass --quiet to suppress it (the per-request _log_resolution line above stays
        # on regardless, since that one carries the actually useful detail).
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

    def __init__(self, host="127.0.0.1", port=0, verbose=False, quiet=False,
                 tls_cert=None, tls_key=None):
        self.host = host
        self.port = port
        self.verbose = verbose
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
        http_server.verbose = self.verbose
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
    parser = argparse.ArgumentParser(description="Test update server for a Chromium-fork updater.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--artifacts", default=None)
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    parser.add_argument("--verbose", action="store_true",
                        help="also print the raw 'METHOD path' access-log line "
                             "(on by default; this flag is now a no-op, kept for "
                             "backward compatibility)")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the raw access-log line (the per-request "
                             "resolution summary still prints regardless)")
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
