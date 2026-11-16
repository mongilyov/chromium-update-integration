#!/usr/bin/env python3
r"""Server for integration tests of the Chromium-Gost auto-updater.

Supply --current-version and --newer-version for every run, plus --targets.
Use --older-version when testing downgrades. Versions come only from these arguments.
If --artifacts is omitted, a unique system temporary directory is used and
removed on clean shutdown. Explicit directories are always preserved.
Ctrl-C stops the server on all platforms; SIGTERM also works on Unix.
Shutdown can wait for an active socket/signing timeout. Force-killing the
process may leave its temporary directory behind.

Endpoints:
    GET /status
    GET or POST /<variant>/update
    GET /<variant>/download-update/<role>/<target>/<file>
    GET /download-<current|newer|older>/<target>
    PUT /upload-<current|newer|older>/<target>

/status returns HTTP 200 while the server is running. Its `ready` field is true
only when every selected target has a baseline and a signed newer package.
Signing here means that signature metadata is present; the browser still
performs the actual cryptographic verification. Optional older packages do not
block readiness for the normal update scenario.

Uploads are staged and signed before publication. Filenames and signatures are
published together in memory. Uploaded filenames are unique so an old update
response cannot download a replacement's bytes.

An explicit --artifacts directory can contain packages in current/, newer/ and
older/. At startup the server finds packages matching the supplied versions and
selected targets, then signs existing newer/older packages again. Signatures are
kept only in memory. Missing packages can be uploaded after startup; ambiguous
matches cause startup to fail. Manually placed packages use names such as
newer/chromium-gost-999.0.0.0-linux-amd64.deb. UUID-prefixed uploads from previous
runs are also recognized. Files for other versions/targets are ignored.
Do not manually edit packages while the server is serving them, or run
multiple server processes against the same artifact directory.

Examples:
    python integration_server.py --key-container CONTAINER \
        --current-version 156.0.8078.96 --newer-version 999.0.0.0 \
        --targets linux_deb
    python integration_server.py --key-container CONTAINER --artifacts DIR \
        --current-version 156.0.8078.96 --newer-version 999.0.0.0 \
        --targets linux_deb

An optional --run-id labels status/logs; it does not change routes or key storage.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import json
import locale
import math
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OS_VALUES = ("windows", "linux", "macos")
LINUX_INSTALLERS = ("deb", "rpm")
TARGETS = ("windows", "macos", "linux_deb", "linux_rpm")
TARGET_SUFFIX = {
    "windows": "windows-amd64-installer.exe",
    "macos": "macos-arm64.tgz",
    "linux_deb": "linux-amd64.deb",
    "linux_rpm": "linux-amd64.rpm",
}
ALL_ROLES = ("current", "newer", "older")
SIGNED_ROLES = ("newer", "older")
CPVERIFY_WINDOWS = r"C:\Program Files (x86)\Crypto Pro\CSP\cpverify.exe"
CPVERIFY_POSIX = "/opt/cprocsp/bin/amd64/cpverify"
DEFAULT_CPVERIFY = CPVERIFY_WINDOWS if os.name == "nt" else CPVERIFY_POSIX
GOST_PROVTYPE = "80"
CHUNK_SIZE = 64 * 1024
MAX_TELEMETRY_SIZE = 64 * 1024
SIGNATURE_RE = re.compile(
    r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{256}|[0-9A-Fa-f]{128})"
    r"[ \t]+(\d{2}\.\d{2}\.\d{4})(?!\d)"
)
VARIANTS = {
    "ok": {"role": "newer"},
    "downgrade": {"role": "older", "force_available": True},
    "corrupt": {"role": "newer", "corrupt_payload": True},
    "truncated": {"misbehave": "truncate"},
    "badjson": {"misbehave": "badjson"},
    "http500": {"misbehave": "http500"},
    "hang": {"misbehave": "hang"},
}


class ServerError(Exception):
    pass


class RequestError(Exception):
    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status = status
        self.headers = headers


def _version_key(version):
    if (not isinstance(version, str) or len(version) > 64
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", version) is None):
        raise ValueError(f"expected a four-part numeric version, got {version!r}")
    return tuple(int(part) for part in version.split("."))


def resolve_target(os_name, installer=None):
    if os_name not in OS_VALUES:
        raise ValueError(f"missing or invalid 'os'; expected one of {OS_VALUES}")
    if os_name != "linux":
        return os_name
    if installer not in LINUX_INSTALLERS:
        raise ValueError("missing or invalid 'installer' for linux; "
                         f"expected one of {LINUX_INSTALLERS}")
    return f"linux_{installer}"


def payload_filename(version, target):
    _version_key(version)
    if target not in TARGET_SUFFIX:
        raise ValueError(f"unknown target {target!r}; expected one of {TARGETS}")
    return f"chromium-gost-{version}-{TARGET_SUFFIX[target]}"


def _valid_signature(signature, timestamp):
    if re.fullmatch(r"(?:[0-9A-Fa-f]{128}|[0-9A-Fa-f]{256})", signature) is None:
        return False
    if re.fullmatch(r"\d{2}\.\d{2}\.\d{4}", timestamp) is None:
        return False
    try:
        datetime.strptime(timestamp, "%d.%m.%Y")
    except ValueError:
        return False
    return True


def _decode(raw):
    for encoding in (locale.getpreferredencoding(False), "utf-8", "cp866"):
        if encoding:
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                pass
    return raw.decode("utf-8", "replace")


def _parse_cpverify_output(output):
    for match in SIGNATURE_RE.finditer(output):
        signature, timestamp = match.groups()
        if _valid_signature(signature, timestamp):
            return signature.upper(), timestamp
    raise ServerError("cannot parse a signature and dd.mm.yyyy timestamp "
                      f"from cpverify output: {output.strip()!r}")


def _run_cpverify(path, container, executable, timeout):
    if not container:
        raise ServerError("no signing key container configured")
    if not os.path.isfile(executable):
        raise ServerError(f"cpverify not found at {executable} (override with --cpverify)")
    command = [executable, "-file_sign", path, "-cont", container,
               "-provtype", GOST_PROVTYPE]
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
    except OSError as error:
        raise ServerError(f"cannot run cpverify: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise ServerError(f"cpverify timed out after {timeout}s") from error
    stdout = _decode(result.stdout)
    if result.returncode != 0:
        detail = (_decode(result.stderr) or stdout).strip()
        raise ServerError(f"cpverify exited {result.returncode}: {detail}")
    return _parse_cpverify_output(stdout)


@dataclass(frozen=True)
class Artifact:
    version: str
    filename: str
    path: str
    signature: str
    timestamp: str


class ArtifactStore:
    """Versions and signatures live in memory; the directory contains packages only."""

    def __init__(self, artifacts_dir=None, *, current_version=None,
                 newer_version=None, older_version=None, targets=TARGETS):
        self.targets = tuple(dict.fromkeys(targets))
        if not self.targets or any(target not in TARGETS for target in self.targets):
            raise ServerError(f"targets must be a non-empty subset of {TARGETS}")
        if current_version is None or newer_version is None:
            raise ServerError("--current-version and --newer-version are required")
        self.versions = {"current": current_version, "newer": newer_version}
        if older_version is not None:
            self.versions["older"] = older_version
        for version in self.versions.values():
            _version_key(version)
        if _version_key(newer_version) <= _version_key(current_version):
            raise ServerError("newer version must be greater than current version")
        if older_version is not None and _version_key(older_version) >= _version_key(current_version):
            raise ServerError("older version must be less than current version")
        self.lock = threading.RLock()
        self._artifacts = {}
        self._pending_deletes = set()
        self._temporary_directory = None
        self.temporary = artifacts_dir is None
        if self.temporary:
            self._temporary_directory = tempfile.TemporaryDirectory(
                prefix="chromium-update-integration-")
            self.directory = self._temporary_directory.name
        else:
            self.directory = os.path.abspath(os.path.expanduser(artifacts_dir))
            os.makedirs(self.directory, exist_ok=True)

    def check_target(self, target):
        if target not in self.targets:
            raise ValueError(f"target {target!r} is not enabled; expected one of {self.targets}")

    def version(self, role):
        if role not in ALL_ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {ALL_ROLES}")
        if role not in self.versions:
            raise ServerError(f"{role} is disabled; supply --{role}-version")
        return self.versions[role]

    def load_existing(self, sign_artifact):
        """Before serving, find the requested versions and sign existing updates."""
        loaded = {}
        for role, version in self.versions.items():
            directory = os.path.join(self.directory, role)
            try:
                with os.scandir(directory) as entries:
                    filenames = [entry.name for entry in entries if entry.is_file()]
            except FileNotFoundError:
                continue
            for target in self.targets:
                # Accept manually placed packages and UUID-prefixed uploads from
                # previous runs. Never infer a version or select by modification time.
                canonical = payload_filename(version, target)
                pattern = re.compile(r"(?:[0-9a-f]{32}-)?" + re.escape(canonical))
                matches = [name for name in filenames if pattern.fullmatch(name)]
                if len(matches) > 1:
                    raise ServerError(f"multiple packages for {role}/{target} version {version} "
                                      f"in {directory}; keep exactly one matching package")
                if not matches:
                    continue
                filename = matches[0]
                path = os.path.join(directory, filename)
                artifact = Artifact(version, filename, path, "", "")
                self._require_payload(artifact)
                if role in SIGNED_ROLES:
                    signature, timestamp = sign_artifact(path)
                    artifact = Artifact(version, filename, path, signature, timestamp)
                    self._require_payload(artifact, signed=True)
                loaded[(role, target)] = artifact
        with self.lock:
            self._artifacts = loaded

    def _artifact(self, role, target):
        self.check_target(target)
        version = self.version(role)
        artifact = self._artifacts.get((role, target))
        if artifact is not None:
            return artifact
        filename = payload_filename(version, target)
        return Artifact(version, filename, os.path.join(self.directory, role, filename), "", "")

    @staticmethod
    def _require_payload(artifact, signed=False):
        if not os.path.isfile(artifact.path) or os.path.getsize(artifact.path) == 0:
            raise ServerError(f"payload missing or empty: {artifact.filename}")
        if signed and not _valid_signature(artifact.signature, artifact.timestamp):
            raise ServerError(f"signature not ready for {artifact.filename}")

    def update_response(self, variant_name, variant, target, client_version, base_url):
        self.check_target(target)
        with self.lock:
            artifact = self._artifact(variant["role"], target)
            available = (variant.get("force_available")
                         or _version_key(artifact.version) > _version_key(client_version))
            if not available:
                return {"update_available": False}
            self._require_payload(artifact, signed=True)
            url = (f"{base_url}/{variant_name}/download-update/{variant['role']}/"
                   f"{target}/{urllib.parse.quote(artifact.filename)}")
            return {"update_available": True, "version": artifact.version,
                    "download_url": url, "signature": artifact.signature,
                    "signature_timestamp": artifact.timestamp}

    @contextmanager
    def open_payload(self, role, target, filename=None, signed=False):
        with self.lock:
            artifact = self._artifact(role, target)
            if filename is not None and filename != artifact.filename:
                raise RequestError(404, "artifact is no longer current; check for updates again")
            self._require_payload(artifact, signed=signed)
            handle = open(artifact.path, "rb")
        try:
            yield artifact, handle
        finally:
            handle.close()
            with self.lock:
                self._remove_obsolete_files()

    @contextmanager
    def stage_upload(self, role, target):
        self.check_target(target)
        self.version(role)  # Reject disabled roles before receiving a large body.
        directory = os.path.join(self.directory, role)
        os.makedirs(directory, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".upload-",
                                         suffix=".part", delete=False) as handle:
            path = handle.name
        try:
            yield path
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def publish(self, role, target, staged_path, signature="", timestamp=""):
        self.check_target(target)
        version = self.version(role)
        if role in SIGNED_ROLES and not _valid_signature(signature, timestamp):
            raise ServerError("refusing to publish an unsigned or invalidly signed update")
        with self.lock:
            old_artifact = self._artifacts.get((role, target))
            filename = uuid.uuid4().hex + "-" + payload_filename(version, target)
            final_path = os.path.join(self.directory, role, filename)
            artifact = Artifact(version, filename, final_path, signature, timestamp)
            os.replace(staged_path, final_path)
            # Publish the bytes and signature together under the same lock used by readers.
            self._artifacts[(role, target)] = artifact
            if old_artifact is not None:
                self._pending_deletes.add(old_artifact.path)
            self._remove_obsolete_files()
            return filename

    def _remove_obsolete_files(self):
        for path in tuple(self._pending_deletes):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                # Windows keeps an active download's file open. Retry on close.
                continue
            self._pending_deletes.discard(path)

    def status(self, run_id=None):
        with self.lock:
            rows = {}
            for target in self.targets:
                row = {}
                for role in self.versions:
                    artifact = self._artifact(role, target)
                    uploaded = (os.path.isfile(artifact.path)
                                and os.path.getsize(artifact.path) > 0)
                    row[f"{role}_uploaded"] = uploaded
                    if role in SIGNED_ROLES:
                        row[f"{role}_signed"] = uploaded and _valid_signature(
                            artifact.signature, artifact.timestamp)
                row["ready"] = (row["current_uploaded"] and row["newer_uploaded"]
                                and row["newer_signed"])
                rows[target] = row
            return {"running": True, "run_id": run_id,
                    **{f"{role}_version": version for role, version in self.versions.items()},
                    "ready": all(row["ready"] for row in rows.values()), "targets": rows}

    def close(self):
        with self.lock:
            self._remove_obsolete_files()
            if self._temporary_directory is not None:
                self._temporary_directory.cleanup()
                self._temporary_directory = None


class _HTTPServer(ThreadingHTTPServer):
    # Join workers before deleting temporary artifacts.
    daemon_threads = False
    block_on_close = True

    def __init__(self, address, owner):
        self.owner = owner
        self.ssl_context = None
        self.stop_event = threading.Event()
        self._connections = set()
        self._connections_lock = threading.Lock()
        super().__init__(address, _Handler)

    def get_request(self):
        request, address = super().get_request()
        if self.ssl_context is not None:
            try:
                request = self.ssl_context.wrap_socket(
                    request, server_side=True, do_handshake_on_connect=False)
            except Exception:
                request.close()
                raise
        return request, address

    def process_request(self, request, client_address):
        with self._connections_lock:
            if self.stop_event.is_set():
                request.close()
                return
            self._connections.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            self.shutdown_request(request)
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            with self._connections_lock:
                self._connections.discard(request)

    def interrupt_connections(self):
        with self._connections_lock:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(self.server.owner.request_timeout)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()
        super().setup()

    def do_POST(self):
        self._route()

    def do_GET(self):
        self._route()

    def do_PUT(self):
        self._route()

    @property
    def owner(self):
        return self.server.owner

    def _request_base_url(self):
        host = self.headers.get("Host")
        return f"{self.owner.scheme}://{host}" if host else self.owner.base_url

    def _route(self):
        # No request can leave an unread body to be parsed as another request.
        self.close_connection = True
        self._response_started = False
        try:
            self._dispatch()
        except RequestError as error:
            self._error(error.status, str(error), error.headers)
        except ValueError as error:
            self._error(400, str(error))
        except ServerError as error:
            self._log_resolution("not-ready", str(error))
            self._error(503, f"artifact not ready: {error}")
        except TimeoutError:
            self._error(408, "request body timed out")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except OSError as error:
            if not self.server.stop_event.is_set():
                self._log_resolution("I/O failure", str(error))
                self._error(500, "server I/O failure; see server log")

    def _require_method(self, *methods):
        if self.command not in methods:
            raise RequestError(405, f"expected {' or '.join(methods)}",
                               {"Allow": ", ".join(methods)})

    def _dispatch(self):
        path = urllib.parse.urlsplit(self.path).path.strip("/")
        parts = path.split("/") if path else []
        if parts == ["status"]:
            self._require_method("GET")
            return self._json(self.owner.store.status(self.owner.run_id))
        if len(parts) == 2 and parts[0] in tuple(f"download-{r}" for r in ALL_ROLES):
            self._require_method("GET")
            return self._serve_file(parts[0][len("download-"):], parts[1])
        if len(parts) == 2 and parts[0] in tuple(f"upload-{r}" for r in ALL_ROLES):
            self._require_method("PUT")
            return self._serve_upload(parts[0][len("upload-"):], parts[1])
        variant_name = parts[0] if parts else ""
        variant = VARIANTS.get(variant_name)
        if variant is None:
            raise RequestError(404, "expected /status, /<variant>/update, "
                               "/<variant>/download-update/<role>/<target>/<file>, "
                               "or /download-<role>/<target>, /upload-<role>/<target>")
        if len(parts) == 2 and parts[1] == "update":
            self._require_method("GET", "POST")
            if variant.get("misbehave"):
                return self._misbehave(variant["misbehave"])
            telemetry = self._read_telemetry()
            target = resolve_target(telemetry.get("os"), telemetry.get("installer"))
            client_version = telemetry.get("version", "")
            _version_key(client_version)
            document = self.owner.store.update_response(
                variant_name, variant, target, client_version, self._request_base_url())
            self._log_resolution(variant_name, {"request": telemetry, "response": document})
            return self._json(document)
        if len(parts) in (4, 5) and parts[1] == "download-update":
            self._require_method("GET")
            if parts[2] != variant.get("role"):
                raise RequestError(404, "role does not match this scenario")
            filename = urllib.parse.unquote(parts[4]) if len(parts) == 5 else None
            return self._serve_file(parts[2], parts[3], filename,
                                    corrupt=variant.get("corrupt_payload", False),
                                    signed=True)
        raise RequestError(404, "unknown endpoint")

    def _serve_file(self, role, target, filename=None, corrupt=False, signed=False):
        with self.owner.store.open_payload(role, target, filename, signed) as (artifact, handle):
            size = os.fstat(handle.fileno()).st_size
            download_name = payload_filename(artifact.version, target)
            self._headers(200, "application/octet-stream", size,
                          {"Content-Disposition": f'attachment; filename="{download_name}"'})
            offset = 0
            while offset < size and not self.server.stop_event.is_set():
                chunk = handle.read(min(CHUNK_SIZE, size - offset))
                if not chunk:
                    break
                if corrupt and offset <= size // 2 < offset + len(chunk):
                    index = size // 2 - offset
                    chunk = chunk[:index] + bytes([chunk[index] ^ 0xFF]) + chunk[index + 1:]
                if not self._safe_write(chunk):
                    break
                offset += len(chunk)
            self._log_resolution(f"download-{role}/{target}", f"sent {offset}/{size} bytes")

    def _content_length(self, required=False):
        if self.headers.get("Transfer-Encoding"):
            raise RequestError(400, "Transfer-Encoding is unsupported; use Content-Length")
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            if required:
                raise RequestError(411, "Content-Length is required")
            return 0
        if len(lengths) != 1 or re.fullmatch(r"[0-9]+", lengths[0]) is None:
            raise RequestError(400, "invalid Content-Length")
        try:
            return int(lengths[0])
        except ValueError as error:
            raise RequestError(400, "invalid Content-Length") from error

    def _serve_upload(self, role, target):
        length = self._content_length(required=True)
        if length == 0:
            raise RequestError(400, "empty upload")
        with self.owner.store.stage_upload(role, target) as path:
            remaining = length
            with open(path, "wb") as handle:
                while remaining and not self.server.stop_event.is_set():
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    handle.write(chunk)
                    remaining -= len(chunk)
            if remaining:
                raise RequestError(400, f"upload truncated ({length - remaining}/{length} bytes)")
            signature = timestamp = ""
            if role in SIGNED_ROLES:
                signature, timestamp = self.owner.sign_artifact(path)
            if self.server.stop_event.is_set():
                raise RequestError(503, "server is stopping")
            filename = self.owner.store.publish(role, target, path, signature, timestamp)
        self._log_resolution(f"upload-{role}/{target}", f"stored {filename} ({length} bytes)")
        self._plain(200, f"stored {filename} ({length} bytes)"
                    + (f"; signed {timestamp}" if signature else ""))

    def _read_telemetry(self):
        query = urllib.parse.urlsplit(self.path).query
        fields = urllib.parse.parse_qs(query)
        length = self._content_length()
        if length > MAX_TELEMETRY_SIZE:
            raise RequestError(413, "update request is too large")
        if length:
            body = self.rfile.read(length)
            if len(body) != length:
                raise RequestError(400, "truncated update request")
            fields.update(urllib.parse.parse_qs(body.decode("utf-8", "replace")))
        return {key: value[0] for key, value in fields.items() if value}

    def _misbehave(self, misbehavior):
        if misbehavior == "http500":
            return self._plain(500, "internal server error (simulated)")
        if misbehavior == "badjson":
            return self._send(200, "application/json",
                              b'{"update_available": true, "version": "0.0.0.0", ')
        if misbehavior == "truncate":
            # Intentionally truncate the update-check response, not a package.
            sample = {"update_available": True, "version": "999.0.0.0",
                      "download_url": f"{self._request_base_url()}/unreachable",
                      "signature": "AAAA", "signature_timestamp": "01.01.2024"}
            full = json.dumps(sample).encode("utf-8")
            self._headers(200, "application/json", len(full))
            return self._safe_write(full[:len(full) // 2])
        if misbehavior == "hang":
            self.server.stop_event.wait(self.owner.hang_seconds)

    def _headers(self, status, content_type, length, extra_headers=None):
        self._response_started = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _send(self, status, content_type, body, extra_headers=None):
        self._headers(status, content_type, len(body), extra_headers)
        self._safe_write(body)

    def _json(self, document):
        self._send(200, "application/json", json.dumps(document, indent=2).encode("utf-8"))

    def _plain(self, status, message, extra_headers=None):
        self._send(status, "text/plain; charset=utf-8",
                   (message + "\n").encode("utf-8"), extra_headers)

    def _error(self, status, message, extra_headers=None):
        if self._response_started:
            return  # A failed download must end, not append another HTTP response.
        try:
            self._plain(status, message, extra_headers)
        except OSError:
            pass  # The client may have disconnected during upload or shutdown.

    def _safe_write(self, data):
        try:
            self.wfile.write(data)
            return True
        except OSError:
            self.close_connection = True
            return False

    def _log_resolution(self, name, outcome):
        label = f"server run={self.owner.run_id}" if self.owner.run_id else "server"
        sys.stderr.write(f"[{label}] {name} -> {outcome!r}\n")

    def log_message(self, fmt, *args):
        if not self.owner.quiet:
            self._log_resolution("http", fmt % args)


class UpdateServer:
    def __init__(self, host="127.0.0.1", port=0, quiet=False,
                 tls_cert=None, tls_key=None, *, artifacts_dir=None,
                 current_version=None, newer_version=None, older_version=None,
                 targets=TARGETS, key_container=None, cpverify_path=DEFAULT_CPVERIFY,
                 run_id=None, sign_timeout=120, request_timeout=30, hang_seconds=3600):
        if bool(tls_cert) != bool(tls_key):
            raise ValueError("--tls-cert and --tls-key must be supplied together")
        for name, value in (("sign_timeout", sign_timeout),
                            ("request_timeout", request_timeout),
                            ("hang_seconds", hang_seconds)):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        self.host, self.port, self.quiet = host, port, quiet
        self.tls_cert, self.tls_key = tls_cert, tls_key
        self.key_container, self.cpverify_path = key_container, cpverify_path
        self.run_id = run_id
        self.sign_timeout, self.request_timeout = sign_timeout, request_timeout
        self.hang_seconds = hang_seconds
        self.scheme = "https" if tls_cert else "http"
        self.base_url = None
        self._http_server = None
        self._thread = None
        self._stopped = False
        self._sign_lock = threading.Lock()
        self.store = ArtifactStore(artifacts_dir, current_version=current_version,
                                   newer_version=newer_version, older_version=older_version,
                                   targets=targets)

    def sign_artifact(self, path):
        # Serializing CSP access also bounds concurrent signer processes.
        with self._sign_lock:
            if self._stopped or (self._http_server is not None
                                 and self._http_server.stop_event.is_set()):
                raise ServerError("server is stopping")
            return _run_cpverify(path, self.key_container, self.cpverify_path,
                                 self.sign_timeout)

    def start(self):
        if self._http_server is not None or self._stopped:
            raise RuntimeError("create a new UpdateServer for each run")
        http_server = None
        try:
            http_server = _HTTPServer((self.host, self.port), self)
            if self.tls_cert:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.tls_cert, self.tls_key)
                http_server.ssl_context = context
            self.store.load_existing(self.sign_artifact)
            self.port = http_server.server_address[1]
            self.base_url = f"{self.scheme}://{self.host}:{self.port}"
            self._http_server = http_server
            self._thread = threading.Thread(target=http_server.serve_forever,
                                            kwargs={"poll_interval": 0.1}, daemon=True)
            self._thread.start()
        except Exception:
            if http_server:
                http_server.server_close()
            self.store.close()
            self._stopped = True
            raise
        return self.base_url

    def stop(self):
        if self._stopped:
            return
        if self._http_server is not None:
            self._http_server.stop_event.set()
            self._http_server.shutdown()
            self._http_server.interrupt_connections()
            self._http_server.server_close()
        if self._thread is not None:
            self._thread.join()
        self.store.close()
        self._stopped = True

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()


def _version_argument(value):
    try:
        _version_key(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    return value


def _positive_seconds(value):
    try:
        seconds = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a positive number of seconds") from error
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("expected a finite positive number of seconds")
    return seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--artifacts", metavar="DIR",
                        help="persistent artifact directory; default: a fresh temporary "
                             "directory removed on clean shutdown")
    parser.add_argument("--current-version", type=_version_argument, required=True)
    parser.add_argument("--newer-version", type=_version_argument, required=True)
    parser.add_argument("--older-version", type=_version_argument,
                        help="optional downgrade package version")
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=TARGETS,
                        help="targets to accept and include in readiness (default: all)")
    parser.add_argument("--run-id", help="optional label for status and logs")
    parser.add_argument("--key-container", "--key_container", dest="key_container", required=True,
                        help="server-local CryptoPro container for signing packages "
                             "(non-interactive, provtype 80)")
    parser.add_argument("--cpverify", default=DEFAULT_CPVERIFY,
                        help="path to cpverify (default: %(default)s)")
    parser.add_argument("--sign-timeout", type=_positive_seconds, default=120)
    parser.add_argument("--request-timeout", type=_positive_seconds, default=30,
                        help="socket I/O timeout in seconds (default: %(default)s)")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--quiet", action="store_true", help="suppress raw HTTP access logs")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("provide --tls-cert and --tls-key together")

    stop_requested = threading.Event()
    previous_handlers = {}

    def request_stop(signum, frame):
        stop_requested.set()

    server = None
    try:
        server = UpdateServer(host=args.host, port=args.port, quiet=args.quiet,
                              tls_cert=args.tls_cert, tls_key=args.tls_key,
                              artifacts_dir=args.artifacts, current_version=args.current_version,
                              newer_version=args.newer_version, older_version=args.older_version,
                              targets=args.targets, key_container=args.key_container,
                              cpverify_path=args.cpverify, run_id=args.run_id,
                              sign_timeout=args.sign_timeout, request_timeout=args.request_timeout)
        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            signum = getattr(signal, name, None)
            if signum is not None:
                previous_handlers[signum] = signal.signal(signum, request_stop)
        server.start()
        print(f"running: {os.path.abspath(__file__)}", flush=True)
        print(f"pid: {os.getpid()}", flush=True)
        print(f"run_id: {args.run_id or '(not set)'}", flush=True)
        print(server.base_url, flush=True)
        print(f"artifacts_dir = {server.store.directory}", flush=True)
        print("artifacts lifetime: " + ("temporary; removed on clean shutdown"
                                       if server.store.temporary else "persistent; preserved"), flush=True)
        print("targets: " + ", ".join(server.store.targets), flush=True)
        print("variants: " + ", ".join(VARIANTS), flush=True)
        print(json.dumps(server.store.status(args.run_id), indent=2), flush=True)
        print("Ready to accept uploads. Ctrl-C to stop.", flush=True)
        while not stop_requested.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    except (OSError, ServerError, ValueError) as error:
        print(f"SERVER FAILED: {error}", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.stop()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
