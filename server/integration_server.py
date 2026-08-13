#!/usr/bin/env python3
"""
integration_server.py

Server for integration tests of a Chromium-Gost auto-updater.
Serves pre-signed artifacts dropped on disk under artifacts/<role>/.
Version and signatures come from artifacts/<role>/config.yaml

Endpoints:
    /<variant>/update
    /<variant>/download-update/<role>/<os>/<installer>/<file>
    /download-<current|newer|older>/<os>/<installer>
    PUT /upload-<current|newer|older>/<os>/<installer>

Usage:
    python integration_server.py --key-container <container> [--host H] [--port P]
                                 [--artifacts DIR] [--cpverify PATH] [--quiet]
"""


from __future__ import annotations

import argparse
import json
import locale
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml


REQ_OS_FIELD = "os"
REQ_INSTALLER_FIELD = "installer"
REQ_VERSION_FIELD = "version"

RESP_AVAILABLE_FIELD = "update_available"
RESP_VERSION_FIELD = "version"
RESP_URL_FIELD = "download_url"
RESP_SIG_FIELD = "signature"
RESP_TS_FIELD = "signature_timestamp"

OS_VALUES = ("windows", "linux", "macos")
INSTALLER_VALUES = ("deb", "rpm", "exe", "tar")

OS_ARCH = {
    "windows": "windows-amd64",
    "linux":   "linux-amd64",
    "macos":   "macos-arm64",
}
INSTALLER_EXT = {
    "deb": ".deb",
    "rpm": ".rpm",
    "exe": "-installer.exe",
    "tar": ".tar.bz2",
}

TARGETS = (("windows", "exe"), ("linux", "deb"), ("linux", "rpm"), ("macos", "tar"))

ALL_ROLES = ("current", "newer", "older")
SIGNED_ROLES = ("newer", "older")

CONFIG_FILE = "config.yaml"
VERSION_KEY = "version"
VERIFICATION_KEY = "verification"
SIGNATURE_KEY = "signature"
TIMESTAMP_KEY = "timestamp"

CPVERIFY_WINDOWS = r"C:\Program Files (x86)\Crypto Pro\CSP\cpverify.exe"
CPVERIFY_POSIX = "/opt/cprocsp/bin/amd64/cpverify"
GOST_PROVTYPE = "80"
SIGNATURE_RE = re.compile(r"([0-9A-F]{64,})[ \t]+(\d{2}\.\d{2}\.\d{4})")

CONFIG = {
    "artifacts_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts"),
    "hang_seconds": 3600,
    "cpverify_path": CPVERIFY_WINDOWS if os.name == "nt" else CPVERIFY_POSIX,
    "key_container": None,
    "sign_timeout": 120,
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


class ConfigError(Exception):
    pass


def config_path(role):
    return os.path.join(CONFIG["artifacts_dir"], role, CONFIG_FILE)


def _scalar(value):
    """An absent value parses as None; everything is kept as a string."""
    if value is None:
        return ""
    return str(value).strip()


def load_role_config(role):
    if role not in ALL_ROLES:
        raise ConfigError(f"unknown role '{role}'; expected one of {ALL_ROLES}")
    path = config_path(role)
    if not os.path.isfile(path):
        raise ConfigError(f"missing config file: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = yaml.safe_load(handle) or {}
        except yaml.YAMLError as error:
            raise ConfigError(f"{path}: invalid YAML: {error}")
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")

    version = _scalar(data.get(VERSION_KEY))
    if not version:
        raise ConfigError(f"{path}: missing or empty '{VERSION_KEY}'")

    raw_verification = data.get(VERIFICATION_KEY)
    if raw_verification and not isinstance(raw_verification, dict):
        raise ConfigError(f"{path}: '{VERIFICATION_KEY}' must be a mapping")
    verification = {}
    for installer, meta in (raw_verification or {}).items():
        if installer not in INSTALLER_VALUES:
            raise ConfigError(f"{path}: unknown installer '{installer}' under "
                              f"'{VERIFICATION_KEY}'; expected one of {INSTALLER_VALUES}")
        if meta and not isinstance(meta, dict):
            raise ConfigError(f"{path}: '{VERIFICATION_KEY}.{installer}' must be a mapping")
        meta = meta or {}
        verification[installer] = {
            SIGNATURE_KEY: _scalar(meta.get(SIGNATURE_KEY)),
            TIMESTAMP_KEY: _scalar(meta.get(TIMESTAMP_KEY)),
        }
    return {VERSION_KEY: version, VERIFICATION_KEY: verification}


def save_role_config(role, config):
    """Rewrite artifacts/<role>/config.yaml with a stable key order."""
    verification = config.get(VERIFICATION_KEY, {})
    document = {
        VERSION_KEY: str(config[VERSION_KEY]),
        VERIFICATION_KEY: {
            installer: {
                SIGNATURE_KEY: str(verification.get(installer, {}).get(SIGNATURE_KEY, "")),
                TIMESTAMP_KEY: str(verification.get(installer, {}).get(TIMESTAMP_KEY, "")),
            }
            for installer in INSTALLER_VALUES
        },
    }
    path = config_path(role)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(document, handle, sort_keys=False, default_flow_style=False,
                       allow_unicode=True)
    os.replace(temp_path, path)                 # readers never see a half-written config
    return path


def record_signature(role, installer, signature, timestamp):
    """Merge one signature/timestamp pair into artifacts/<role>/config.yaml."""
    if installer not in INSTALLER_VALUES:
        raise ConfigError(f"unknown installer '{installer}'; expected one of {INSTALLER_VALUES}")
    config = load_role_config(role)
    config[VERIFICATION_KEY][installer] = {
        SIGNATURE_KEY: str(signature or ""),
        TIMESTAMP_KEY: str(timestamp or ""),
    }
    return save_role_config(role, config)


def _version_key(version):
    return tuple(int(part) for part in version.split("."))


def payload_filename(version, os_name, installer):
    if os_name not in OS_ARCH:
        raise ConfigError(f"unknown os '{os_name}'; expected one of {OS_VALUES}")
    if installer not in INSTALLER_EXT:
        raise ConfigError(f"unknown installer '{installer}'; expected one of {INSTALLER_VALUES}")
    return f"chromium-gost-{version}-{OS_ARCH[os_name]}{INSTALLER_EXT[installer]}"


def role_version(role):
    return load_role_config(role)[VERSION_KEY]


def payload_path(role, os_name, installer):
    version = role_version(role)
    filename = payload_filename(version, os_name, installer)
    path = os.path.join(CONFIG["artifacts_dir"], role, filename)
    if not os.path.isfile(path):
        raise ConfigError(f"payload missing on disk: {path}")
    return path, filename


def signature_meta(role, installer):
    if installer not in INSTALLER_VALUES:
        raise ConfigError(f"unknown installer '{installer}'; expected one of {INSTALLER_VALUES}")
    verification = load_role_config(role)[VERIFICATION_KEY]
    meta = verification.get(installer)
    if meta is None:
        raise ConfigError(f"no '{VERIFICATION_KEY}.{installer}' entry in {config_path(role)}")
    return meta


def _decode(raw):
    for encoding in (locale.getpreferredencoding(False), "utf-8", "cp866"):
        if not encoding:
            continue
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _parse_cpverify_output(output):
    """cpverify prints '<signature-hex> <dd.mm.yyyy>'; ignore any chatter around it."""
    match = SIGNATURE_RE.search(output)
    if match is None:
        raise ConfigError(f"cannot parse '<signature> <timestamp>' from cpverify output: "
                          f"{output.strip()!r}")
    return match.group(1), match.group(2)


def _run_cpverify(path, container):
    executable = CONFIG["cpverify_path"]
    if not os.path.isfile(executable):
        raise ConfigError(f"cpverify not found at {executable} (override with --cpverify)")
    command = [executable, "-file_sign", path, "-cont", container, "-provtype", GOST_PROVTYPE]
    try:
        result = subprocess.run(command, capture_output=True, timeout=CONFIG["sign_timeout"])
    except OSError as error:
        raise ConfigError(f"cannot run {executable}: {error}")
    except subprocess.TimeoutExpired:
        raise ConfigError(f"cpverify timed out after {CONFIG['sign_timeout']}s on {path}")
    stdout = _decode(result.stdout)
    if result.returncode != 0:
        detail = (_decode(result.stderr) or stdout).strip()
        raise ConfigError(f"cpverify exited {result.returncode} on {path}: {detail}")
    return stdout


def sign_artifact(role, os_name, installer, path=None):
    """Produce (signature, timestamp) for a payload, using cpverify -file_sign.

    `path` signs a staged file that is not at its final name yet (the upload handler
    passes the .part), and defaults to the published artifact. The key container comes
    from --key-container; no PIN is sent and provtype is always 80. Both halves of the
    result are cpverify's own -- the timestamp is not re-derived from the local clock.

    Pure: it signs and returns, it does not touch config.yaml. Persisting is the
    caller's job via record_signature() -- sign_and_record() below does both.
    """
    container = CONFIG["key_container"]
    if not container:
        raise ConfigError("no key container configured; start the server with --key-container")
    if path is None:
        path, _ = payload_path(role, os_name, installer)
    if not os.path.isfile(path):
        raise ConfigError(f"nothing to sign at {path}")
    return _parse_cpverify_output(_run_cpverify(path, container))


def sign_and_record(role, os_name, installer, path=None):
    """Sign a payload and write the result into its role's config.yaml."""
    signature, timestamp = sign_artifact(role, os_name, installer, path)
    record_signature(role, installer, signature, timestamp)
    return signature, timestamp


def artifact_report():
    rows = []
    for role in ALL_ROLES:
        try:
            version = role_version(role)
        except ConfigError:
            version = None
        for os_name, installer in TARGETS:
            if version is None:
                rows.append((role, os_name, installer, None, None, False))
                continue
            filename = payload_filename(version, os_name, installer)
            path = os.path.join(CONFIG["artifacts_dir"], role, filename)
            rows.append((role, os_name, installer, version, path, os.path.isfile(path)))
    return rows


def print_artifact_report(file=sys.stdout):
    print(f"artifacts_dir = {CONFIG['artifacts_dir']}", file=file)
    rows = artifact_report()
    width = max((len(f"{role}/{os_name}/{installer}") for role, os_name, installer, *_ in rows),
                default=8)
    problems = 0
    for role, os_name, installer, version, path, exists in rows:
        label = f"{role}/{os_name}/{installer}".ljust(width)
        if version is None:
            print(f"  [NO CONFIG ] {label}  (bad or missing {role}/{CONFIG_FILE})", file=file)
            problems += 1
            continue
        status = "OK        " if exists else "NO PAYLOAD"
        if not exists:
            problems += 1
        print(f"  [{status}] {label}  v{version}  {path}", file=file)
    if problems:
        print(f"  -> {problems} problem(s); those requests will 500 until fixed.", file=file)


def build_response(variant_name, variant, os_name, installer, client_version, base_url):
    role = variant["role"]
    offered_version = role_version(role)
    available = (variant.get("force_available")
                 or _version_key(offered_version) > _version_key(client_version))
    if not available:
        return {RESP_AVAILABLE_FIELD: False}
    _, filename = payload_path(role, os_name, installer)
    meta = signature_meta(role, installer)
    quoted = urllib.parse.quote(filename)
    return {
        RESP_AVAILABLE_FIELD: True,
        RESP_VERSION_FIELD: offered_version,
        RESP_URL_FIELD: f"{base_url}/{variant_name}/download-update/{role}/{os_name}/{installer}/{quoted}",
        RESP_SIG_FIELD: meta[SIGNATURE_KEY],
        RESP_TS_FIELD: meta[TIMESTAMP_KEY],
    }


def _corrupt(data):
    if not data:
        return b"\x00"
    corrupted = bytearray(data)
    corrupted[len(corrupted) // 2] ^= 0xFF
    return bytes(corrupted)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self._route()

    def do_GET(self):
        self._route()

    def do_PUT(self):
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
                                    "/<variant>/download-update/<role>/<os>/<installer>/<file>, "
                                    "or /download-<current|newer|older>/<os>/<installer>")

        if parts[0] in ("download-current", "download-newer", "download-older"):
            if len(parts) < 3:
                return self._plain(404, f"expected /{parts[0]}/<os>/<installer>")
            role = parts[0][len("download-"):]
            return self._serve_role(role, parts[1], parts[2])

        if parts[0] in ("upload-current", "upload-newer", "upload-older"):
            if len(parts) < 3:
                return self._plain(404, f"expected PUT /{parts[0]}/<os>/<installer>")
            role = parts[0][len("upload-"):]
            return self._serve_upload(role, parts[1], parts[2])

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
            if len(parts) < 5:
                return self._plain(404, "download path is "
                                        "/<variant>/download-update/<role>/<os>/<installer>/<file>")
            return self._serve_download(variant, parts[2], parts[3], parts[4])
        return self._plain(404, "expected /update or "
                                "/download-update/<role>/<os>/<installer>/<file>")

    def _serve_check(self, variant_name, variant):
        telemetry = self._read_telemetry()
        try:
            os_name = self._pick(telemetry, REQ_OS_FIELD, OS_VALUES)
            installer = self._pick(telemetry, REQ_INSTALLER_FIELD, INSTALLER_VALUES)
            client_version = self._client_version(telemetry)
            document = build_response(variant_name, variant, os_name, installer,
                                      client_version, self._request_base_url())
        except ConfigError as error:
            self._log_resolution(variant_name, telemetry, error)
            return self._plain(500, f"artifact/config not ready: {error}")
        except ValueError as error:
            self._log_resolution(variant_name, telemetry, error)
            return self._plain(400, str(error))
        self._log_resolution(variant_name, telemetry, document)
        self._send(200, "application/json", json.dumps(document, indent=2).encode("utf-8"))

    def _serve_download(self, variant, role, os_name, installer):
        try:
            path, filename = payload_path(role, os_name, installer)
        except ConfigError as error:
            self._log_resolution(f"download role={role}", {"os": os_name, "installer": installer}, error)
            return self._plain(500, f"artifact/config not ready: {error}")
        with open(path, "rb") as handle:
            data = handle.read()
        if variant.get("corrupt_payload"):
            data = _corrupt(data)
        self._log_resolution(f"download role={role}", {"os": os_name, "installer": installer},
                             f"served {filename} ({len(data)}B)")
        self._serve_bytes(data, filename)

    def _serve_role(self, role, os_name, installer):
        try:
            path, filename = payload_path(role, os_name, installer)
        except ConfigError as error:
            self._log_resolution(f"download-{role}", {"os": os_name, "installer": installer}, error)
            status = 400 if "unknown" in str(error) else 500
            return self._plain(status, str(error))
        with open(path, "rb") as handle:
            data = handle.read()
        self._log_resolution(f"download-{role}", {"os": os_name, "installer": installer},
                             f"served {filename} ({len(data)}B)")
        self._serve_bytes(data, filename)

    def _serve_bytes(self, data, filename):
        self._send(200, "application/octet-stream", data,
                   extra_headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    def _serve_upload(self, role, os_name, installer):
        if role not in ALL_ROLES:
            return self._plain(400, f"invalid role '{role}'; expected one of {ALL_ROLES}")
        if os_name not in OS_VALUES:
            return self._plain(400, f"invalid os '{os_name}'; expected one of {OS_VALUES}")
        if installer not in INSTALLER_VALUES:
            return self._plain(400, f"invalid installer '{installer}'; expected one of {INSTALLER_VALUES}")
        try:
            version = role_version(role)
            filename = payload_filename(version, os_name, installer)
        except ConfigError as error:
            self._log_resolution(f"upload-{role}", {"os": os_name, "installer": installer}, error)
            return self._plain(500, f"config not ready: {error}")

        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return self._plain(400, "empty upload (need Content-Length and a body)")

        dest_dir = os.path.join(CONFIG["artifacts_dir"], role)
        os.makedirs(dest_dir, exist_ok=True)
        final_path = os.path.join(dest_dir, filename)
        part_path = final_path + ".part"

        remaining = length
        with open(part_path, "wb") as handle:
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                handle.write(chunk)
                remaining -= len(chunk)
        if remaining != 0:
            os.remove(part_path)
            return self._plain(400, f"upload truncated ({length - remaining}/{length} bytes)")

        note = ""
        if role in SIGNED_ROLES:
            try:
                signature, timestamp = sign_and_record(role, os_name, installer, part_path)
            except ConfigError as error:
                os.remove(part_path)        # never publish an unsigned artifact
                self._log_resolution(f"upload-{role}", {"os": os_name, "installer": installer},
                                     f"rejected {filename}: signing failed: {error}")
                return self._plain(500, f"signing failed, {filename} not stored: {error}")
            note = f"; signed {timestamp} {signature[:16]}..."

        os.replace(part_path, final_path)   # only appears complete and signed, never half-written

        self._log_resolution(f"upload-{role}", {"os": os_name, "installer": installer},
                             f"stored {filename} ({length}B){note}")
        self._plain(200, f"stored {filename} ({length}B){note}\n")

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
                RESP_URL_FIELD: f"{self._request_base_url()}/ok/download-update/newer/linux/deb/installer",
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

    def _pick(self, telemetry, field, allowed):
        value = telemetry.get(field)
        if value not in allowed:
            raise ValueError(f"missing or invalid '{field}'; expected one of {allowed}")
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
    parser.add_argument("--key-container", "--key_container", dest="key_container",
                        required=True,
                        help="CryptoPro key container used to sign uploaded artifacts "
                             "(no PIN, provtype 80)")
    parser.add_argument("--cpverify", default=CONFIG["cpverify_path"],
                        help="path to cpverify (default: %(default)s)")
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the raw access-log line (per-request resolution "
                             "summary still prints)")
    args = parser.parse_args(argv)

    if args.artifacts:
        CONFIG["artifacts_dir"] = args.artifacts
    CONFIG["key_container"] = args.key_container
    CONFIG["cpverify_path"] = args.cpverify

    print(f"running: {os.path.abspath(__file__)}", flush=True)
    print(f"pid: {os.getpid()}", flush=True)

    server = UpdateServer(host=args.host, port=args.port, quiet=args.quiet,
                          tls_cert=args.tls_cert, tls_key=args.tls_key)
    base_url = server.start()
    print(base_url, flush=True)
    print("variants: " + ", ".join(sorted(VARIANTS)), flush=True)
    print("plus: /download-<current|newer|older>/<os>/<installer>  "
          "and  PUT /upload-<current|newer|older>/<os>/<installer>", flush=True)
    print(f"uploads to {', '.join(SIGNED_ROLES)} are signed on arrival with "
          f"{CONFIG['cpverify_path']} (container {CONFIG['key_container']}); "
          f"an upload that cannot be signed is rejected", flush=True)
    print_artifact_report()
    print("Ctrl-C to stop.", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
