"""Server regression tests. No browser, CryptoPro installation or private key needed.

Run: python -m unittest discover -s server -p 'test_*.py' -v
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

import integration_server as server


CURRENT = "156.0.8078.96"
NEWER = "999.0.0.0"
OLDER = "100.0.0.0"
DATE = "16.11.2026"


def signature(data):
    return hashlib.sha512(data).hexdigest().upper()


def fake_sign(path):
    return signature(Path(path).read_bytes()), DATE


class ServerTests(unittest.TestCase):
    def setUp(self):
        logging = patch.object(server._Handler, "_log_resolution")
        logging.start()
        self.addCleanup(logging.stop)

    def make_server(self, **kwargs):
        signer = kwargs.pop("signer", fake_sign)
        options = dict(current_version=CURRENT, newer_version=NEWER,
                       targets=("linux_deb",), key_container="test-container", quiet=True)
        options.update(kwargs)
        instance = server.UpdateServer(**options)
        signing = patch.object(instance, "sign_artifact", side_effect=signer)
        instance.test_signer = signing.start()
        self.addCleanup(signing.stop)
        self.addCleanup(instance.stop)
        instance.start()
        return instance

    def request(self, instance, path, method="GET", body=None, headers=None):
        if path.startswith("http"):
            path = urlsplit(path).path
        connection = http.client.HTTPConnection("127.0.0.1", instance.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def upload(self, instance, role, data=b"package", target="linux_deb"):
        status, _, body = self.request(instance, f"/upload-{role}/{target}", "PUT", data)
        self.assertEqual(status, 200, body)

    def status(self, instance):
        status, _, body = self.request(instance, "/status")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def update(self, instance, variant="ok", target="linux_deb", version=CURRENT,
               method="GET"):
        params = {"os": target.split("_")[0], "version": version}
        if target.startswith("linux_"):
            params["installer"] = target.split("_")[1]
        query = urlencode(params)
        path = f"/{variant}/update"
        if method == "GET":
            path += "?" + query
            query = None
        status, _, body = self.request(instance, path, method, query)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def assert_no_staging(self, instance):
        paths = list(Path(instance.store.directory).rglob(".upload-*.part"))
        self.assertEqual(paths, [])

    def wait_until(self, predicate):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("server did not reach the expected state")

    def raw_request(self, instance, data):
        with socket.create_connection(("127.0.0.1", instance.port), timeout=5) as sock:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(sock)
            response.begin()
            return response.status, response.read()

    def test_temporary_run_initialization_and_cleanup(self):
        instance = self.make_server(run_id="pipeline-123")
        directory = Path(instance.store.directory)
        self.assertTrue(directory.is_dir())
        status = self.status(instance)
        self.assertEqual(status["run_id"], "pipeline-123")
        self.assertEqual(status["current_version"], CURRENT)
        self.assertEqual(status["newer_version"], NEWER)
        self.assertFalse(status["ready"])
        self.assertEqual(list(status["targets"]), ["linux_deb"])
        self.assertNotIn("errors", status)
        self.assertNotIn("older_version", status)
        self.assertEqual(list(directory.rglob("*")), [])
        instance.stop()
        instance.stop()
        self.assertFalse(directory.exists())

    def test_upload_check_and_stream_download(self):
        instance = self.make_server()
        data = bytes(range(256)) * 1025
        self.upload(instance, "current", b"baseline")
        instance.test_signer.assert_not_called()
        self.assertFalse(self.status(instance)["ready"])
        self.upload(instance, "newer", data)
        self.assertTrue(self.status(instance)["ready"])
        document = self.update(instance, method="POST")
        self.assertEqual(document["version"], NEWER)
        self.assertEqual(document["signature"], signature(data))
        self.assertEqual(document["signature_timestamp"], DATE)
        status, headers, body = self.request(instance, document["download_url"])
        self.assertEqual(status, 200)
        self.assertEqual(body, data)
        self.assertEqual(int(headers["Content-Length"]), len(data))
        self.assertIn(server.payload_filename(NEWER, "linux_deb"),
                      headers["Content-Disposition"])
        self.assertEqual(self.request(instance, "/download-current/linux_deb")[2], b"baseline")
        self.assertEqual(self.request(instance, "/download-newer/linux_deb")[2], data)
        self.assertEqual(self.update(instance, version=NEWER), {"update_available": False})
        self.assert_no_staging(instance)

    def test_unsigned_or_missing_update_is_not_advertised(self):
        instance = self.make_server()
        query = f"/ok/update?os=linux&installer=deb&version={CURRENT}"
        self.assertEqual(self.request(instance, query)[0], 503)
        legacy_path = Path(instance.store.directory, "newer",
                           server.payload_filename(NEWER, "linux_deb"))
        legacy_path.parent.mkdir()
        legacy_path.write_bytes(b"unsigned")
        self.assertEqual(self.request(instance, query)[0], 503)
        self.assertFalse(self.status(instance)["targets"]["linux_deb"]["newer_signed"])

    def test_all_platforms_and_simultaneous_uploads(self):
        instance = self.make_server(targets=server.TARGETS)
        barrier = threading.Barrier(len(server.TARGETS))

        def concurrent_sign(path):
            barrier.wait(timeout=5)
            return fake_sign(path)

        instance.test_signer.side_effect = concurrent_sign
        payloads = {target: (target.encode() + b" bytes") * 100 for target in server.TARGETS}
        with ThreadPoolExecutor(max_workers=len(server.TARGETS)) as pool:
            futures = [pool.submit(self.upload, instance, "newer", data, target)
                       for target, data in payloads.items()]
            for future in futures:
                future.result(timeout=10)
        for target, data in payloads.items():
            self.upload(instance, "current", b"baseline", target)
            document = self.update(instance, target=target)
            self.assertEqual(document["signature"], signature(data))
            self.assertEqual(self.request(instance, document["download_url"])[2], data)
        self.assertTrue(self.status(instance)["ready"])
        self.assert_no_staging(instance)

    def test_replacement_invalidates_old_url_and_removes_old_file(self):
        instance = self.make_server()
        self.upload(instance, "newer", b"old package")
        first = self.update(instance)
        old_path = Path(instance.store.directory, "newer",
                        urlsplit(first["download_url"]).path.rsplit("/", 1)[1])
        self.upload(instance, "newer", b"replacement")
        second = self.update(instance)
        self.assertNotEqual(first["download_url"], second["download_url"])
        self.assertEqual(self.request(instance, first["download_url"])[0], 404)
        self.assertEqual(self.request(instance, second["download_url"])[2], b"replacement")
        self.assertFalse(old_path.exists())

    def test_active_download_retains_its_bytes_across_replacement(self):
        instance = self.make_server()
        self.upload(instance, "newer", b"old package")
        with instance.store.open_payload("newer", "linux_deb", signed=True) as (old, handle):
            self.upload(instance, "newer", b"replacement")
            self.assertEqual(handle.read(), b"old package")
        self.assertFalse(Path(old.path).exists())
        self.assertEqual(self.request(instance, "/download-newer/linux_deb")[2], b"replacement")

    def test_signing_failure_preserves_published_pair(self):
        instance = self.make_server()
        self.upload(instance, "newer", b"good package")
        before = self.update(instance)
        for error in (server.ServerError("signing failed"),
                      server.ServerError("cpverify timed out after 1s")):
            with self.subTest(error=str(error)):
                instance.test_signer.side_effect = error
                status, _, _ = self.request(instance, "/upload-newer/linux_deb", "PUT", b"bad")
                self.assertEqual(status, 503)
                self.assertEqual(self.update(instance), before)
                self.assertEqual(self.request(instance, before["download_url"])[2], b"good package")
                self.assert_no_staging(instance)

    def test_file_publication_failure_preserves_published_pair(self):
        instance = self.make_server()
        self.upload(instance, "newer", b"good package")
        before = self.update(instance)
        files_before = set(Path(instance.store.directory, "newer").iterdir())
        with patch.object(server.os, "replace", side_effect=OSError("disk full")):
            status, _, _ = self.request(instance, "/upload-newer/linux_deb", "PUT", b"bad")
        self.assertEqual(status, 500)
        self.assertEqual(self.update(instance), before)
        self.assertEqual(set(Path(instance.store.directory, "newer").iterdir()), files_before)
        self.assertEqual(self.request(instance, before["download_url"])[2], b"good package")

    def test_truncated_upload_is_rejected_and_cleaned(self):
        instance = self.make_server()
        self.upload(instance, "newer", b"original")
        before = self.update(instance)
        status, _ = self.raw_request(instance,
            b"PUT /upload-newer/linux_deb HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Length: 20\r\n\r\nshort")
        self.assertEqual(status, 400)
        self.assertEqual(self.update(instance), before)
        self.assert_no_staging(instance)

    def test_upload_socket_timeout_is_rejected_and_cleaned(self):
        instance = self.make_server(request_timeout=0.2)
        with socket.create_connection(("127.0.0.1", instance.port), timeout=5) as sock:
            sock.sendall(b"PUT /upload-newer/linux_deb HTTP/1.1\r\n"
                         b"Host: localhost\r\nContent-Length: 20\r\n\r\nshort")
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual(response.status, 408)
            response.read()
        instance.test_signer.assert_not_called()
        self.assert_no_staging(instance)

    def test_invalid_upload_requests_do_not_publish(self):
        instance = self.make_server()
        cases = [(b"", 411), (b"Content-Length: 0\r\n", 400),
                 (b"Content-Length: -1\r\n", 400),
                 (b"Content-Length: 1\r\nContent-Length: 1\r\n", 400),
                 (b"Transfer-Encoding: chunked\r\n", 400)]
        for headers, expected in cases:
            with self.subTest(headers=headers):
                status, _ = self.raw_request(instance,
                    b"PUT /upload-newer/linux_deb HTTP/1.1\r\nHost: localhost\r\n"
                    + headers + b"\r\n")
                self.assertEqual(status, expected)
        self.assertEqual(self.request(instance, "/upload-newer/windows", "PUT", b"x")[0], 400)
        self.assertEqual(self.request(instance, "/upload-newer/linux_deb")[0], 405)
        self.assertEqual(self.request(instance, "/download-current/linux_deb", "PUT", b"x")[0], 405)
        self.assertEqual(self.request(instance, "/upload-older/linux_deb", "PUT", b"x")[0], 503)
        instance.test_signer.assert_not_called()
        self.assert_no_staging(instance)

    def test_corrupt_download_changes_only_midpoint(self):
        instance = self.make_server()
        data = bytes(range(256)) * 1025
        self.upload(instance, "newer", data)
        document = self.update(instance, "corrupt")
        status, _, actual = self.request(instance, document["download_url"])
        self.assertEqual(status, 200)
        midpoint = len(data) // 2
        expected = data[:midpoint] + bytes([data[midpoint] ^ 0xFF]) + data[midpoint + 1:]
        self.assertEqual(actual, expected)
        self.assertEqual(document["signature"], signature(data))

    def test_downgrade_uses_optional_signed_older_payload(self):
        instance = self.make_server(older_version=OLDER)
        self.upload(instance, "current")
        self.upload(instance, "newer")
        self.assertTrue(self.status(instance)["ready"])
        self.assertFalse(self.status(instance)["targets"]["linux_deb"]["older_uploaded"])
        self.upload(instance, "older", b"old browser")
        document = self.update(instance, "downgrade")
        self.assertTrue(document["update_available"])
        self.assertEqual(document["version"], OLDER)
        self.assertEqual(self.request(instance, document["download_url"])[2], b"old browser")
        mismatched = document["download_url"].replace("/older/", "/newer/")
        self.assertEqual(self.request(instance, mismatched)[0], 404)

    def test_failure_scenarios_are_preserved(self):
        instance = self.make_server()
        self.assertEqual(self.request(instance, "/http500/update")[0], 500)
        status, _, body = self.request(instance, "/badjson/update")
        self.assertEqual(status, 200)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(body)
        with self.assertRaises(http.client.IncompleteRead):
            self.request(instance, "/truncated/update")

    def test_shutdown_releases_hang_and_partial_upload(self):
        # Windows may not interrupt a timed socket read on shutdown; keep the
        # configured bound small here and verify cleanup after it expires.
        instance = self.make_server(request_timeout=1)
        directory = Path(instance.store.directory)
        hang = socket.create_connection(("127.0.0.1", instance.port), timeout=5)
        upload = socket.create_connection(("127.0.0.1", instance.port), timeout=5)
        self.addCleanup(hang.close)
        self.addCleanup(upload.close)
        entered_hang = threading.Event()
        original = server._Handler._misbehave

        def signal_hang(handler, misbehavior):
            entered_hang.set()
            return original(handler, misbehavior)

        with patch.object(server._Handler, "_misbehave", signal_hang):
            hang.sendall(b"GET /hang/update HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertTrue(entered_hang.wait(3))
            upload.sendall(b"PUT /upload-newer/linux_deb HTTP/1.1\r\n"
                           b"Host: localhost\r\nContent-Length: 1000\r\n\r\nx")
            self.wait_until(lambda: list(directory.rglob(".upload-*.part")))
            start = time.monotonic()
            instance.stop()
        self.assertLess(time.monotonic() - start, 3)
        self.assertFalse(directory.exists())
        self.assertFalse(instance._thread.is_alive())
        instance.test_signer.assert_not_called()

    def test_shutdown_waits_for_signer_before_cleaning(self):
        instance = self.make_server()
        directory = Path(instance.store.directory)
        entered = threading.Event()
        release = threading.Event()

        def signing(path):
            entered.set()
            release.wait(5)
            return fake_sign(path)

        instance.test_signer.side_effect = signing
        sock = socket.create_connection(("127.0.0.1", instance.port), timeout=5)
        self.addCleanup(sock.close)
        sock.sendall(b"PUT /upload-newer/linux_deb HTTP/1.1\r\nHost: localhost\r\n"
                     b"Content-Length: 1\r\n\r\nx")
        self.assertTrue(entered.wait(3))
        with ThreadPoolExecutor(max_workers=1) as pool:
            stopping = pool.submit(instance.stop)
            try:
                self.assertTrue(instance._http_server.stop_event.wait(3))
                self.assertTrue(directory.exists())
                self.assertFalse(stopping.done())
            finally:
                release.set()
            stopping.result(timeout=5)
        self.assertFalse(directory.exists())

    def test_independent_servers_do_not_share_artifacts(self):
        first = self.make_server()
        second = self.make_server(newer_version="998.0.0.0")
        self.upload(first, "newer", b"one")
        self.upload(second, "newer", b"two")
        self.assertNotEqual(first.store.directory, second.store.directory)
        self.assertEqual(self.update(first)["version"], NEWER)
        self.assertEqual(self.update(second)["version"], "998.0.0.0")
        self.assertEqual(self.request(first, "/download-newer/linux_deb")[2], b"one")
        self.assertEqual(self.request(second, "/download-newer/linux_deb")[2], b"two")

    def write_package(self, directory, role, version, data, target="linux_deb"):
        path = Path(directory, role, server.payload_filename(version, target))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_persistent_uploads_restart_without_metadata_files(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = self.make_server(artifacts_dir=directory)
            try:
                self.upload(instance, "current", b"baseline")
                self.upload(instance, "newer", b"replacement")
                self.assertTrue(self.status(instance)["ready"])
            finally:
                instance.stop()
            files = [path for path in Path(directory).rglob("*") if path.is_file()]
            self.assertEqual(len(files), 2)
            self.assertTrue(all(path.suffix == ".deb" for path in files))
            restarted = self.make_server(
                artifacts_dir=directory, signer=lambda path: ("CD" * 64, "17.11.2026"))
            try:
                restarted.test_signer.assert_called_once()
                self.assertTrue(self.status(restarted)["ready"])
                self.assertEqual(self.request(restarted, "/download-current/linux_deb")[2], b"baseline")
                self.assertEqual(self.request(restarted, "/download-newer/linux_deb")[2], b"replacement")
                document = self.update(restarted)
                self.assertEqual(document["signature"], "CD" * 64)
                self.assertEqual(document["signature_timestamp"], "17.11.2026")
            finally:
                restarted.stop()
            self.assertEqual(set(files), {path for path in Path(directory).rglob("*") if path.is_file()})

    def test_existing_packages_use_argument_versions_and_ignore_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            for role, version in (("current", CURRENT), ("newer", NEWER), ("older", OLDER)):
                self.write_package(directory, role, version, role.encode())
            ignored = Path(directory, "newer", "config.yaml")
            ignored.write_text("not even valid yaml: [", encoding="utf-8")
            original_names = {path for path in Path(directory).rglob("*")}
            instance = self.make_server(artifacts_dir=directory, older_version=OLDER)
            try:
                self.assertTrue(self.status(instance)["ready"])
                self.assertEqual(instance.test_signer.call_count, 2)
                self.assertEqual(self.update(instance)["version"], NEWER)
                self.assertEqual(self.update(instance, "downgrade")["version"], OLDER)
                self.assertEqual(self.request(instance, "/download-newer/linux_deb")[2], b"newer")
                self.assertEqual(self.update(instance)["signature"], signature(b"newer"))
            finally:
                instance.stop()
            self.assertEqual(ignored.read_text(encoding="utf-8"), "not even valid yaml: [")
            self.assertEqual(original_names, {path for path in Path(directory).rglob("*")})

    def test_existing_packages_can_be_replaced_without_ambiguity_on_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            original = self.write_package(directory, "newer", NEWER, b"old package")
            instance = self.make_server(artifacts_dir=directory)
            try:
                self.upload(instance, "newer", b"replacement")
                self.assertFalse(original.exists())
            finally:
                instance.stop()
            restarted = self.make_server(artifacts_dir=directory)
            try:
                self.assertEqual(self.request(restarted, "/download-newer/linux_deb")[2], b"replacement")
            finally:
                restarted.stop()

    def test_other_versions_targets_and_disabled_older_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            original = self.write_package(directory, "newer", NEWER, b"version 999")
            self.write_package(directory, "newer", NEWER, b"windows", target="windows")
            self.write_package(directory, "older", OLDER, b"old browser")
            Path(directory, "newer", ".upload-leftover.part").write_bytes(b"incomplete")
            instance = self.make_server(artifacts_dir=directory, newer_version="998.0.0.0")
            try:
                self.assertEqual(self.status(instance)["newer_version"], "998.0.0.0")
                self.assertFalse(self.status(instance)["targets"]["linux_deb"]["newer_uploaded"])
                instance.test_signer.assert_not_called()
                self.upload(instance, "newer", b"version 998")
                self.assertEqual(self.update(instance)["version"], "998.0.0.0")
            finally:
                instance.stop()
            restarted = self.make_server(artifacts_dir=directory)
            try:
                restarted.test_signer.assert_called_once_with(str(original))
                self.assertEqual(self.update(restarted)["version"], NEWER)
                self.assertEqual(self.request(restarted, "/download-newer/linux_deb")[2], b"version 999")
            finally:
                restarted.stop()

    def test_duplicate_matching_packages_fail_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            canonical = self.write_package(directory, "newer", NEWER, b"canonical")
            duplicate = canonical.with_name("a" * 32 + "-" + canonical.name)
            duplicate.write_bytes(b"another package")
            with self.assertRaisesRegex(server.ServerError, "multiple packages"):
                self.make_server(artifacts_dir=directory)
            self.assertEqual(canonical.read_bytes(), b"canonical")
            self.assertEqual(duplicate.read_bytes(), b"another package")

    def test_existing_package_signing_failure_stops_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            package = self.write_package(directory, "newer", NEWER, b"package")
            with self.assertRaisesRegex(server.ServerError, "signing failed"):
                self.make_server(artifacts_dir=directory, signer=server.ServerError("signing failed"))
            self.assertEqual(package.read_bytes(), b"package")
            self.assertEqual(list(package.parent.iterdir()), [package])

    def test_versions_are_required_and_validated_before_creating_directories(self):
        for version in ("../999", "999.0.0", "a.b.c.d", "999.0.0.0/../x"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                server.ArtifactStore(current_version=CURRENT, newer_version=version)
        with self.assertRaisesRegex(server.ServerError, "greater"):
            server.ArtifactStore(current_version=CURRENT, newer_version=OLDER)
        with self.assertRaisesRegex(server.ServerError, "less"):
            server.ArtifactStore(current_version=CURRENT, newer_version=NEWER, older_version=NEWER)
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory, "must-not-be-created")
            with self.assertRaisesRegex(server.ServerError, "required"):
                server.ArtifactStore(missing)
            self.assertFalse(missing.exists())

    def test_failed_start_cleans_temporary_directory(self):
        instance = server.UpdateServer(tls_cert="missing.pem", tls_key="missing.key",
                                       current_version=CURRENT, newer_version=NEWER)
        directory = Path(instance.store.directory)
        with self.assertRaises(OSError):
            instance.start()
        self.assertFalse(directory.exists())
        instance.stop()


class SigningAndCliTests(unittest.TestCase):
    def test_cpverify_command_and_signature_output(self):
        expected = "AB" * 64
        result = subprocess.CompletedProcess([], 0,
            stdout=f"CryptoPro\n{expected.lower()} {DATE}\nOK\n".encode(), stderr=b"")
        with patch.object(server.os.path, "isfile", return_value=True), \
                patch.object(server.subprocess, "run", return_value=result) as run:
            self.assertEqual(server._run_cpverify("package.deb", "container", "cpverify", 7),
                             (expected, DATE))
        run.assert_called_once_with(
            ["cpverify", "-file_sign", "package.deb", "-cont", "container", "-provtype", "80"],
            capture_output=True, timeout=7)

    def test_cpverify_rejects_failure_timeout_and_invalid_signature(self):
        invalid = subprocess.CompletedProcess([], 0, stdout=b"not a signature", stderr=b"")
        failure = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"failed")
        with patch.object(server.os.path, "isfile", return_value=True):
            for outcome in (invalid, failure, subprocess.TimeoutExpired("cpverify", 1)):
                with self.subTest(outcome=outcome):
                    kwargs = ({"side_effect": outcome} if isinstance(outcome, Exception)
                              else {"return_value": outcome})
                    with patch.object(server.subprocess, "run", **kwargs), \
                            self.assertRaises(server.ServerError):
                        server._run_cpverify("package", "container", "cpverify", 1)
        for text in ("AB" * 63 + " " + DATE, "AB" * 64 + " 31.02.2026",
                     "AB" * 129 + " " + DATE):
            with self.subTest(text=text), self.assertRaises(server.ServerError):
                server._parse_cpverify_output(text)
        self.assertEqual(server._parse_cpverify_output("AB" * 128 + " " + DATE),
                         ("AB" * 128, DATE))

    def test_signer_access_is_serialized(self):
        instance = server.UpdateServer(current_version=CURRENT, newer_version=NEWER,
                                       key_container="test")
        self.addCleanup(instance.stop)
        instance.start()
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def signer(path, *args):
            calls.append(path)
            entered.set()
            release.wait(3)
            return "AB" * 64, DATE

        with patch.object(server, "_run_cpverify", side_effect=signer), \
                ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(instance.sign_artifact, "one")
            try:
                self.assertTrue(entered.wait(3))
                second = pool.submit(instance.sign_artifact, "two")
                self.assertEqual(calls, ["one"])
            finally:
                release.set()
            first.result(timeout=3)
            second.result(timeout=3)
        self.assertEqual(calls, ["one", "two"])

    def test_cli_rejects_incomplete_or_invalid_configuration(self):
        base = ["--key-container", "test", "--current-version", CURRENT,
                "--newer-version", NEWER]
        cases = [["--key-container", "test"],
                 ["--key-container", "test", "--artifacts", "unused-directory"],
                 ["--key-container", "test", "--current-version", CURRENT],
                 ["--key-container", "test", "--artifacts", "unused-directory",
                  "--newer-version", NEWER],
                 base + ["--tls-cert", "cert.pem"], base + ["--port", "-1"],
                 base + ["--newer-version", "../999"],
                 base + ["--sign-timeout", "nan"], base + ["--request-timeout", "0"]]
        for arguments in cases:
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as result:
                server.main(arguments)
            self.assertEqual(result.exception.code, 2)

    @unittest.skipIf(os.name == "nt", "SIGTERM terminates immediately on Windows; use Ctrl-C there")
    def test_cli_sigterm_cleans_temporary_directory(self):
        process = subprocess.Popen(
            [sys.executable, "-B", server.__file__, "--key-container", "test",
             "--current-version", CURRENT, "--newer-version", NEWER,
             "--targets", "linux_deb"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        try:
            # Read startup lines on a worker so startup regressions have a bounded timeout.
            with ThreadPoolExecutor(max_workers=1) as pool:
                def startup():
                    for line in process.stdout:
                        if line.startswith("artifacts_dir = "):
                            return Path(line.strip().split(" = ", 1)[1])
                    raise AssertionError("server exited before printing artifact directory")
                future = pool.submit(startup)
                try:
                    directory = future.result(timeout=5)
                except Exception:
                    process.kill()
                    raise
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0)
            self.assertFalse(directory.exists())
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()


if __name__ == "__main__":
    unittest.main()
