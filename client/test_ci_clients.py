"""Regression tests; never install packages or launch an installed browser.

Run: python -S -B -m unittest discover -s client -p 'test_*.py' -v
"""

from contextlib import contextmanager, redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import ci_common as common
import prepare_integration_test as prepare
import run_integration_test as run


CURRENT = "156.0.8078.96"
NEWER = "999.0.0.0"


def ready_status():
    return {"running": True, "run_id": "123", "current_version": CURRENT,
            "newer_version": NEWER, "targets": {"linux_deb": {
                "current_uploaded": True, "newer_uploaded": True, "newer_signed": True}}}


class Clock:
    value = 0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


@contextmanager
def http_fixture(body=b"", declared_length=None, document=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps(document(self.server.server_port)).encode() if document else body
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload) if declared_length is None else declared_length))
            self.send_header("Content-Disposition", 'attachment; filename="../../escape.deb"')
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class ClientTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ci-client-test-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.report = SimpleNamespace(directory=self.directory, data={})
        stdout = redirect_stdout(io.StringIO())
        stderr = redirect_stderr(io.StringIO())
        stdout.__enter__()
        stderr.__enter__()
        self.addCleanup(stdout.__exit__, None, None, None)
        self.addCleanup(stderr.__exit__, None, None, None)

    def prep_args(self, **changes):
        values = dict(target="linux_deb", system_level=False, command_timeout=1,
                      expect_version=None, server="http://test", server_timeout=1,
                      run_id="123", package=None, timeout=1)
        values.update(changes)
        return SimpleNamespace(**values)

    def run_args(self, **changes):
        browser = self.directory / "browser"
        browser.write_bytes(b"test placeholder")
        values = dict(browser=str(browser), target="linux_deb", system_level=False,
                      server="http://test", variant="ok", expect_no_update=False,
                      expect_version=None, expect_current_version=None, require_log=None,
                      timeout=10, relaunch_grace=2, server_timeout=1, run_id="123",
                      command_timeout=1, poll_interval=1, keep_profile=False)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_download_streams_and_ignores_disposition_filename(self):
        data = bytes(range(256)) * 1025
        with http_fixture(data) as (url, _):
            path = prepare.download_baseline(url, "linux_deb", self.directory, 3)
        self.assertEqual(Path(path), self.directory / "baseline.deb")
        self.assertEqual(Path(path).read_bytes(), data)
        self.assertEqual(list(self.directory.iterdir()), [Path(path)])

    def test_truncated_and_empty_downloads_are_removed(self):
        for body, length in ((b"partial", 100), (b"", 0)):
            with self.subTest(body=body), http_fixture(body, length) as (url, _):
                with self.assertRaises(RuntimeError):
                    prepare.download_baseline(url, "linux_deb", self.directory, 3)
            self.assertFalse((self.directory / "baseline.deb").exists())

    def test_prepare_download_failure_does_not_remove_installation(self):
        target = Mock(target="linux_deb")
        with patch.object(prepare, "current_platform", return_value=target), \
                patch.object(prepare, "wait_for_server", return_value=ready_status()), \
                patch.object(prepare, "download_baseline", side_effect=OSError("network failed")):
            with self.assertRaisesRegex(OSError, "network failed"):
                prepare.prepare(self.prep_args(), self.report)
        target.remove.assert_not_called()
        target.install.assert_not_called()

    def test_prepare_installs_package_and_checks_installed_version(self):
        target = Mock(target="linux_deb")
        target.installed_version.return_value = CURRENT
        actions = []
        target.remove.side_effect = lambda: actions.append("remove")
        target.install.side_effect = lambda path: actions.append("install")
        with patch.object(prepare, "current_platform", return_value=target):
            prepare.prepare(self.prep_args(package="local.deb", expect_version=CURRENT), self.report)
        self.assertEqual(actions, ["remove", "install"])
        self.assertEqual(self.report.data["installed_version"], CURRENT)
        target.installed_version.return_value = NEWER
        with patch.object(prepare, "current_platform", return_value=target), \
                self.assertRaisesRegex(RuntimeError, "installed baseline"):
            prepare.prepare(self.prep_args(package="local.deb", expect_version=CURRENT), self.report)

    def test_prepare_local_package_requires_explicit_version(self):
        target = Mock(target="linux_deb")
        with patch.object(prepare, "current_platform", return_value=target), \
                self.assertRaisesRegex(ValueError, "requires --expect-version"):
            prepare.prepare(self.prep_args(package="local.deb"), self.report)
        target.remove.assert_not_called()

    def test_linux_query_errors_are_not_treated_as_absent_packages(self):
        with patch.object(prepare, "capture_command", side_effect=RuntimeError("database error")), \
                self.assertRaisesRegex(RuntimeError, "database error"):
            prepare.LinuxPlatform().remove()

    def test_windows_registry_scope_and_both_views(self):
        key = Mock()
        key.__enter__ = Mock(return_value=key)
        key.__exit__ = Mock(return_value=False)
        registry = SimpleNamespace(HKEY_LOCAL_MACHINE="machine", HKEY_CURRENT_USER="user",
                                   KEY_WOW64_64KEY=64, KEY_WOW64_32KEY=32, KEY_READ=1,
                                   OpenKey=Mock(side_effect=[FileNotFoundError(), key]),
                                   QueryValueEx=Mock(return_value=(CURRENT, 1)))
        with patch.dict(sys.modules, winreg=registry):
            self.assertEqual(common.windows_installed_version(True), CURRENT)
        calls = registry.OpenKey.call_args_list
        self.assertEqual([call.args[0] for call in calls], ["machine", "machine"])
        self.assertEqual([call.args[3] for call in calls], [65, 33])
        registry.OpenKey.side_effect = None
        registry.OpenKey.return_value = key
        with patch.dict(sys.modules, winreg=registry):
            self.assertEqual(common.windows_installed_version(False), CURRENT)
        self.assertEqual(registry.OpenKey.call_args.args[0], "user")

    def test_macos_reads_full_bundle_version(self):
        bundle = self.directory / "Chromium-Gost.app"
        info = bundle / "Contents" / "Info.plist"
        info.parent.mkdir(parents=True)
        info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": CURRENT,
                                        "CFBundleVersion": "8078.96"}))
        executable = bundle / "Contents" / "MacOS" / "Chromium-Gost"
        self.assertEqual(run.MacOSPlatform().installed_version(str(executable)), CURRENT)
        with patch.object(prepare.MacOSPlatform, "APP_PATH", str(bundle)):
            self.assertEqual(prepare.MacOSPlatform().installed_version(), CURRENT)

    def test_macos_checks_old_framework_and_dangling_current_link(self):
        target = run.MacOSPlatform()
        with patch.object(run, "_bundle_path", return_value=str(self.directory)), \
                patch.object(run.os, "readlink", return_value=NEWER), \
                patch.object(run.os.path, "isdir", side_effect=lambda path: not str(path).endswith("Current")):
            issues = target.post_relaunch_check("browser", CURRENT, NEWER)
        self.assertTrue(any("old version folder" in issue for issue in issues))
        self.assertTrue(any("existing framework" in issue for issue in issues))

    def test_linux_proc_matches_deleted_binary_but_not_other_browser(self):
        wanted = str(self.directory / "chrome")
        with patch.object(run.os, "listdir", return_value=["123", "456", "self"]), \
                patch.object(run.os, "readlink", side_effect=[wanted + " (deleted)", wanted + "-other"]):
            self.assertEqual(run.LinuxPlatform().pids_for_executable(wanted), {123})

    def test_actual_command_streams_output_and_times_out(self):
        log = self.directory / "command.log"
        common.run_command([sys.executable, "-c", "print('x' * 200000)"], "test output", log, 5)
        self.assertGreater(log.stat().st_size, 200000)
        with self.assertRaises(subprocess.TimeoutExpired):
            common.run_command([sys.executable, "-c", "import time; time.sleep(20)"],
                               "test timeout", log, 0.2)

    def test_report_failure_is_machine_readable(self):
        def failure(report):
            raise RuntimeError("expected <failure> & details")
        code = common.run_reported(self.directory, "example", failure)
        self.assertEqual(code, 1)
        result_dir = next(self.directory.iterdir())
        result = json.loads((result_dir / "result.json").read_text())
        self.assertEqual(result["status"], "failed")
        self.assertIn("<failure>", result["error"])
        self.assertEqual(ET.parse(result_dir / "junit.xml").getroot().attrib["failures"], "1")

    def test_status_checks_only_selected_platform_and_run_identity(self):
        with patch.object(common, "read_json", return_value=ready_status()):
            self.assertEqual(common.wait_for_server("http://test", "linux_deb", 1, role="newer",
                                                    run_id="123")["newer_version"], NEWER)
            with self.assertRaisesRegex(ValueError, "run_id"):
                common.wait_for_server("http://test", "linux_deb", 1, run_id="wrong")
            with self.assertRaisesRegex(ValueError, "not enabled"):
                common.wait_for_server("http://test", "windows", 1)

    def test_targets_are_checked_for_all_platforms(self):
        for os_name, allowed in (("Linux", ("linux_deb", "linux_rpm")),
                                 ("Windows", ("windows",)), ("Darwin", ("macos",))):
            with patch.object(common.platform, "system", return_value=os_name):
                for target in allowed:
                    self.assertEqual(common.choose_target(target), target)
                wrong = next(target for target in common.TARGETS if target not in allowed)
                with self.assertRaises(ValueError):
                    common.choose_target(wrong)

    def test_cdp_reads_running_version_and_rejects_wrong_profile_token(self):
        token = "/devtools/browser/test-token"
        with http_fixture(document=lambda port: {"Browser": "Chrome/" + NEWER,
                "webSocketDebuggerUrl": f"ws://127.0.0.1:{port}{token}"}) as (_, port):
            path = self.directory / "DevToolsActivePort"
            path.write_text(f"{port}\n{token}")
            self.assertEqual(run.running_browser_version(self.directory), NEWER)
            path.write_text(f"{port}\n/devtools/browser/wrong-token")
            with self.assertRaisesRegex(RuntimeError, "test profile"):
                run.running_browser_version(self.directory)

    def observe(self, installed=NEWER, running=NEWER, no_update=False, post_check=None):
        clock = Clock()
        target = Mock()
        target.read_version.side_effect = lambda *args, **kwargs: installed(clock.value) if callable(installed) else installed
        target.post_relaunch_check.side_effect = post_check or (lambda *args: [])
        actual_running = lambda *args, **kwargs: running(clock.value) if callable(running) else running
        args = SimpleNamespace(browser="browser", timeout=10, poll_interval=1, relaunch_grace=2)
        with patch.object(run.time, "monotonic", clock.now), patch.object(run.time, "sleep", clock.sleep), \
                patch.object(run, "running_browser_version", side_effect=actual_running):
            if no_update:
                run.observe_no_update(args, target, self.directory, CURRENT, self.report)
            else:
                run.observe_update(args, target, self.directory, CURRENT, NEWER, self.report)
        return clock.value

    def test_installed_version_change_alone_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.observe(installed=NEWER, running=CURRENT)

    def test_running_version_change_alone_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.observe(installed=CURRENT, running=NEWER)

    def test_updated_browser_must_be_stable(self):
        self.assertGreaterEqual(self.observe(), 2)
        def crash(at):
            if at >= 1:
                raise OSError("browser crashed")
            return NEWER
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.observe(running=crash)

    def test_macos_post_relaunch_failure_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, "old framework"):
            self.observe(post_check=lambda *args: ["old framework remains"])

    def test_negative_case_observes_full_window_and_rejects_changes(self):
        self.assertGreaterEqual(self.observe(installed=CURRENT, running=CURRENT, no_update=True), 10)
        with self.assertRaisesRegex(RuntimeError, "unexpected installed version"):
            self.observe(installed=lambda at: NEWER if at >= 3 else CURRENT,
                         running=CURRENT, no_update=True)

    def test_negative_observation_starts_after_browser_is_ready(self):
        def delayed(at):
            if at < 3:
                raise OSError("starting")
            return CURRENT
        self.assertGreaterEqual(self.observe(installed=CURRENT, running=delayed, no_update=True), 13)

    def test_negative_case_fails_if_browser_disappears(self):
        def crashed(at):
            if at >= 3:
                raise OSError("browser crashed")
            return CURRENT
        with self.assertRaisesRegex(RuntimeError, "became unavailable"):
            self.observe(installed=CURRENT, running=crashed, no_update=True)

    def test_negative_case_fails_if_browser_never_starts(self):
        def unavailable(at):
            raise OSError("browser unavailable")
        with self.assertRaisesRegex(RuntimeError, "did not become ready"):
            self.observe(installed=CURRENT, running=unavailable, no_update=True)

    def test_success_waits_for_platform_cleanup_then_stability(self):
        checks = 0
        def post_check(*args):
            nonlocal checks
            checks += 1
            return ["old framework remains"] if checks <= 3 else []
        self.assertEqual(self.observe(post_check=post_check), 5)

    @contextmanager
    def mocked_run(self, start=CURRENT, pids=(), cleanup=None):
        target = Mock(EXTRA_LAUNCH_FLAGS=[])
        target.installed_version.return_value = start
        target.pids_for_executable.return_value = set(pids)
        with patch.object(run, "current_platform", return_value=target), \
                patch.object(run, "choose_target", return_value="linux_deb"), \
                patch.object(run, "require_desktop_user"), \
                patch.object(run, "wait_for_server", return_value=ready_status()), \
                patch.object(run, "start_browser") as launch, \
                patch.object(run, "observe_update") as observe, \
                patch.object(run, "observe_no_update", observe), \
                patch.object(run, "close_browser_at_path", return_value=cleanup or []) as close:
            yield launch, observe, close

    def test_wrong_baseline_and_existing_processes_fail_before_launch(self):
        for start, pids in ((NEWER, ()), (CURRENT, (123,))):
            with self.subTest(start=start, pids=pids), self.mocked_run(start, pids) as (launch, _, _):
                with self.assertRaises(RuntimeError):
                    run.run_case(self.run_args(), self.report)
                launch.assert_not_called()

    def test_cleanup_runs_after_observation_failure(self):
        with self.mocked_run() as (_, observe, close):
            observe.side_effect = RuntimeError("update failed")
            with self.assertRaisesRegex(RuntimeError, "update failed"):
                run.run_case(self.run_args(), self.report)
            close.assert_called_once()
        self.assertFalse(Path(self.report.data["profile"]).exists())

    def test_cleanup_runs_on_cancellation_and_report_is_nonzero(self):
        with self.mocked_run() as (_, observe, close):
            observe.side_effect = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                run.run_case(self.run_args(), self.report)
            close.assert_called_once()
        def interrupted(report):
            raise KeyboardInterrupt()
        self.assertEqual(common.run_reported(self.directory, "cancelled", interrupted), 130)

    def test_cleanup_failure_fails_test_and_preserves_profile(self):
        with self.mocked_run(cleanup=["surviving process"]):
            with self.assertRaisesRegex(RuntimeError, "surviving process"):
                run.run_case(self.run_args(), self.report)
        self.assertTrue(Path(self.report.data["profile"]).exists())

    def test_failed_launch_removes_only_its_temporary_profile(self):
        unrelated = self.directory / "keep.txt"
        unrelated.write_text("keep")
        with self.mocked_run() as (launch, _, close):
            launch.side_effect = OSError("launch failed")
            with self.assertRaisesRegex(OSError, "launch failed"):
                run.run_case(self.run_args(), self.report)
            close.assert_not_called()
        self.assertFalse(Path(self.report.data["profile"]).exists())
        self.assertEqual(unrelated.read_text(), "keep")

    def test_keep_profile_preserves_profile_after_successful_cleanup(self):
        with self.mocked_run() as (_, _, close):
            run.run_case(self.run_args(keep_profile=True), self.report)
            close.assert_called_once()
        self.assertTrue(Path(self.report.data["profile"]).is_dir())

    def test_negative_case_requires_request_and_error_evidence(self):
        args = self.run_args(variant="corrupt", expect_no_update=True)
        with self.mocked_run(), self.assertRaisesRegex(RuntimeError, "no evidence"):
            run.run_case(args, self.report)
        (self.directory / "netlog.json").write_text('"url":"http://test/corrupt/update"')
        with self.mocked_run(), self.assertRaisesRegex(RuntimeError, "log message"):
            run.run_case(args, self.report)
        (self.directory / "chromium.log").write_text("Failed to verify update integrity")
        with self.mocked_run():
            run.run_case(args, self.report)
        self.assertTrue(self.report.data["update_request_observed"])

    def test_browser_output_is_redirected_to_file_not_pipes(self):
        with open(self.directory / "output.log", "wb") as output, \
                patch.object(run.subprocess, "Popen") as popen:
            run.start_browser("browser", "http://test", "ok", self.directory,
                              self.directory, output)
            self.assertIs(popen.call_args.kwargs["stdout"], output)
            self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.STDOUT)
            arguments = popen.call_args.args[0]
            self.assertIn("--remote-debugging-port=0", arguments)
            self.assertIn(f"--user-data-dir={self.directory}", arguments)

    def test_cleanup_checks_newly_relaunched_pids_not_only_initial_set(self):
        target = Mock()
        target.pids_for_executable.side_effect = [{1}, {2}, set()]
        process = Mock()
        process.poll.return_value = 0
        with patch.object(run.time, "sleep"):
            self.assertEqual(run.close_browser_at_path(target, "browser", process), [])
        self.assertEqual(target.close_pids.call_count, 2)
        self.assertEqual(target.close_pids.call_args.args[0], {2})

    def test_cli_rejects_invalid_timeouts_and_versions(self):
        for entry in (prepare.main, run.main):
            base = ["--browser", "unused"] if entry == run.main else []
            for arguments in (["--timeout", "nan"], ["--timeout", "0"],
                              ["--expect-version", "999"]):
                with self.subTest(entry=entry, arguments=arguments), self.assertRaises(SystemExit) as caught:
                    entry(base + arguments)
                self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
