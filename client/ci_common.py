"""Small, standard-library-only helpers shared by the CI clients."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import http.client
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


SERVER_ENV_VARIABLE = "CHROMIUM_TEST_UPDATE_SERVER_URL"
TARGETS = ("windows", "macos", "linux_deb", "linux_rpm")
VERSION_RE = re.compile(r"(?<![0-9.])[0-9]+(?:\.[0-9]+){3}(?![0-9.])")


def version(value):
    if not isinstance(value, str) or len(value) > 64 or not VERSION_RE.fullmatch(value):
        raise ValueError(f"expected a four-part numeric version, got {value!r}")
    return value


def parse_version(output):
    match = VERSION_RE.search(output)
    return match.group(0) if match else None


def positive_seconds(value):
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a positive number of seconds") from error
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("expected a finite positive number of seconds")
    return number


def version_argument(value):
    try:
        return version(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def choose_target(target=None):
    choices = {"Windows": ("windows",), "Darwin": ("macos",),
               "Linux": ("linux_deb", "linux_rpm")}.get(platform.system())
    if choices is None:
        raise RuntimeError(f"unsupported platform: {platform.system()}")
    if target is not None and target not in choices:
        raise ValueError(f"this platform supports {choices}, not {target}")
    return target or choices[0]


def normalize_server_url(url):
    if not url:
        raise ValueError(f"provide --server or {SERVER_ENV_VARIABLE}")
    if "://" not in url:
        url = "http://" + url
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.query or parsed.fragment):
        raise ValueError("server must be an HTTP(S) base URL without credentials, query or fragment")
    parsed.port  # Validate the port before changing any installed software.
    return url.rstrip("/")


def read_json(url, timeout, local=False):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if local else None
    request = opener.open if opener else urllib.request.urlopen
    with request(url, timeout=timeout) as response:
        body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024:
        raise RuntimeError("JSON response exceeds 1 MiB")
    document = json.loads(body)
    if not isinstance(document, dict):
        raise RuntimeError("expected a JSON object")
    return document


def wait_for_server(server_url, target, timeout, *, role="current", run_id=None):
    deadline = time.monotonic() + timeout
    last_error = "server is not ready"
    while time.monotonic() < deadline:
        try:
            status = read_json(server_url + "/status", min(5, deadline - time.monotonic()))
            if run_id is not None and status.get("run_id") != run_id:
                raise ValueError(f"server run_id is {status.get('run_id')!r}, expected {run_id!r}")
            row = status.get("targets", {}).get(target)
            if row is None:
                raise ValueError(f"server has not enabled target {target}")
            version(status.get("current_version"))
            version(status.get("newer_version"))
            if role == "older":
                version(status.get("older_version"))
            ready = row.get("current_uploaded") is True
            if role != "current":
                ready = ready and row.get(f"{role}_uploaded") is True and row.get(f"{role}_signed") is True
            if status.get("running") is True and ready:
                return status
            last_error = f"packages not ready for {target}: {row}"
        except (OSError, RuntimeError, json.JSONDecodeError, http.client.HTTPException) as error:
            last_error = str(error)
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise RuntimeError(f"server readiness timed out after {timeout}s: {last_error}")


def capture_command(command, timeout=10, ok_codes=(0,), env=None):
    result = subprocess.run(command, capture_output=True, text=True, errors="replace",
                            timeout=timeout, env=env)
    if result.returncode not in ok_codes:
        raise RuntimeError(f"command exited {result.returncode}: {command!r}\n"
                           f"{result.stdout}\n{result.stderr}")
    return result


def windows_installed_version(system_level=False):
    import winreg
    hive = winreg.HKEY_LOCAL_MACHINE if system_level else winreg.HKEY_CURRENT_USER
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            with winreg.OpenKey(hive, r"Software\Chromium", 0, winreg.KEY_READ | view) as key:
                value, _ = winreg.QueryValueEx(key, "pv")
                return version(str(value))
        except FileNotFoundError:
            continue
    raise RuntimeError("Chromium version is missing from the selected Windows registry scope")


def run_command(command, what, log_path, timeout, ok_codes=(0,), env=None):
    """Stream installer output to disk, and bound the entire command's lifetime."""
    print(f"{what}: {command!r}", flush=True)
    options = {"start_new_session": True} if os.name != "nt" else {}
    with open(log_path, "ab", buffering=0) as output:
        output.write(f"\n$ {command!r}\n".encode("utf-8"))
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   env=env, **options)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            if os.name == "nt":
                try:
                    subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)],
                                   stdout=output, stderr=subprocess.STDOUT, timeout=10)
                finally:
                    if process.poll() is None:
                        process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=10)
            raise
    if code not in ok_codes:
        raise RuntimeError(f"{what} failed (exit {code}); see {log_path}")
    return code


@contextmanager
def cancellation_signals():
    previous = {}

    def cancel(signum, frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    for name in ("SIGTERM", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is not None:
            previous[signum] = signal.signal(signum, cancel)
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


class Report:
    def __init__(self, root, name):
        if root:
            root = os.path.abspath(root)
            os.makedirs(root, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix=name + "-", dir=root))
        self.name = name
        self.started = time.monotonic()
        self.data = {"test": name, "started_at": datetime.now(timezone.utc).isoformat(),
                     "platform": platform.system(), "result_directory": str(self.directory)}
        print(f"results: {self.directory}", flush=True)

    def finish(self, code, error=None):
        duration = time.monotonic() - self.started
        self.data.update(status="passed" if code == 0 else "failed", exit_code=code,
                         duration_seconds=round(duration, 3))
        if error:
            self.data["error"] = str(error)
        (self.directory / "result.json").write_text(
            json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
        suite = ET.Element("testsuite", name="chromium-update-integration", tests="1",
                           failures=str(int(code != 0)), time=f"{duration:.3f}")
        case = ET.SubElement(suite, "testcase", name=self.name,
                             classname="chromium.update", time=f"{duration:.3f}")
        if code:
            ET.SubElement(case, "failure", message=str(error or "failed")).text = str(error or "failed")
        ET.SubElement(case, "system-out").text = f"Logs: {self.directory}"
        ET.ElementTree(suite).write(self.directory / "junit.xml", encoding="utf-8", xml_declaration=True)
        print(f"RESULT: {'PASS' if code == 0 else 'FAIL'}; {self.directory}", flush=True)


def run_reported(root, name, action):
    report = Report(root, name)
    error = None
    code = 0
    try:
        with cancellation_signals():
            action(report)
    except KeyboardInterrupt as caught:
        code, error = 130, str(caught) or "interrupted"
    except Exception as caught:
        code, error = 1, caught
        (report.directory / "error.log").write_text(traceback.format_exc(), encoding="utf-8")
    if error is not None:
        print(f"FAILED: {error}", file=sys.stderr, flush=True)
    report.finish(code, error)
    return code
