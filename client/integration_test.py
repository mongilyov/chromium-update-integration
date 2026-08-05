#!/usr/bin/env python3
"""
integration_test.py -- orchestrator. Runs the two stages in order:
    1. prepare_integration_testing.py -- remove the current browser, install the baseline
    2. run_integration_testing.py     -- launch the browser to update and assert the result
Aborts if prepare fails. Does NOT run the update server; point --server at a running one
(see test_update_server.py).

USAGE
    python integration_test.py \
        --browser /opt/chromium-gost/chrome \
        --server http://192.168.44.10:8080 \
        --variant ok \
        [--expect-version 999.0.0.0] [--target linux_deb] [--package /path/to.deb]
        [--timeout 120] [--poll-interval 1.0] [--relaunch-grace 5.0] [--skip-prepare]

Assumes root/Administrator (the prepare stage installs packages).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
PREPARE_SCRIPT = os.path.join(HERE, "prepare_integration_testing.py")
RUN_SCRIPT = os.path.join(HERE, "run_integration_testing.py")


def _run_stage(title, command):
    print(f"\n=== {title} ===", flush=True)
    print("$ " + " ".join(command), flush=True)
    return subprocess.run(command).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description="Orchestrate prepare + run for the update test.")
    parser.add_argument("--browser", required=True, help="path to the browser executable")
    parser.add_argument("--server", required=True, help="base URL of a running update server")
    parser.add_argument("--variant", default="ok", help="server variant/role (ok, downgrade, ...)")
    parser.add_argument("--expect-version", default=None,
                        help="version the update should reach (passed to the run stage)")
    parser.add_argument("--target", default=None,
                        help="download-current target for prepare (defaults to this platform)")
    parser.add_argument("--package", default=None,
                        help="local baseline package for prepare instead of download-current")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--relaunch-grace", type=float, default=5.0)
    parser.add_argument("--skip-prepare", action="store_true",
                        help="skip the baseline setup stage and only run the update test")
    args = parser.parse_args(argv)

    if not args.skip_prepare:
        prepare_command = [sys.executable, PREPARE_SCRIPT, "--server", args.server,
                           "--timeout", str(args.timeout)]
        if args.target:
            prepare_command += ["--target", args.target]
        if args.package:
            prepare_command += ["--package", args.package]
        code = _run_stage("PREPARE", prepare_command)
        if code != 0:
            print(f"\nprepare stage failed (exit {code}); aborting before the test.")
            return code

    run_command = [sys.executable, RUN_SCRIPT,
                   "--browser", args.browser,
                   "--server", args.server,
                   "--variant", args.variant,
                   "--timeout", str(args.timeout),
                   "--poll-interval", str(args.poll_interval),
                   "--relaunch-grace", str(args.relaunch_grace)]
    if args.expect_version:
        run_command += ["--expect-version", args.expect_version]
    return _run_stage("RUN", run_command)


if __name__ == "__main__":
    sys.exit(main())
