#!/usr/bin/env python3
"""Adversarial unit coverage for the signed modern UDP evidence path."""

import contextlib
import ctypes as C
import io
import json
import hashlib
import os
from pathlib import Path
import pty
import re
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import textwrap
import time
import unittest
from unittest import mock
from types import SimpleNamespace


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import modern_udp_e2e_probe as udp_probe  # noqa: E402
from modern_udp_e2e_probe import (  # noqa: E402
    ProductViolation,
    controlled_echo_load,
    parse_quic_shaped_payload,
    pressure_burst,
    quic_shaped_payload,
)
from modern_udp_evidence import (  # noqa: E402
    BundleVerificationError,
    parse_signed_udp_status_lines,
    pressure_window_observation,
    producer_sources_sha256,
    validate_echo_decision_bijection,
    validate_echo_socket_maps,
    verify_bundle,
    _validate_echo_timing,
)


RUN_UUID = "12345678-1234-4234-8234-123456789abc"
DIGEST = "a" * 64


def exercise_capture_terminal_context(test, helpers, *, stress=False):
    """Create an isolated controlling PTY; never open the user's terminal."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        observation = textwrap.dedent("""\
            import json, os, pathlib, sys, time
            root = pathlib.Path(sys.argv[1])
            with open('/dev/tty', 'rb', buffering=0) as terminal:
                record = dict(pid=os.getpid(), parent=os.getppid(),
                              sid=os.getsid(0), pgid=os.getpgrp(),
                              foreground=os.tcgetpgrp(terminal.fileno()))
            (root / (sys.argv[2] + '.json')).write_text(json.dumps(record))
            if sys.argv[2] == 'leaf':
                if os.fork() == 0:
                    # Keep the capture pipe open after the command exits.
                    time.sleep(0.2)
                    (root / 'drained').write_text('done')
                    os._exit(0)
                os._exit(7)
        """)
        probe = root / "terminal_probe.py"
        probe.write_text(observation)
        command = f"{shlex.quote(sys.executable)} {shlex.quote(str(probe))} {shlex.quote(str(root))}"
        invocation = (
            f'run_bounded_capture "$TMP_DIR/output" 5 {command} leaf'
            if stress else f'run_bounded 5 {command} leaf > "$TMP_DIR/output" 2>&1'
        )
        prefix = "" if stress else "bounded_"
        fixture_helpers = helpers.replace(
            f"{prefix}pid_identity() {{", "fixture_pid_identity() {", 1
        ) + textwrap.dedent(f"""\
            {prefix}pid_identity() {{
              local identity
              identity="$(fixture_pid_identity "$@")" || return 1
              if [[ "${{2:-}}" == generation \\
                && "$(ps -o ppid= -p "$1" | tr -d '[:space:]')" == "$$" ]]; then
                printf '%s\\t%s\\n' "$1" "$identity" >> "$TMP_DIR/owned-generations"
              fi
              printf '%s\\n' "$identity"
            }}
        """)
        program = fixture_helpers + textwrap.dedent(f"""\
            TMP_DIR={shlex.quote(str(root))}
            BOUNDED_CLEANUP_FAILED="$TMP_DIR/failed"
            AUXILIARY_PIDS=() AUXILIARY_DRAIN_RECEIPTS=()
            CLEANUP_INCOMPLETE=0 EVIDENCE_FAILED=0
            {command} caller || exit 90
            {invocation}
            result=$?
            [[ -e "$TMP_DIR/drained" ]] || exit 91
            printf '%s %s %s %s\\n' "$result" \\
              "$(jobs -p | wc -l | tr -d ' ')" \\
              "$CLEANUP_INCOMPLETE" "$EVIDENCE_FAILED" > "$TMP_DIR/result"
        """)
        child, terminal = pty.fork()
        if child == 0:
            os.execv("/bin/bash", ["/bin/bash", "-c", program])
        output = bytearray()
        status = None
        passed = False
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.05)[0]:
                    try:
                        data = os.read(terminal, 65536)
                    except OSError as error:
                        if error.errno != 5:  # PTY masters may report EIO at EOF.
                            raise
                        data = b""
                    output.extend(data)
                observed, status_value = os.waitpid(child, os.WNOHANG)
                if observed:
                    status = status_value
                    break
            detail = output.decode(errors="replace")
            if (root / "output").exists():
                detail += (root / "output").read_text()
            test.assertIsNotNone(status, "isolated terminal fixture timed out: " + detail)
            test.assertEqual(os.waitstatus_to_exitcode(status), 0, detail)
            test.assertEqual((root / "result").read_text(), "7 0 0 0\n", detail)
            caller = json.loads((root / "caller.json").read_text())
            leaf = json.loads((root / "leaf.json").read_text())
            test.assertEqual(caller["sid"], child)
            test.assertEqual(leaf["sid"], caller["sid"])
            test.assertEqual(leaf["pgid"], leaf["parent"])
            test.assertNotEqual(leaf["pgid"], caller["pgid"])
            test.assertEqual(leaf["foreground"], caller["pgid"])
            registered = dict(
                row.split("\t") for row in (root / "owned-generations").read_text().splitlines()
            )
            test.assertRegex(registered[str(leaf["parent"])], r"^[0-9a-f]{64}$")
            test.assertFalse((root / "failed").exists())
            test.assertFalse(list(root.glob("*.drain.*")))
            passed = True
        finally:
            try:
                if not passed:
                    # The unreaped PTY shell is our direct child. Stop it so
                    # no new helper can race registration during fallback.
                    if status is None:
                        try:
                            os.kill(child, signal.SIGSTOP)
                        except ProcessLookupError:
                            pass
                    try:
                        cleanup = helpers + textwrap.dedent(f"""\
                            # Synthetic fixture processes never need privilege.
                            sudo() {{ return 1; }}
                            tree="" failed=0
                            while IFS=$'\\t' read -r pid identity; do
                              [[ "$pid" =~ ^[1-9][0-9]*$ \\
                                && "$identity" =~ ^[0-9a-f]{{64}}$ ]] || continue
                              if {prefix}signal_owned_identity "$pid" "$identity" STOP; then
                                observed="$({prefix}collect_owned_tree "$pid" "$identity" $((SECONDS + 1)))" || failed=1
                                tree+="$observed"$'\\n'
                              elif ! {prefix}owned_identity_has_exited "$pid" "$identity"; then
                                failed=1
                              fi
                            done < <(sort -u {shlex.quote(str(root / 'owned-generations'))})
                            while IFS=$'\\t' read -r pid identity; do
                              [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
                              {prefix}signal_owned_identity "$pid" "$identity" KILL || true
                            done <<< "$tree"
                            deadline=$((SECONDS + 2))
                            while ! {prefix}owned_tree_has_exited "$tree"; do
                              (( SECONDS < deadline )) || exit 1
                              sleep 0.01
                            done
                            exit "$failed"
                        """)
                        if (root / "owned-generations").exists():
                            drained = subprocess.run(
                                ["/bin/bash", "-c", cleanup], capture_output=True,
                                text=True, timeout=5,
                            )
                            test.assertEqual(drained.returncode, 0, drained.stdout + drained.stderr)
                    finally:
                        if status is None:
                            try:
                                os.killpg(child, signal.SIGKILL)
                            except (ProcessLookupError, PermissionError):
                                # The group may already be empty. The unreaped
                                # direct child remains safe to signal by PID.
                                try:
                                    os.kill(child, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            os.waitpid(child, 0)
            finally:
                os.close(terminal)


def exercise_owned_chain_discovery(test, helpers, prefix, *, expired=False):
    """Use eight native processes, then prove cleanup before fallback teardown."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        pids_file = root / "pids"
        chain = textwrap.dedent("""\
            import os, signal, sys, time
            os.setsid()
            for index in range(8):
                with open(sys.argv[1], "a") as output:
                    output.write(str(os.getpid()) + "\\n")
                if index == 7 or os.fork() != 0:
                    break
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(30)
        """)
        process = subprocess.Popen([sys.executable, "-c", chain, str(pids_file)])
        pids = []
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                pids = list(map(int, pids_file.read_text().splitlines())) if pids_file.exists() else []
                if len(pids) == 8:
                    break
                time.sleep(0.02)
            test.assertEqual(len(pids), 8)
            program = helpers + textwrap.dedent(f"""\
                set -u
                identity="$({prefix}pid_identity {process.pid} generation)"
                {prefix}signal_owned_identity {process.pid} "$identity" STOP || exit 9
                tree_text="$({prefix}collect_owned_tree {process.pid} "$identity" $((SECONDS + {0 if expired else 5})))"
                result=$?
                while IFS=$'\\t' read -r pid generation; do
                  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
                  {prefix}signal_owned_identity "$pid" "$generation" KILL || true
                done <<< "$tree_text"
                printf 'rc=%s\\n%s\\n' "$result" "$tree_text"
            """)
            started = time.monotonic()
            result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=8)
            test.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            test.assertLess(time.monotonic() - started, 5)
            lines = result.stdout.splitlines()
            test.assertEqual(lines[0], f"rc={int(expired)}", result.stdout)
            observed = [int(line.split("\t")[0]) for line in lines[1:]]
            test.assertEqual(len(observed), 1 if expired else 8, result.stdout)
            test.assertEqual(set(observed), {process.pid} if expired else set(pids))
            process.wait(timeout=2)
            deadline = time.monotonic() + 2
            survivors = pids
            while survivors and time.monotonic() < deadline:
                survivors = []
                for pid in pids:
                    try:
                        os.kill(pid, 0)
                        survivors.append(pid)
                    except ProcessLookupError:
                        pass
                if survivors:
                    time.sleep(0.02)
            test.assertFalse(survivors, f"owned chain survived discovery cleanup: {survivors}")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # macOS can return EPERM for a now-empty group whose leader
                # has exited; still require proof that our child is gone.
                if process.poll() is None:
                    raise
            process.wait(timeout=2)


class BoundedCommandCleanupTests(unittest.TestCase):
    @staticmethod
    def shell_function(name):
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        return name + "() {" + shell.split(name + "() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"

    def helper_source(self):
        return "".join(self.shell_function(name) for name in (
            "bounded_pid_identity", "bounded_owned_job_is_active",
            "bounded_owned_job_has_exited", "bounded_owned_identity_has_exited",
            "bounded_owned_tree_has_exited", "bounded_collect_owned_tree",
            "bounded_signal_owned_identity", "bounded_command_supervisor", "bounded_drain_receipt_valid", "run_bounded",
        ))

    def setUp(self):
        try:
            inspected = subprocess.run(
                ["/bin/ps", "-p", str(os.getpid()), "-o", "lstart="],
                capture_output=True, text=True, timeout=3,
            )
        except OSError:
            self.skipTest("host sandbox blocks process identity inspection")
        if inspected.returncode != 0 or not inspected.stdout.strip():
            self.skipTest("host sandbox blocks process identity inspection")

    def test_bounded_seal_and_verify_leave_the_complete_manifest_unchanged(self):
        import signed_run_evidence as evidence
        from test_signed_run_evidence import make_run

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "evidence"
            receipts = parent / "receipt-paths"
            make_run(root, "modern_udp", claims=[
                ("dial9_workload_coverage", "1"),
                ("dial9_claim", "exact-workload"),
            ])
            program = self.helper_source() + textwrap.dedent(f"""\
                set -eu
                TMP_DIR={shlex.quote(str(root))}
                BOUNDED_CLEANUP_FAILED="$TMP_DIR/.bounded-cleanup-failed"
                mktemp() {{
                  local receipt
                  receipt="$(command mktemp "$@")" || return
                  printf '%s\\n' "$receipt" >> {shlex.quote(str(receipts))}
                  printf '%s\\n' "$receipt"
                }}
                run_bounded 10 {shlex.quote(sys.executable)} \
                  {shlex.quote(str(SCRIPT_DIR / 'signed_run_evidence.py'))} \
                  seal "$TMP_DIR" --actual-exit-code 0
                run_bounded 10 {shlex.quote(sys.executable)} \
                  {shlex.quote(str(SCRIPT_DIR / 'signed_run_evidence.py'))} \
                  verify "$TMP_DIR" --actual-exit-code 0
                [[ -z "$(jobs -p)" && ! -e "$BOUNDED_CLEANUP_FAILED" ]]
            """)
            result = subprocess.run(
                ["bash", "-c", program], capture_output=True, text=True, timeout=25,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(evidence.verify(root, actual_exit_code=0)["passed"], "1")
            paths = [Path(path) for path in receipts.read_text().splitlines()]
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(root not in path.parents for path in paths))
            self.assertTrue(all(not path.exists() for path in paths))

    def run_tree_fixture(self, *, delayed_writer=False, orphan=False, deny_kill=False, interrupt=None, expire_discovery=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pids = root / "pids"
            leaf_file = root / "leaf"
            late_write = root / "late-write"
            finished = root / "finished"
            failed = root / "cleanup-failed"
            tree = root / "tree.py"
            tree.write_text(textwrap.dedent(f"""\
                import os, pathlib, signal, time
                os.dup2(3, 1)
                os.dup2(3, 2)
                def record():
                    with open({str(pids)!r}, "a") as output:
                        output.write(str(os.getpid()) + "\\n")
                record()
                if os.fork() == 0:
                    record()
                    if os.fork() == 0:
                        record()
                        pathlib.Path({str(leaf_file)!r}).write_text(str(os.getpid()))
                        if {delayed_writer!r}:
                            time.sleep(3)
                            pathlib.Path({str(late_write)!r}).write_text("late artifact write")
                            os._exit(0)
                        signal.signal(signal.SIGTERM, signal.SIG_IGN)
                        os.kill(os.getpid(), signal.SIGSTOP)
                        time.sleep(30)
                    if {orphan!r}:
                        os._exit(0)
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    time.sleep(30)
                if {orphan!r}:
                    os._exit(0)
                time.sleep(30)
            """))
            program = self.helper_source() + f"\nBOUNDED_CLEANUP_FAILED={shlex.quote(str(failed))}\nexec 3>&1\n"
            if expire_discovery:
                program += self.shell_function("bounded_collect_owned_tree").replace(
                    "bounded_collect_owned_tree()", "real_bounded_collect_owned_tree()", 1
                )
                program += "bounded_collect_owned_tree() { real_bounded_collect_owned_tree \"$1\" \"$2\" \"$SECONDS\"; }\n"
            if interrupt is not None:
                program += (
                    "trap 'exit 130' INT\ntrap 'exit 143' TERM\n"
                    "trap 'printf \"signal-exit=%s jobs=%s\\n\" \"$?\" \"$(jobs -p | wc -l | tr -d \" \")\"' EXIT\n"
                )
            if deny_kill:
                program += self.shell_function("bounded_signal_owned_identity").replace(
                    "bounded_signal_owned_identity()", "real_bounded_signal_owned_identity()", 1
                )
                program += textwrap.dedent(f"""\
                    bounded_signal_owned_identity() {{
                      if [[ -s {shlex.quote(str(leaf_file))} && "$3" == KILL \
                        && "$1" == "$(cat {shlex.quote(str(leaf_file))})" ]]; then return 1; fi
                      real_bounded_signal_owned_identity "$@"
                    }}
                    # Model a group containing one privileged descendant: group
                    # KILL reaches the owned supervisor but cannot kill that leaf.
                    kill() {{
                      local member protected
                      if [[ "$1" == -KILL && "$3" == -* \
                        && -s {shlex.quote(str(leaf_file))} ]]; then
                        protected="$(cat {shlex.quote(str(leaf_file))})"
                        for member in $(pgrep -g "${{3#-}}"); do
                          [[ "$member" == "$protected" ]] || builtin kill -KILL "$member" 2>/dev/null || true
                        done
                        return 0
                      fi
                      builtin kill "$@"
                    }}
                    sudo() {{ return 1; }}
                """)
            program += textwrap.dedent(f"""\
                run_bounded {10 if interrupt is not None else 1} {shlex.quote(sys.executable)} {shlex.quote(str(tree))} > {shlex.quote(str(root / 'command-output'))} 2>&1
                result=$?
                printf 'rc=%s jobs=%s\\n' "$result" "$(jobs -p | wc -l | tr -d ' ')"
                printf '%s\\n' "$result" > {shlex.quote(str(finished))}
            """)
            started = time.monotonic()
            process = subprocess.Popen(
                ["/bin/bash", "-c", program], stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True,
            )
            pid_values = []
            survivors = []
            try:
                if interrupt is not None:
                    deadline = time.monotonic() + 5
                    while not leaf_file.exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue(leaf_file.exists(), "command tree never reached the signal boundary")
                    os.kill(process.pid, interrupt)
                if deny_kill:
                    deadline = time.monotonic() + 10
                    while not finished.exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue(finished.exists(), "cleanup never returned after denied KILL")
                    self.assertEqual(finished.read_text().strip(), "125")
                    self.assertTrue(failed.exists(), "unreaped writer did not block sealing")
                    os.kill(int(leaf_file.read_text()), signal.SIGKILL)
                output, _ = process.communicate(timeout=10)
                if interrupt is not None:
                    self.assertEqual(process.returncode, 128 + interrupt, output)
                    self.assertEqual(output.splitlines()[-1], f"signal-exit={128 + interrupt} jobs=0")
                else:
                    self.assertEqual(process.returncode, 0, output)
                    expected = 125 if deny_kill or expire_discovery else 124
                    self.assertEqual(output.splitlines()[-1], f"rc={expected} jobs=0")
                self.assertLess(time.monotonic() - started, 10)
                self.assertEqual(failed.exists(), deny_kill or expire_discovery)
                self.assertTrue(pids.exists())
                pid_values = [int(value) for value in pids.read_text().splitlines()]
                self.assertEqual(len(pid_values), 3)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    survivors = []
                    for pid in pid_values:
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            continue
                        survivors.append(pid)
                    if not survivors:
                        break
                    time.sleep(0.05)
                self.assertFalse(survivors, f"command descendants survived cleanup: {survivors}")
                self.assertFalse(late_write.exists())
            finally:
                if pids.exists():
                    for pid in map(int, pids.read_text().splitlines()):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_timeout_stops_delayed_artifact_writer(self):
        self.run_tree_fixture(delayed_writer=True)

    def test_capture_preserves_terminal_session_and_drains_owned_group(self):
        exercise_capture_terminal_context(self, self.helper_source())

    def test_discovery_visits_each_owned_generation_once(self):
        exercise_owned_chain_discovery(self, self.helper_source(), "bounded_")

    def test_expired_discovery_retains_root_cleanup_authority(self):
        exercise_owned_chain_discovery(self, self.helper_source(), "bounded_", expired=True)

    def test_expired_discovery_reaps_group_and_blocks_evidence(self):
        self.run_tree_fixture(orphan=True, expire_discovery=True)

    def test_timeout_reaps_stopped_term_resistant_descendants_holding_pipes(self):
        self.run_tree_fixture()

    def test_successful_wrapper_exit_cannot_orphan_stopped_pipe_holder(self):
        self.run_tree_fixture(orphan=True)

    def test_unreaped_descendant_returns_failure_and_blocks_sealing(self):
        self.run_tree_fixture(orphan=True, deny_kill=True)

    def test_interrupt_cleans_up_before_outer_exit_finalization(self):
        for interrupt in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(interrupt=interrupt):
                self.run_tree_fixture(orphan=True, interrupt=interrupt)

    def test_finalizer_never_seals_after_bounded_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parser = root / "status-parser.py"
            parser.write_text("import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text().strip())\n")
            failed = root / "cleanup-failed"
            failed.touch()
            program = self.shell_function("finalize") + textwrap.dedent(f"""\
                TMP_DIR={shlex.quote(str(root))}
                BOUNDED_CLEANUP_FAILED={shlex.quote(str(failed))}
                MODERN_EVIDENCE={shlex.quote(str(parser))}
                EVIDENCE_STATUS={shlex.quote(str(root / 'status'))}
                FINALIZING=0 MAIN_FINISHED=1 RUN_START_EPOCH_MS=1
                UDP_PROBE_ATTEMPT_COUNT=9 UDP_PROBE_PASS_COUNT=9
                UDP_PRESSURE_LOG_CHECKED=1 PRESSURE_PROBE_ATTEMPTED=1 PRESSURE_PROBE_PASSED=1
                ISSUES=() FAILURES=() OBSERVED_FAILURES=()
                add_issue() {{ ISSUES+=("$1"); }}
                stop_active_workloads() {{ :; }}
                stop_echo_server() {{ :; }}
                stop_log_capture() {{ :; }}
                stop_remaining_owned_commands() {{ :; }}
                check_final_provider_logs() {{ :; }}
                sleep() {{ :; }}
                collect_dial9_evidence() {{ :; }}
                restore_profile() {{ :; }}
                require_provider_identity() {{ :; }}
                capture_provider_generation_sample() {{ :; }}
                stop_provider_generation_monitor() {{ :; }}
                write_workload_claims() {{ :; }}
                write_evidence_status() {{ printf '%s\\n' "$3" > "$EVIDENCE_STATUS"; }}
                write_common_evidence_status() {{ printf '%s %s %s\\n' "$@" > "$TMP_DIR/common-status"; }}
                run_bounded() {{
                  for argument in "$@"; do
                    if [[ "$argument" == seal || "$argument" == verify ]]; then
                      printf '%s\\n' "$argument" >> "$TMP_DIR/seal-attempts"
                    fi
                  done
                  printf 'crash_count\\t0\\n'
                }}
                finalize
            """)
            result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual((root / "common-status").read_text(), "0 0 2\n")
            self.assertFalse((root / "seal-attempts").exists())

    def test_privileged_signal_fallback_is_scoped_to_the_observed_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attempts = root / "sudo-attempts"
            program = self.helper_source() + textwrap.dedent(f"""\
                /bin/sleep 30 &
                child=$!
                trap 'builtin kill -KILL "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
                identity="$(bounded_pid_identity "$child" generation)"
                kill() {{ return 1; }}
                sudo() {{
                  printf '%s\\n' "$*" >> {shlex.quote(str(attempts))}
                  [[ "$1" == -n && "$2" == /bin/kill && "$3" == -STOP \
                    && "$4" == -- && "$5" == "$child" ]] || return 90
                  shift 2
                  builtin kill "$@"
                }}
                bounded_signal_owned_identity "$child" wrong-generation STOP
                wrong=$?
                bounded_signal_owned_identity "$child" "$identity" STOP
                correct=$?
                state="$(ps -o state= -p "$child" | tr -d ' ')"
                printf 'wrong=%s correct=%s stopped=%s\\n' "$wrong" "$correct" "${{state:0:1}}"
            """)
            result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.stdout, "wrong=1 correct=0 stopped=T\n", result.stderr)
            rows = attempts.read_text().splitlines()
            self.assertEqual(len(rows), 1)
            self.assertRegex(rows[0], r"^-n /bin/kill -STOP -- [1-9][0-9]*$")

    def test_completed_command_preserves_output_status_and_unrelated_process(self):
        unrelated = subprocess.Popen(["/bin/sleep", "30"])
        try:
            with tempfile.TemporaryDirectory() as temporary:
                failed = Path(temporary) / "cleanup-failed"
                program = self.helper_source() + f"\nBOUNDED_CLEANUP_FAILED={shlex.quote(str(failed))}\n"
                program += "run_bounded 3 /bin/sh -c 'printf payload; exit 7'\nprintf ':rc=%s jobs=%s\\n' \"$?\" \"$(jobs -p | wc -l | tr -d ' ')\"\n"
                result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "payload:rc=7 jobs=0\n")
                self.assertIsNone(unrelated.poll())
                self.assertFalse(failed.exists())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=5)

    def test_owned_command_handoff_preserves_actual_leaf_pid_and_exit_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = self.helper_source() + "".join(self.shell_function(name) for name in (
                "start_owned_command", "unregister_owned_command", "join_owned_command",
            )) + textwrap.dedent(f"""\
                TMP_DIR={shlex.quote(str(root))}
                BOUNDED_CLEANUP_FAILED="$TMP_DIR/failed"
                OWNED_COMMAND_SEQUENCE=0 ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT=0
                OWNED_COMMAND_IDENTITIES=() OWNED_COMMAND_SOURCE_PIDS=()
                OWNED_COMMAND_SOURCE_IDENTITIES=() OWNED_COMMAND_ROLES=() OWNED_COMMAND_FILES=()
                add_issue() {{ printf '%s\\n' "$1" >&2; }}
                start_owned_command probe /usr/bin/python3 -c \\
                  'import os,pathlib,sys;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));sys.exit(7)' \\
                  "$TMP_DIR/leaf" || exit 3
                owner="$OWNED_COMMAND_PID" source="$OWNED_COMMAND_SOURCE_PID"
                join_owned_command "$owner" "$((SECONDS + 5))"
                result=$?
                printf 'rc=%s owner=%s source=%s actual=%s registered=%s\\n' \\
                  "$result" "$owner" "$source" "$(cat "$TMP_DIR/leaf")" "${{OWNED_COMMAND_ROLES[owner]:-none}}"
            """)
            result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            values = dict(item.split("=") for item in result.stdout.strip().split())
            self.assertEqual(values["rc"], "7")
            self.assertEqual(values["source"], values["actual"])
            self.assertNotEqual(values["owner"], values["source"])
            self.assertEqual(values["registered"], "none")
            self.assertFalse((root / "failed").exists())
            self.assertFalse(list(root.glob(".owned-command-*")))


class OwnedCommandLifecycleTests(unittest.TestCase):
    """Exercise process state, signals, and wait with synthetic operations only."""

    shell_function = staticmethod(BoundedCommandCleanupTests.shell_function)
    # This existing finalizer fixture is entirely mocked and needs no host ps
    # capability; keep it active when native lifecycle checks are unavailable.
    test_finalizer_never_seals_after_bounded_cleanup_failure = (
        BoundedCommandCleanupTests.test_finalizer_never_seals_after_bounded_cleanup_failure
    )

    def helpers(self):
        return "".join(self.shell_function(name) for name in (
            "bounded_owned_job_has_exited", "bounded_signal_owned_identity",
            "bounded_owned_identity_has_exited", "bounded_owned_tree_has_exited",
            "bounded_drain_receipt_valid", "owned_command_source_is_alive", "unregister_owned_command",
            "join_owned_command", "stop_active_workloads", "stop_log_capture",
        ))

    def run_mock(self, body):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = self.helpers() + textwrap.dedent(f"""\
                TMP_DIR={shlex.quote(str(root))}
                BOUNDED_CLEANUP_FAILED="$TMP_DIR/failed"
                OWNED_COMMAND_IDENTITIES=() OWNED_COMMAND_SOURCE_PIDS=()
                OWNED_COMMAND_SOURCE_IDENTITIES=() OWNED_COMMAND_ROLES=() OWNED_COMMAND_FILES=()
                OWNED_COMMAND_IDENTITIES[41]={'a' * 64}
                OWNED_COMMAND_SOURCE_PIDS[41]=42
                OWNED_COMMAND_SOURCE_IDENTITIES[41]={'b' * 64}
                OWNED_COMMAND_ROLES[41]=http3
                OWNED_COMMAND_FILES[41]="$TMP_DIR/command"
                ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT=0
                ISSUES=()
                add_issue() {{ ISSUES+=("$1"); }}
                sleep() {{ SECONDS=$((SECONDS + 1)); }}
                wait() {{ printf '%s\\n' "$1" >> "$TMP_DIR/waits"; return 7; }}
                bounded_pid_identity() {{ printf '%s\\n' "${{OWNED_COMMAND_IDENTITIES[$1]}}"; }}
                bounded_owned_job_is_active() {{ return 0; }}
                ps() {{ printf 'S\\n'; }}
                kill() {{ printf '%s\\n' "$*" >> "$TMP_DIR/signals"; return 0; }}
                sudo() {{ return 1; }}
            """) + textwrap.dedent(body)
            result = subprocess.run(
                ["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            artifacts = {path.name: path.read_text() for path in root.iterdir()}
            return result.stdout, artifacts

    def test_inconclusive_ps_never_proves_a_live_owned_job_exited(self):
        for ps_body in ("return 0", "return 1"):
            with self.subTest(ps_body=ps_body):
                output, _ = self.run_mock(f"""\
                    ps() {{ {ps_body}; }}
                    bounded_owned_job_has_exited 41
                    printf 'exited=%s\\n' "$?"
                """)
                self.assertEqual(output, "exited=1\n")

    def test_intercepted_http3_is_stopped_with_early_owned_workloads(self):
        output, _ = self.run_mock("""\
            OWNED_COMMAND_ROLES[41]=http3-intercept
            OWNED_COMMAND_IDENTITIES[51]=logger-identity
            OWNED_COMMAND_ROLES[51]=logger
            join_owned_command() {
              printf 'joined=%s mode=%s\\n' "$1" "$3"
              unregister_owned_command "$1"
              return 0
            }
            stop_active_workloads
            printf 'h3=%s logger=%s\\n' "${OWNED_COMMAND_ROLES[41]:-gone}" "${OWNED_COMMAND_ROLES[51]}"
        """)
        self.assertEqual(output, "joined=41 mode=stop\nh3=gone logger=logger\n")

    def test_bounded_command_rejects_missing_or_mismatched_drain_receipt(self):
        helpers = self.shell_function("run_bounded") + self.shell_function("bounded_drain_receipt_valid")
        for receipt, expected in (("42\t7\n", 7), ("", 125), ("42\t0\n", 125)):
            with self.subTest(receipt=receipt):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    program = helpers + textwrap.dedent(f"""\
                        BOUNDED_CLEANUP_FAILED={shlex.quote(str(root / 'failed'))}
                        bounded_command_supervisor() {{ return 0; }}
                        bounded_pid_identity() {{ printf '%s\\n' {'a' * 64}; }}
                        bounded_owned_job_has_exited() {{ return 0; }}
                        bounded_owned_tree_has_exited() {{ return 0; }}
                        wait() {{ printf '%s' {shlex.quote(receipt)} > "$receipt"; return 7; }}
                        run_bounded 3 unused-command
                        printf 'rc=%s\\n' "$?"
                    """)
                    result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, f"rc={expected}\n")
                    self.assertEqual((root / "failed").exists(), expected == 125)

    def test_generation_change_revokes_every_signal(self):
        output, artifacts = self.run_mock(f"""\
            bounded_pid_identity() {{ printf '%s\\n' {'c' * 64}; }}
            for signal in STOP TERM CONT KILL; do
              bounded_signal_owned_identity 41 {'a' * 64} "$signal"
              printf '%s=%s\\n' "$signal" "$?"
            done
        """)
        self.assertEqual(output, "STOP=1\nTERM=1\nCONT=1\nKILL=1\n")
        self.assertNotIn("signals", artifacts)

    def test_denied_termination_is_bounded_and_never_waits_or_unregisters(self):
        output, artifacts = self.run_mock(f"""\
            bounded_collect_owned_tree() {{ printf '41\\t%s\\n' {'a' * 64}; }}
            bounded_signal_owned_identity() {{
              printf '%s\\n' "$3" >> "$TMP_DIR/signals"
              [[ "$3" == STOP || "$3" == CONT ]]
            }}
            join_owned_command 41 "$SECONDS" stop 1
            result=$?
            printf 'rc=%s reaped=%s forced=%s registered=%s\\n' \\
              "$result" "$OWNED_JOIN_REAPED" "$OWNED_JOIN_FORCED" "${{OWNED_COMMAND_ROLES[41]}}"
        """)
        self.assertEqual(output, "rc=125 reaped=0 forced=1 registered=http3\n")
        self.assertEqual(artifacts["signals"], "STOP\nTERM\nCONT\nKILL\n")
        self.assertIn("failed", artifacts)
        self.assertNotIn("waits", artifacts)

    def test_reaped_http3_job_is_unregistered_before_later_cleanup(self):
        output, artifacts = self.run_mock("""\
            bounded_owned_job_has_exited() { return 0; }
            HTTP3_SOURCE_PID=42
            printf '42\\t7\\n' > "$TMP_DIR/command.complete"
            join_owned_command 41 "$SECONDS"
            result=$?
            stop_active_workloads
            printf 'rc=%s reaped=%s registered=%s source=%s\\n' \\
              "$result" "$OWNED_JOIN_REAPED" "${OWNED_COMMAND_ROLES[41]:-none}" "$HTTP3_SOURCE_PID"
        """)
        self.assertEqual(output, "rc=7 reaped=1 registered=none source=42\n")
        self.assertEqual(artifacts["waits"], "41\n")
        self.assertNotIn("signals", artifacts)
        self.assertNotIn("failed", artifacts)

    def test_unassisted_supervisor_exit_requires_exact_group_drain_receipt(self):
        for receipt in (None, "43\t7\n", "42\t0\n"):
            with self.subTest(receipt=receipt):
                setup = "" if receipt is None else (
                    "printf '%s' " + shlex.quote(receipt) + ' > "$TMP_DIR/command.complete"\n'
                )
                output, artifacts = self.run_mock(setup + """\
                    bounded_owned_job_has_exited() { return 0; }
                    join_owned_command 41 "$SECONDS"
                    result=$?
                    printf 'rc=%s reaped=%s registered=%s\\n' \\
                      "$result" "$OWNED_JOIN_REAPED" "${OWNED_COMMAND_ROLES[41]:-none}"
                """)
                self.assertEqual(output, "rc=125 reaped=1 registered=none\n")
                self.assertEqual(artifacts["waits"], "41\n")
                self.assertIn("failed", artifacts)
                self.assertNotIn("signals", artifacts)

    def test_logger_cannot_claim_join_after_failed_cleanup(self):
        output, artifacts = self.run_mock("""\
            LOG_PID=41 LOG_STREAM_ALIVE_END=0 LOG_STREAM_JOINED=0
            owned_command_source_is_alive() { return 0; }
            bounded_signal_owned_identity() { return 1; }
            stop_log_capture
            printf 'alive=%s joined=%s pid=%s issues=%s\\n' \\
              "$LOG_STREAM_ALIVE_END" "$LOG_STREAM_JOINED" "$LOG_PID" "${#ISSUES[@]}"
        """)
        self.assertEqual(output, "alive=1 joined=0 pid=41 issues=1\n")
        self.assertIn("failed", artifacts)
        self.assertNotIn("waits", artifacts)

    def test_forced_but_proven_exit_is_not_reported_as_normal_success(self):
        output, artifacts = self.run_mock(f"""\
            bounded_collect_owned_tree() {{ printf '41\\t%s\\n' {'a' * 64}; }}
            bounded_owned_job_has_exited() {{ [[ -e "$TMP_DIR/exited" ]]; }}
            bounded_owned_tree_has_exited() {{ [[ -e "$TMP_DIR/exited" ]]; }}
            bounded_signal_owned_identity() {{
              [[ "$3" != KILL ]] || : > "$TMP_DIR/exited"
              return 0
            }}
            join_owned_command 41 "$SECONDS" stop 1
            result=$?
            printf 'rc=%s reaped=%s forced=%s count=%s\\n' \\
              "$result" "$OWNED_JOIN_REAPED" "$OWNED_JOIN_FORCED" "$ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT"
        """)
        self.assertEqual(output, "rc=124 reaped=1 forced=1 count=1\n")
        self.assertEqual(artifacts["waits"], "41\n")
        self.assertNotIn("failed", artifacts)


def passing_status():
    values = {
        "complete": "1", "passed": "1", "exit_code": "0",
        "udp_probe_attempt_count": "9", "udp_probe_pass_count": "9",
        "udp_pressure_log_checked": "1", "rust_udp_drop_transitions": "1",
        "rust_udp_resume_transitions": "1", "swift_udp_staging_drop_samples": "0",
        "log_stream_started": "1", "log_stream_alive_end": "1",
        "log_stream_joined": "1", "profile_restored": "1",
        "dial9_baseline_max_index": "7", "callback_generation": "modern",
        "dial9_required_flow_id": "103", "dial9_current_segment_count": "1",
        "dial9_required_pair_count": "132", "dial9_required_close_reason": "1",
        "dial9_required_close_age_ms": "900", "dial9_required_bytes_in": "0",
        "dial9_required_bytes_out": "0", "provider_pid": "9001",
        "provider_identity": DIGEST, "provider_identity_stable": "1",
        "http3_source_pid": "2001", "http3_flow_id": "109",
        "http3_remote_endpoint": "1.1.1.1:443", "pressure_probe_attempted": "1",
        "pressure_probe_passed": "1", "pressure_drop_transitions": "1",
        "pressure_resume_transitions": "1", "pressure_drop_reasons": "global_bytes",
        "pressure_recovered_reasons": "global_bytes", "run_uuid": RUN_UUID,
        "run_start_epoch_ms": "1000", "run_end_epoch_ms": "5000",
        "evidence_kind": "modern_udp", "provider_generation_identity": DIGEST,
        "producer_sources_sha256": DIGEST,
        "engine_generations_sha256": DIGEST, "http3_request_count": "12",
        "http3_pass_count": "12", "http3_flow_count": "12",
        "http3_duration_ms": "2500", "http3_min_concurrent": "4",
        "http3_intercept_passed": "1", "http3_intercept_source_pid": "3500",
        "http3_intercept_flow_id": "2500", "http3_intercept_provider_generation": "8",
        "http3_intercept_local_endpoint": "192.0.2.1:54000",
        "http3_intercept_remote_endpoint": "1.1.1.1:443",
        "echo_socket_count": "128", "echo_datagrams_per_socket": "1",
        "echo_payload_bytes": "1200", "echo_expected_count": "128",
        "echo_exact_echo_count": "128", "echo_flow_count": "128",
        "echo_payload_set_sha256": DIGEST, "echo_endpoint": "127.0.0.1:44444",
        "echo_source_pid": "2002", "pressure_datagram_count": "512",
        "pressure_payload_bytes": "4096", "pressure_expected_bytes": "2097152",
        "concurrent_load_deadline_seconds": "180", "concurrent_load_timed_out": "0",
        "active_workload_forced_termination_count": "0",
        "passthrough_dns_source_pid": "1001", "passthrough_dns_flow_id": "101",
        "control_dns_source_pid": "1002", "control_dns_flow_id": "102",
        "ntp_source_pid": "1003", "ntp_flow_id": "103",
        "pressure_source_pid": "1004", "pressure_flow_id": "104",
        "blocked_dns_source_pid": "1005", "blocked_dns_flow_id": "105",
        "recovery_ntp_source_pid": "1006", "recovery_ntp_flow_id": "106",
        "dial9_required_close_reason_name": "shutdown",
        "dial9_close_age_bound_ms": "5000", "dial9_requirements_sha256": DIGEST,
        "dial9_requirement_count": "132", "dial9_matched_requirement_count": "132",
        "schema_version": "6", "schema_complete": "1",
    }
    keys = ["complete", "passed", "exit_code"]
    keys.extend(key for key in values if key not in {*keys, "schema_complete"})
    keys.append("schema_complete")
    return [f"{key}\t{values[key]}\n" for key in keys]


def replace(lines, key, value):
    return [f"{key}\t{value}\n" if line.startswith(key + "\t") else line for line in lines]


def _write_status(directory, overrides):
    lines = passing_status()
    for key, value in overrides.items():
        lines = replace(lines, key, str(value))
    (directory / "udp-evidence-status.tsv").write_text("".join(lines))


def _decision(run_uuid, provider_pid, generation, action, flow_id, remote, local, app, pid):
    return (
        f"udp_e2e_decision run_uuid={run_uuid} provider_pid={provider_pid} "
        f"provider_generation={generation} rama_decision={action} flow_id={flow_id} "
        f"remote_endpoint={remote} local_endpoint={local} source_app={app} source_pid={pid}"
    )


def probe_receipt_fixture(label, source_pid, endpoint, *, start_epoch_ms=1100, run_uuid=RUN_UUID):
    """An ordinary captured request/response, independent of the replay helper."""
    protocol = "ntp" if label in ("ntp", "recovery") else "dns"
    if protocol == "dns":
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"
        request = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
        response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question
        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
    else:
        request = bytes((0x23,)) + bytes(39) + struct.pack("!II", 2_208_988_801, 0)
        response = bytes((0x24, 1)) + bytes(22) + request[40:48] + bytes(16)
    start = start_epoch_ms * 1_000_000 + 1_000_000_000
    timeout = label == "blocked"
    elapsed_ms = 4002 if timeout else 3
    server, port = endpoint.rsplit(":", 1)
    return {
        "schema_version": 1, "kind": "udp_protocol_probe", "run_uuid": run_uuid,
        "probe_label": label, "source_pid": source_pid, "protocol": protocol,
        "endpoint": endpoint, "dns_name": "example.com" if protocol == "dns" else None,
        "expect_no_response": timeout, "timeout_ns": (4 if timeout else 8) * 1_000_000_000,
        "request_hex": request.hex(), "sent_bytes": len(request),
        "response_hex": None if timeout else response.hex(),
        "response_peer": None if timeout else [server, int(port)],
        "receive_outcome": "timeout" if timeout else "response",
        "start_epoch_ms": start_epoch_ms, "end_epoch_ms": start_epoch_ms + elapsed_ms,
        "start_monotonic_ns": start, "receive_started_monotonic_ns": start + 1_000_000,
        "receive_completed_monotonic_ns": start + (elapsed_ms - 1) * 1_000_000,
        "end_monotonic_ns": start + elapsed_ms * 1_000_000,
        "close_error": False, "exit_code": 0, "schema_complete": True,
    }


def http3_receipt_fixture():
    body = b"fl=fixture\nhttp=http/3\ntls=TLSv1.3\n"
    return {
        "schema_version": 1, "kind": "bound_http3_client", "schema_complete": True,
        "run_uuid": RUN_UUID, "source_pid": 3500,
        "url": "https://cloudflare.com/cdn-cgi/trace",
        "library_path": "/opt/homebrew/Cellar/curl/8.20.0/lib/libcurl.4.dylib",
        "library_sha256": "30011f4f6bb8db9f151673d9c2327eb7f81b24f3e3a6e201d0a27bfb31773a14",
        "libcurl_version": "libcurl/8.20.0 OpenSSL/3.6.0 ngtcp2/1.22.1 nghttp3/1.15.0",
        "requested_local_port": 54000, "http_version": 30, "response_code": 200,
        "local_endpoint": "192.0.2.1:54000", "remote_endpoint": "1.1.1.1:443",
        "monotonic_clock": "CLOCK_MONOTONIC",
        "start_epoch_ms": 8600, "end_epoch_ms": 8700,
        "start_monotonic_ns": 9_600_000_000, "end_monotonic_ns": 9_700_000_000,
        "response_body_bytes": len(body), "response_body_sha256": hashlib.sha256(body).hexdigest(),
        "passed": True, "exit_code": 0, "error": None,
    }, body


def build_strict_bundle(directory):
    provider_pid = 9001
    unblocked_generation = 7
    blocked_generation = 8
    echo_pid = 2002
    echo_endpoint = "127.0.0.1:44444"
    echo_digest = DIGEST
    echo_endpoints = [f"127.0.0.1:{50000 + index}" for index in range(128)]
    echo_flows = [1000 + index for index in range(128)]
    lines = [
        _decision(RUN_UUID, provider_pid, 7, "passthrough", 101, "1.1.1.1:53", "127.0.0.1:41001", "com.apple.python3", 1001),
        _decision(RUN_UUID, provider_pid, 7, "intercept", 103, "162.159.200.1:123", "127.0.0.1:41003", "com.apple.python3", 1003),
        _decision(RUN_UUID, provider_pid, 7, "passthrough", 102, "8.8.8.8:53", "127.0.0.1:41002", "com.apple.python3", 1002),
    ]
    lines.extend(
        _decision(RUN_UUID, provider_pid, 7, "intercept", flow_id, echo_endpoint,
                  endpoint, "com.apple.python3", echo_pid)
        for flow_id, endpoint in zip(echo_flows, echo_endpoints)
    )
    lines.extend([
        _decision(RUN_UUID, provider_pid, 7, "intercept", 104, "162.159.200.1:123", "127.0.0.1:41004", "com.apple.python3", 1004),
        'UDP ingress pressure dropped datagram flow_id=104 pressure="global_bytes" cumulative_drops=1 global_retained_bytes=4096 global_max_retained_bytes=4096',
        'UDP ingress pressure resumed flow flow_id=104 pressure="global_bytes" cumulative_resumptions=1 global_retained_bytes=0 global_max_retained_bytes=4096',
        _decision(RUN_UUID, provider_pid, 7, "intercept", 106, "162.159.200.1:123", "127.0.0.1:41006", "com.apple.python3", 1006),
    ])
    h3_pids = list(range(3000, 3006))
    h3_flows = list(range(2000, 2006))
    lines.extend(
        _decision(RUN_UUID, provider_pid, 7, "passthrough", flow_id, "1.1.1.1:443",
                  f"127.0.0.1:{52000 + index}", "com.apple.nscurl", pid)
        for index, (flow_id, pid) in enumerate(zip(h3_flows, h3_pids))
    )
    lines.append(
        _decision(RUN_UUID, provider_pid, 8, "blocked", 105, "8.8.8.8:53",
                  "127.0.0.1:41005", "com.apple.python3", 1005)
    )
    lines.append(
        _decision(RUN_UUID, provider_pid, 8, "intercept", 2500, "1.1.1.1:443",
                  "192.0.2.1:54000", "com.apple.python3", 3500)
    )
    (directory / "provider.log").write_text("\n".join(lines) + "\n")
    probe_results = ["label\tsource_pid\texit_code\n"]
    for label, pid, endpoint, started in (
        ("passthrough", 1001, "1.1.1.1:53", 1100),
        ("ntp", 1003, "162.159.200.1:123", 1200),
        ("control", 1002, "8.8.8.8:53", 1300),
        ("recovery", 1006, "162.159.200.1:123", 1700),
        ("blocked", 1005, "8.8.8.8:53", 4500),
    ):
        value = probe_receipt_fixture(label, pid, endpoint, start_epoch_ms=started)
        (directory / f"udp-probe-{label}.json").write_text(json.dumps(value) + "\n")
        probe_results.append(f"{label}\t{pid}\t0\n")
    (directory / "udp-probe-results.tsv").write_text("".join(probe_results))

    phase_rows = (
        ("schema_version", 2), ("unblocked_start_line", 0),
        ("udp_error_start_line", 0), ("passthrough_start_line", 0),
        ("passthrough_end_line", 1), ("ntp_start_line", 1), ("ntp_end_line", 2),
        ("control_start_line", 2), ("control_end_line", 3),
        ("pressure_start_line", 3), ("pressure_end_line", 134),
        ("echo_start_line", 3), ("echo_end_line", 134),
        ("recovery_start_line", 134), ("recovery_end_line", 135),
        ("http3_start_line", 135), ("http3_end_line", 141),
        ("blocked_profile_start_line", 141), ("blocked_start_line", 141),
        ("blocked_end_line", 142), ("http3_intercept_start_line", 142),
        ("http3_intercept_end_line", 143), ("provider_log_end_line", 143),
        ("schema_complete", 1),
    )
    (directory / "provider-log-phases.tsv").write_text(
        "".join(f"{key}\t{value}\n" for key, value in phase_rows)
    )

    client = {
        "schema_version": 2, "kind": "controlled_echo_client", "run_uuid": RUN_UUID,
        "endpoint": echo_endpoint, "socket_count": 128, "datagrams_per_socket": 1,
        "payload_bytes": 1200, "expected_count": 128, "sent_count": 128,
        "received_count": 128, "exact_echo_count": 128, "unique_echo_count": 128,
        "independent_socket_count": 128, "local_endpoints": echo_endpoints,
        "socket_endpoints": [[index, endpoint] for index, endpoint in enumerate(echo_endpoints)],
        "local_endpoint_set_sha256": hashlib.sha256("\n".join(echo_endpoints).encode()).hexdigest(),
        "payload_set_sha256": echo_digest, "echo_set_sha256": echo_digest,
        "error_count": 0, "passed": True, "schema_complete": True,
        "interval_ms": 0, "start_epoch_ms": 1500, "end_epoch_ms": 1501,
        "start_monotonic_ns": 1000000000, "end_monotonic_ns": 1001000000,
        "packet_timings_ns": [[index, 0, 1000000000, 1001000000] for index in range(128)],
    }
    server = {
        "schema_version": 2, "kind": "controlled_echo_server", "run_uuid": RUN_UUID,
        "endpoint": echo_endpoint, "expected_count": 128, "received_count": 128,
        "echo_count": 128, "duplicate_count": 0, "malformed_count": 0,
        "peer_mismatch_count": 0,
        "socket_peers": [[index, endpoint] for index, endpoint in enumerate(echo_endpoints)],
        "payload_set_sha256": echo_digest, "passed": True, "schema_complete": True,
    }
    ready = {
        "schema_version": 2, "run_uuid": RUN_UUID, "endpoint": echo_endpoint,
        "server_pid": 4000, "schema_complete": True,
    }
    for name, value in (
        ("controlled-echo-client.json", client), ("controlled-echo-server.json", server),
        ("controlled-echo-ready.json", ready),
    ):
        (directory / name).write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    (directory / "controlled-echo-client.log").write_text(
        f"QUIC-shaped UDP controlled echo ok: sockets=128 datagrams=128 bytes=1200 sha256={echo_digest}\n"
    )
    (directory / "controlled-echo-server.log").write_bytes(b"")
    (directory / "echo-identities.tsv").write_text("".join(
        f"7\t{flow_id}\t{endpoint}\n" for flow_id, endpoint in zip(echo_flows, echo_endpoints)
    ))

    pid_rows = []
    result_rows = ["round\tworker\tsource_pid\texit_code\thttp3_marker\tsha256\n"]
    for index, pid in enumerate(h3_pids):
        round_number, worker = index // 2 + 1, index % 2 + 1
        pid_rows.append(f"{round_number}\t{worker}\t{pid}\n")
        output = f"http=http/3\nround={round_number} worker={worker}\n".encode()
        (directory / f"http3-{round_number}-{worker}.log").write_bytes(output)
        result_rows.append(
            f"{round_number}\t{worker}\t{pid}\t0\t1\t{hashlib.sha256(output).hexdigest()}\n"
        )
    (directory / "http3-pids.tsv").write_text("".join(pid_rows))
    (directory / "http3-results.tsv").write_text("".join(result_rows))
    (directory / "http3-round-results.tsv").write_text(
        "round\texpected_workers\tbarrier_release_epoch_ms\tpre_release_alive\n"
        "1\t2\t2000\t2\n2\t2\t3000\t2\n3\t2\t4000\t2\n"
    )
    (directory / "http3-timing.tsv").write_text(
        "schema_version\t1\nstart_monotonic_ms\t100\nend_monotonic_ms\t2600\n"
        "duration_ms\t2500\nrounds\t3\nconcurrency\t2\nschema_complete\t1\n"
    )
    (directory / "http3-endpoints.txt").write_text("1.1.1.1:443\n")
    receipt, body = http3_receipt_fixture()
    (directory / "http3-url.txt").write_text(receipt["url"] + "\n")
    (directory / "http3-intercept-client.json").write_text(json.dumps(receipt) + "\n")
    (directory / "http3-intercept-body.txt").write_bytes(body)
    (directory / "http3-intercept-result.tsv").write_text("source_pid\texit_code\n3500\t0\n")

    requirement_rows = [
        "label\tprovider_pid\tprovider_generation\tflow_id\tprotocol\tsource_pid\tclose_reason\tmin_bytes_in\tmax_bytes_in\tmin_bytes_out\tmax_bytes_out\n",
        "ntp\t9001\t7\t103\t2\t1003\t1\t48\t48\t48\t48\n",
        "pressure\t9001\t7\t104\t2\t1004\t1\t4096\t2093056\t0\t0\n",
        "recovery-ntp\t9001\t7\t106\t2\t1006\t1\t48\t48\t48\t48\n",
    ]
    requirement_rows.extend(
        f"echo-{index}\t9001\t7\t{flow_id}\t2\t2002\t1\t1200\t1200\t1200\t1200\n"
        for index, flow_id in enumerate(echo_flows)
    )
    requirement_rows.append("http3-intercept\t9001\t8\t2500\t2\t3500\t1\t1\t16777216\t1\t16777216\n")
    requirements = "".join(requirement_rows)
    (directory / "dial9-requirements.tsv").write_text(requirements)

    restore_messages = [
        "container app launched", "temporary test UDP pass-through ports=",
        "temporary test UDP blocked endpoints=",
        "udp_e2e_restore_profile=persisted-default evidence_identity=absent",
        "status=connected",
        "udp_e2e_restart=begin launch-time UDP policy overrides requested",
        "status transition connected -> disconnecting",
        "status transition disconnecting -> disconnected",
        "proxy stopped after UDP policy update", "calling startVPNTunnel",
        "transparent proxy start requested",
        "status transition disconnected -> connecting",
        "status transition connecting -> connected",
    ]
    restore_slice = "".join(
        f"[1970-01-01T00:00:09Z] INFO: {message}\n" for message in restore_messages
    )
    (directory / "restore-container.log").write_text(restore_slice)
    (directory / "restore.log").write_text(
        "restore_invocation schema=1 mode=dev reset_profile=0 "
        "udp_passthrough_ports=empty udp_blocked_endpoints=empty evidence_identity=absent\n"
    )
    restore_rows = (
        ("schema_version", 1), ("run_uuid", RUN_UUID), ("provider_pid", provider_pid),
        ("replaced_provider_generation", blocked_generation),
        ("restore_started_epoch_ms", 9000), ("restore_completed_epoch_ms", 9500),
        ("container_start_line", 100), ("container_end_line", 113),
        ("slice_line_count", 13),
        ("slice_sha256", hashlib.sha256(restore_slice.encode()).hexdigest()),
        ("profile", "persisted-default"), ("evidence_identity", "absent"),
        ("fresh_connected", 1), ("schema_complete", 1),
    )
    (directory / "restore-receipt.tsv").write_text(
        "".join(f"{key}\t{value}\n" for key, value in restore_rows)
    )
    for name in (
        "source-test_modern_udp_flow.sh",
        "source-modern_udp_e2e_probe.py",
        "source-install_tproxy_app_bundle.sh",
        "source-modern_udp_evidence.py",
        "source-soak_pressure_log.py",
        "source-signed_run_evidence.py",
    ):
        (directory / name).write_text(f"fixture bytes for {name}\n")
    producer_digest = producer_sources_sha256(directory)
    (directory / "workload-claims.tsv").write_text(
        "evidence_kind\tmodern_udp\n"
        f"run_uuid\t{RUN_UUID}\n"
        "dial9_diagnostic_only\t0\n"
        "dial9_workload_coverage\t1\n"
        "dial9_claim\texact-workload\n"
        "quic_shaped_not_valid_quic\t1\n"
        "echo_socket_count\t128\n"
        "echo_exact_echo_count\t128\n"
        "http3_request_count\t6\n"
        "http3_pass_count\t6\n"
        "http3_intercept_passed\t1\n"
        "dial9_requirement_count\t132\n"
        "dial9_matched_requirement_count\t132\n"
        f"producer_sources_sha256\t{producer_digest}\n"
        "schema_complete\t1\n"
    )
    crashes = directory / "crashes"
    crashes.mkdir()
    (crashes / "crash-snapshot.tsv").write_text(
        "schema_version\t2\n"
        f"run_uuid\t{RUN_UUID}\n"
        f"provider_generation_identity\t{DIGEST}\n"
        "since_epoch_ms\t1000\n"
        "snapshot_epoch_ms\t11000\n"
        "process_names\torg.ramaproxy.example.tproxy.dev.provider\n"
        "crash_count\t0\n"
        f"crash_names_sha256\t{hashlib.sha256(b'').hexdigest()}\n"
        "schema_complete\t1\n"
    )
    generation_tail = f"9001|500|500000|{'c' * 40}|{DIGEST}|{'b' * 64}"
    (directory / "provider-generation-samples.tsv").write_text(
        "schema_version\t1\n"
        f"provider_generation_identity\t{DIGEST}\n"
        "running_pid\t9001\n"
        "running_start_epoch_ms\t500\n"
        "running_start_epoch_us\t500000\n"
        f"running_dynamic_cdhash\t{'c' * 40}\n"
        f"running_command_sha256\t{DIGEST}\n"
        f"running_executable_path_sha256\t{'b' * 64}\n"
        "cadence_ms\t2000\n"
        "max_gap_ms\t5000\n"
        "sample_count\t5\n"
        f"sample_000001\t900|{generation_tail}\n"
        f"sample_000002\t3000|{generation_tail}\n"
        f"sample_000003\t6000|{generation_tail}\n"
        f"sample_000004\t9000|{generation_tail}\n"
        f"sample_000005\t11000|{generation_tail}\n"
        "schema_complete\t1\n"
    )
    engine_digest = hashlib.sha256(b"9001:7:8").hexdigest()
    _write_status(directory, {
        "run_end_epoch_ms": 10000,
        "http3_source_pid": 3000, "http3_flow_id": 2000,
        "http3_request_count": 6, "http3_pass_count": 6, "http3_flow_count": 6,
        "http3_min_concurrent": 2, "echo_source_pid": echo_pid,
        "engine_generations_sha256": engine_digest,
        "producer_sources_sha256": producer_digest,
        "dial9_requirements_sha256": hashlib.sha256(requirements.encode()).hexdigest(),
    })


def reseal_test_manifest(directory):
    rows = []
    for path in sorted(directory.iterdir(), key=lambda value: value.name):
        if path.name != "evidence-manifest.tsv" and path.is_file():
            content = path.read_bytes()
            rows.append(f"{path.name}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}\n")
    (directory / "evidence-manifest.tsv").write_text("".join(rows))


HTTP3_FIXTURE_RECEIPT, HTTP3_FIXTURE_BODY = http3_receipt_fixture()


class BoundHttp3ReceiptTests(unittest.TestCase):
    def replay(self, value, body=HTTP3_FIXTURE_BODY):
        expected = HTTP3_FIXTURE_RECEIPT
        return udp_probe.replay_http3_receipt(
            value, body, expected['run_uuid'], expected['source_pid'], expected['url'])

    def test_offline_receipt_and_rejection_boundaries(self):
        receipt = dict(HTTP3_FIXTURE_RECEIPT)
        # Replay must remain offline even when the claimed library is absent.
        with mock.patch.object(C, 'CDLL', side_effect=AssertionError('native load in replay')):
            self.assertEqual(self.replay(receipt), 0)
        integer_fields = ('schema_version', 'source_pid', 'requested_local_port',
                          'http_version', 'response_code', 'start_epoch_ms', 'end_epoch_ms',
                          'start_monotonic_ns', 'end_monotonic_ns', 'response_body_bytes', 'exit_code')
        mutations = [(key, True) for key in integer_fields]
        mutations += [
            ('run_uuid', 'bad'), ('source_pid', receipt['source_pid'] + 1),
            ('url', receipt['url'] + 'x'), ('kind', 'udp_protocol_probe'),
            ('monotonic_clock', 'mach_absolute_time'), ('schema_complete', 1),
            ('passed', 1), ('passed', False), ('error', ''), ('exit_code', 20),
            ('library_path', '/'), ('library_path', 'relative'), ('library_path', '/a/../b'),
            ('library_path', '/a\nb'), ('library_sha256', 'A' * 64),
            ('libcurl_version', 'notcurl'), ('libcurl_version', 'libcurl/8.20.0wrong'),
            ('requested_local_port', 0), ('requested_local_port', 1),
            ('local_endpoint', '0.0.0.0:54000'), ('local_endpoint', '192.0.2.1:054000'),
            ('local_endpoint', 'unavailable'), ('local_endpoint', '[::1]:54000'),
            ('remote_endpoint', '1.1.1.1:53'), ('remote_endpoint', '0.0.0.0:443'),
            ('http_version', 3), ('response_code', 204),
            ('response_body_bytes', len(HTTP3_FIXTURE_BODY) + 1), ('response_body_sha256', '0' * 64),
            ('start_monotonic_ns', 0), ('end_monotonic_ns', receipt['start_monotonic_ns'] - 1),
            ('end_monotonic_ns', receipt['start_monotonic_ns'] + 30_000_000_001),
            ('end_epoch_ms', receipt['end_epoch_ms'] + 3000),
        ]
        for key, value in mutations:
            with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                self.replay(dict(receipt, **{key: value}))
        for body in (b'', bytearray(HTTP3_FIXTURE_BODY), b'http=http/30\n',
                     b'http=http/3\nhttp=http/3\n', b'x' * (udp_probe.HTTP3_BODY_MAX_BYTES + 1)):
            with self.subTest(body_size=len(body)), self.assertRaises(ValueError):
                self.replay(dict(receipt, response_body_bytes=len(body),
                                 response_body_sha256=hashlib.sha256(body).hexdigest()), body)
        for changed in (dict(receipt, extra=1),
                        {key: value for key, value in receipt.items() if key != 'error'}):
            with self.subTest(keys=set(changed)), self.assertRaises(ValueError):
                self.replay(changed)
        with self.assertRaises(ValueError):
            self.replay(receipt, HTTP3_FIXTURE_BODY + b'x')

    def test_bounded_client_lifecycle(self):
        modes = ('success', 'global_init_error', 'handle_error', 'bind_error',
                 'setopt_error', 'perform_error', 'oversized_body', 'callback_error',
                 'wrong_protocol', 'cleanup_error')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'libcurl.dylib'
            path.write_bytes(b'mock library: never loaded')
            for mode in modes:
                with self.subTest(mode=mode):
                    options = {}
                    library = SimpleNamespace()
                    for name, result in (
                        ('curl_global_init', 0), ('curl_global_cleanup', None),
                        ('curl_easy_init', 123), ('curl_easy_cleanup', None),
                        ('curl_easy_setopt', 0), ('curl_easy_getinfo', 0),
                        ('curl_easy_perform', 0), ('curl_version', b'libcurl/8.20.0 mock'),
                    ):
                        setattr(library, name, mock.Mock(return_value=result))
                    selection = mock.MagicMock()
                    selection.__enter__.return_value = selection
                    selection.getsockname.return_value = ('0.0.0.0', 54000)
                    if mode == 'global_init_error': library.curl_global_init.return_value = 2
                    if mode == 'handle_error': library.curl_easy_init.return_value = None
                    if mode == 'bind_error': selection.bind.side_effect = OSError('mock bind failure')
                    if mode == 'cleanup_error':
                        library.curl_easy_cleanup.side_effect = RuntimeError('mock cleanup failure')

                    def setopt(handle, option, value):
                        options[option] = value
                        return 48 if mode == 'setopt_error' else 0
                    library.curl_easy_setopt.side_effect = setopt

                    def perform(handle):
                        # The selection socket must close before traffic, and the
                        # transfer must use that one port with no HTTP fallback.
                        self.assertEqual(selection.__exit__.call_count, 1)
                        selection.bind.assert_called_once_with(('0.0.0.0', 0))
                        self.assertEqual({key: options[key].value for key in (84, 139, 140, 113, 155, 156)},
                                         {84: 31, 139: 54000, 140: 1, 113: 1, 155: 15000, 156: 10000})
                        self.assertEqual(options[10004].value, b'')
                        self.assertEqual(options[10177].value, b'*')
                        self.assertEqual(library.curl_easy_setopt.argtypes, [C.c_void_p, C.c_int])
                        self.assertEqual(library.curl_easy_getinfo.argtypes, [C.c_void_p, C.c_int])
                        if mode == 'perform_error': return 28
                        if mode == 'oversized_body':
                            self.assertEqual(options[20011](None, 1, udp_probe.HTTP3_BODY_MAX_BYTES + 1, None), 0)
                            return 23
                        if mode == 'callback_error':
                            with mock.patch.object(C, 'string_at', side_effect=ValueError('mock read failure')):
                                self.assertEqual(options[20011](None, 1, 1, None), 0)
                            return 23
                        buffer = C.create_string_buffer(HTTP3_FIXTURE_BODY)
                        self.assertEqual(options[20011](C.addressof(buffer), 1, len(HTTP3_FIXTURE_BODY), None),
                                         len(HTTP3_FIXTURE_BODY))
                        return 0
                    library.curl_easy_perform.side_effect = perform

                    def getinfo(handle, info, pointer):
                        pointer._obj.value = {
                            0x200000 + 46: 2 if mode == 'wrong_protocol' else 30,
                            0x200000 + 2: 200, 0x200000 + 42: 54000, 0x200000 + 40: 443,
                            0x100000 + 41: b'192.0.2.1', 0x100000 + 32: b'1.1.1.1',
                        }[info]
                        return 0
                    library.curl_easy_getinfo.side_effect = getinfo
                    receipt_path, body_path = root / (mode + '.json'), root / (mode + '.body')
                    with mock.patch.object(C, 'CDLL', return_value=library), \
                            mock.patch.object(udp_probe.socket, 'socket', return_value=selection), \
                            contextlib.redirect_stdout(io.StringIO()):
                        if mode == 'success':
                            udp_probe.http3_probe(path, HTTP3_FIXTURE_RECEIPT['url'],
                                                  HTTP3_FIXTURE_RECEIPT['run_uuid'], receipt_path, body_path)
                        else:
                            with self.assertRaises(RuntimeError):
                                udp_probe.http3_probe(path, HTTP3_FIXTURE_RECEIPT['url'],
                                                      HTTP3_FIXTURE_RECEIPT['run_uuid'], receipt_path, body_path)
                    receipt = udp_probe.read_http3_receipt(receipt_path)
                    body = udp_probe.read_http3_body(body_path)
                    self.assertEqual(set(receipt), udp_probe.HTTP3_RECEIPT_KEYS)
                    self.assertEqual(receipt['passed'], mode == 'success')
                    self.assertEqual(receipt['exit_code'], 0 if mode == 'success' else 20)
                    self.assertEqual(receipt['response_body_bytes'], len(body))
                    self.assertEqual(receipt['response_body_sha256'], hashlib.sha256(body).hexdigest())
                    self.assertLessEqual(len(body), udp_probe.HTTP3_BODY_MAX_BYTES)
                    self.assertEqual(library.curl_easy_cleanup.call_count,
                                     0 if mode in ('global_init_error', 'handle_error') else 1)
                    self.assertEqual(library.curl_global_cleanup.call_count, 0 if mode == 'global_init_error' else 1)
                    if mode in ('global_init_error', 'handle_error', 'bind_error', 'setopt_error'):
                        library.curl_easy_perform.assert_not_called()
                    if mode == 'success':
                        self.assertEqual(udp_probe.replay_http3_receipt(
                            receipt, body, receipt['run_uuid'], os.getpid(), receipt['url']), 0)

    def test_bounded_files_and_no_replace_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = root / 'body'
            body.write_bytes(HTTP3_FIXTURE_BODY)
            duplicate = root / 'duplicate.json'
            duplicate.write_text(json.dumps(HTTP3_FIXTURE_RECEIPT)[:-1] + ',"exit_code":0}')
            with self.assertRaises(ValueError): udp_probe.read_http3_receipt(duplicate)
            symlink = root / 'symlink'
            symlink.symlink_to(body)
            with self.assertRaises(OSError): udp_probe.read_http3_body(symlink)
            oversized = root / 'oversized'
            oversized.write_bytes(b'x' * (udp_probe.HTTP3_BODY_MAX_BYTES + 1))
            with self.assertRaises(ValueError): udp_probe.read_http3_body(oversized)
            with self.assertRaises(FileExistsError): udp_probe._publish_http3_file(body, b'overwrite')
            self.assertEqual(body.read_bytes(), HTTP3_FIXTURE_BODY)
            self.assertFalse(list(root.glob('.http3-probe-*')))



class DnsWireValidationTests(unittest.TestCase):
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    address = bytes((93, 184, 216, 34))

    @staticmethod
    def record(owner, data, kind=1, record_class=1, ttl=60):
        return owner + struct.pack("!HHIH", kind, record_class, ttl, len(data)) + data

    def response(self, answers, authority=(), additional=(), *, flags=0x8180, question=None):
        return (struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), len(authority), len(additional))
                + (self.question if question is None else question)
                + b"".join((*answers, *authority, *additional)))

    def validate(self, response):
        udp_probe.validate_dns_response(self.query, response, ("8.8.8.8", 53), "8.8.8.8")

    def test_accepts_complete_compressed_uncompressed_and_case_insensitive_answers(self):
        for owner, question in ((b"\xc0\x0c", self.question),
                                (b"\x07example\x03com\0", self.question),
                                (b"\x07EXAMPLE\x03COM\0", self.question.upper())):
            with self.subTest(owner=owner, question=question):
                self.validate(self.response([self.record(owner, self.address)], question=question))

    def test_accepts_cname_chain_and_pointer_to_prior_compressed_rdata(self):
        alias = b"\x05alias\xc0\x0c"
        alias_offset = len(self.query) + 12  # first answer's CNAME RDATA
        alias_pointer = struct.pack("!H", 0xC000 | alias_offset)
        self.validate(self.response([
            self.record(b"\xc0\x0c", alias, kind=5),
            self.record(alias_pointer, self.address),
        ]))
        first = b"\x05first\x07example\x03com\0"
        second = b"\x06second\x07example\x03com\0"
        # Record ordering is immaterial to the answer's CNAME chain.
        self.validate(self.response([
            self.record(second, self.address),
            self.record(first, second, kind=5),
            self.record(b"\xc0\x0c", first, kind=5),
        ]))

    def test_accepts_protocol_name_bound_and_long_prior_pointer_chain(self):
        longest_name = (b"\x3f" + b"a" * 63) * 3 + b"\x3d" + b"b" * 61 + b"\0"
        self.assertEqual(len(longest_name), 255)
        target = struct.pack("!H", 0xC000 | (len(self.query) + 12))
        self.validate(self.response([
            self.record(b"\xc0\x0c", longest_name, 5),
            self.record(target, self.address),
        ]))
        records = []
        previous, offset = 12, len(self.query)
        for _ in range(1000):
            record = self.record(struct.pack("!H", 0xC000 | previous), self.address)
            records.append(record)
            previous, offset = offset, offset + len(record)
        self.validate(self.response(records))

    def test_accepts_opaque_authority_additional_and_bounded_edns_options(self):
        opt = self.record(b"\0", struct.pack("!HH", 65001, 3) + b"abc", 41, 1232, 0)
        unknown = self.record(b"\0", bytes(600), 65280)
        response = self.response([self.record(b"\xc0\x0c", self.address)],
                                 [self.record(b"\xc0\x0c", b"\x02ns\xc0\x0c", 2)],
                                 [unknown, opt])
        self.assertGreater(len(response), 512)
        self.validate(response)

    def test_rejects_every_truncated_prefix_and_unframed_trailing_bytes(self):
        response = self.response([self.record(b"\xc0\x0c", self.address)])
        for length in range(len(response)):
            with self.subTest(length=length), self.assertRaises(RuntimeError):
                self.validate(response[:length])
        with self.assertRaisesRegex(RuntimeError, "trailing"):
            self.validate(response + b"\0")

    def test_rejects_opcode_tc_and_mismatched_question_or_answer(self):
        answer = self.record(b"\xc0\x0c", self.address)
        cases = {
            "opcode": self.response([answer], flags=0x8980),
            "TC": self.response([answer], flags=0x8380),
            "question-name": self.response([answer], question=b"\x07invalid" + self.question[8:]),
            "question-type": self.response([answer], question=self.question[:-4] + b"\0\x1c\0\x01"),
            "question-class": self.response([answer], question=self.question[:-2] + b"\0\x03"),
            "answer-name": self.response([self.record(b"\x07invalid\x03com\0", self.address)]),
            "answer-class": self.response([self.record(b"\xc0\x0c", self.address, record_class=3)]),
            "only-additional-A": self.response([self.record(b"\xc0\x0c", b"\x01x", 16)], additional=[answer]),
            "CNAME-without-A": self.response([self.record(b"\xc0\x0c", b"\x05alias\xc0\x0c", 5)]),
            "CNAME-cycle": self.response([self.record(b"\xc0\x0c", b"\xc0\x0c", 5)]),
        }
        for case, response in cases.items():
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                self.validate(response)

    def test_rejects_invalid_record_lengths_and_name_compression(self):
        answer = self.record(b"\xc0\x0c", self.address)
        start = len(self.query)
        cases = {
            "A-length": self.response([self.record(b"\xc0\x0c", self.address[:3])]),
            "CNAME-length": self.response([self.record(b"\xc0\x0c", b"\xc0\x0c\0", 5)]),
            "CNAME-label-crosses-rdata": self.response([
                self.record(b"\xc0\x0c", b"\x05abc", 5), answer]),
            "CNAME-pointer-crosses-rdata": self.response([
                self.record(b"\xc0\x0c", b"\xc0", 5), answer]),
            "self-pointer": self.response([self.record(struct.pack("!H", 0xC000 | start), self.address)]),
            "label-pointer-loop": self.response([
                self.record(b"\x01x" + struct.pack("!H", 0xC000 | start), self.address)]),
            "forward-pointer": self.response([self.record(b"\xff\xff", self.address)]),
            "header-pointer": self.response([self.record(b"\xc0\0", self.address)]),
            "reserved-label": self.response([self.record(b"\x40" + bytes(64) + b"\0", self.address)]),
            "oversized-name": self.response([self.record(
                (b"\x3f" + b"a" * 63) * 3 + b"\x3e" + b"b" * 62 + b"\0", self.address)]),
            "authority-overrun": self.response([answer], authority=[self.record(b"\0", b"abcd", 65280)[:-1]]),
            "additional-overrun": self.response([answer], additional=[self.record(b"\0", b"abcd", 65280)[:-1]]),
        }
        for case, response in cases.items():
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                self.validate(response)

    def test_rejects_malformed_edns_and_extended_error(self):
        answer = self.record(b"\xc0\x0c", self.address)
        opt = self.record(b"\0", b"", 41, 1232, 0)
        cases = (
            [self.record(b"\0", b"", 41, 1232, 1 << 24)],
            [self.record(b"\0", b"\x00", 41, 1232, 0)],
            [self.record(b"\0", struct.pack("!HH", 65001, 4) + b"abc", 41, 1232, 0)],
            [self.record(b"\xc0\x0c", b"", 41, 1232, 0)],
            [opt, opt],
        )
        for records in cases:
            with self.subTest(records=records), self.assertRaises(RuntimeError):
                self.validate(self.response([answer], additional=records))


class ProtocolProbeReceiptTests(unittest.TestCase):
    def capture(self, root, label, *, outcome="response", mutate=None, close_error=False,
                partial_send=False, early_timeout=False, bind_error=False):
        """Mock only our socket and clock; never contact a protocol endpoint."""
        protocol = "ntp" if label in ("ntp", "recovery") else "dns"
        server, port = ("162.159.200.1", 123) if protocol == "ntp" else ("8.8.8.8", 53)
        now = [10_000_000_000]
        sent = []
        received = []
        binds = []
        closes = []
        timeout = 4 if label == "blocked" else 8
        path = root / f"udp-probe-{label}.json"

        class MockSocket:
            def bind(self, endpoint):
                binds.append(endpoint)
                if bind_error:
                    raise OSError("ordinary mocked bind error")

            def settimeout(self, seconds):
                self.timeout = seconds

            def sendto(self, packet, endpoint):
                if binds != [("0.0.0.0", 0)]:
                    raise AssertionError("probe sent before ephemeral bind")
                sent.append((bytes(packet), endpoint))
                now[0] += 1_000_000
                return len(packet) - int(partial_send)

            def recvfrom(self, maximum):
                received.append(maximum)
                now[0] += 1_000_000 if outcome != "timeout" or early_timeout else timeout * 1_000_000_000
                if outcome == "timeout":
                    raise socket.timeout("ordinary mocked timeout")
                if outcome == "error":
                    raise OSError("ordinary mocked socket error")
                packet = sent[0][0]
                if protocol == "dns":
                    response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + packet[12:]
                    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
                else:
                    response = bytes((0x24, 1)) + bytes(22) + packet[40:48] + bytes(16)
                pair = (response, (server, port))
                return mutate(*pair) if mutate else pair

            def close(self):
                closes.append(True)
                if close_error:
                    raise OSError("ordinary mocked close error")

        error = None
        with mock.patch.object(udp_probe.socket, "socket", return_value=MockSocket()), \
                mock.patch.object(udp_probe.time, "clock_gettime_ns", side_effect=lambda _: now[0]), \
                mock.patch.object(udp_probe.time, "time_ns", side_effect=lambda: now[0] + 1_000_000_000_000), \
                mock.patch.object(udp_probe.time, "time", side_effect=lambda: 1000 + now[0] / 1e9), \
                mock.patch("builtins.print"):
            try:
                keywords = dict(run_uuid=RUN_UUID, probe_label=label, result_file=str(path))
                if protocol == "dns":
                    udp_probe.dns_query(server, "example.com", timeout, label == "blocked", **keywords)
                else:
                    udp_probe.ntp_query(server, timeout, **keywords)
            except Exception as caught:
                error = caught
        self.assertEqual(binds, [("0.0.0.0", 0)])
        self.assertEqual(closes, [True])
        self.assertEqual(len(sent), 0 if bind_error else 1)
        if sent:
            self.assertEqual(sent[0][1], (server, port))
        self.assertEqual(received, [] if partial_send or bind_error else [65_535])
        self.assertFalse(list(root.glob(".udp-probe-*.tmp")))
        return path, error

    def replay(self, value):
        return udp_probe.replay_probe_receipt(
            value, RUN_UUID, value["probe_label"], os.getpid(), value["endpoint"]
        )

    def test_all_five_canaries_publish_raw_receipts_and_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label in udp_probe.PROBE_LABELS:
                with self.subTest(label=label):
                    path, error = self.capture(root, label, outcome="timeout" if label == "blocked" else "response")
                    self.assertIsNone(error)
                    value = udp_probe.read_probe_receipt(path)
                    self.assertEqual(self.replay(value), 0)
                    self.assertEqual(len(bytes.fromhex(value["request_hex"])), value["sent_bytes"])
                    self.assertEqual(value["response_hex"] is None, label == "blocked")
                    self.assertEqual(path.stat().st_nlink, 1)

    def test_bind_failure_closes_without_traffic_and_publishes_failure(self):
        for label in udp_probe.PROBE_LABELS:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                path, error = self.capture(Path(temporary), label, bind_error=True)
                self.assertIsInstance(error, OSError)
                value = udp_probe.read_probe_receipt(path)
                self.assertEqual(value["sent_bytes"], 0)
                self.assertEqual(value["receive_outcome"], "not_started")
                self.assertEqual(self.replay(value), udp_probe.PROBE_ERROR_EXIT)

    def test_malformed_packets_and_wrong_peers_preserve_raw_failed_outcomes(self):
        mutations = (
            ("control", "truncated", lambda response, peer: (b"short", peer)),
            ("control", "transaction", lambda response, peer: (bytes((response[0] ^ 1,)) + response[1:], peer)),
            ("control", "response", lambda response, peer: (response[:2] + b"\x01" + response[3:], peer)),
            ("control", "rcode", lambda response, peer: (response[:3] + b"\x83" + response[4:], peer)),
            ("control", "answer", lambda response, peer: (response[:6] + bytes(2) + response[8:], peer)),
            ("control", "peer", lambda response, peer: (response, ("8.8.4.4", peer[1]))),
            ("ntp", "truncated", lambda response, peer: (response[:47], peer)),
            ("ntp", "mode", lambda response, peer: (b"\x23" + response[1:], peer)),
            ("ntp", "stratum", lambda response, peer: (response[:1] + b"\x00" + response[2:], peer)),
            ("recovery", "originate", lambda response, peer: (response[:24] + bytes(8) + response[32:], peer)),
            ("recovery", "peer", lambda response, peer: (response, (peer[0], 124))),
            ("blocked", "malformed", lambda response, peer: (b"short", peer)),
        )
        for label, name, mutation in mutations:
            with self.subTest(label=label, mutation=name), tempfile.TemporaryDirectory() as temporary:
                path, error = self.capture(Path(temporary), label, mutate=mutation)
                self.assertIsInstance(error, RuntimeError)
                self.assertNotIsInstance(error, ProductViolation)
                value = udp_probe.read_probe_receipt(path)
                self.assertEqual(value["receive_outcome"], "response")
                self.assertEqual(self.replay(value), udp_probe.PROBE_ERROR_EXIT)
                value["exit_code"] = 0
                with self.assertRaisesRegex(ValueError, "raw protocol evidence"):
                    self.replay(value)

    def test_timeout_socket_failure_and_block_violation_remain_distinct(self):
        cases = (
            ("control", "timeout", False, False, socket.timeout, 20),
            ("ntp", "error", False, False, OSError, 20),
            ("blocked", "error", True, False, OSError, 20),
            ("ntp", "response", True, False, OSError, 20),
            ("ntp", "response", False, True, RuntimeError, 20),
            ("blocked", "response", False, False, ProductViolation, 10),
            ("blocked", "response", True, False, ProductViolation, 10),
            ("blocked", "timeout", True, False, None, 0),
        )
        for label, outcome, close_error, partial_send, expected_error, expected in cases:
            with self.subTest(case=(label, outcome, close_error, partial_send)), tempfile.TemporaryDirectory() as temporary:
                path, error = self.capture(Path(temporary), label, outcome=outcome,
                                           close_error=close_error, partial_send=partial_send)
                if expected_error is None:
                    self.assertIsNone(error)
                else:
                    self.assertIsInstance(error, expected_error)
                value = udp_probe.read_probe_receipt(path)
                self.assertEqual(self.replay(value), expected)

    def test_incomplete_dns_wire_data_cannot_claim_pass_or_a_block_violation(self):
        cases = (
            ("header-only", lambda response: response[:12]),
            ("truncated-question", lambda response: response[:28]),
            ("truncated-A", lambda response: response[:-1]),
            ("mismatched-question", lambda response: response[:13] + b"invalid" + response[20:]),
        )
        for label in ("passthrough", "control", "blocked"):
            for case, response_fixture in cases:
                with self.subTest(label=label, case=case), tempfile.TemporaryDirectory() as temporary:
                    path, error = self.capture(Path(temporary), label,
                                               mutate=lambda response, peer: (response_fixture(response), peer))
                    self.assertIsInstance(error, RuntimeError)
                    self.assertNotIsInstance(error, ProductViolation)
                    value = udp_probe.read_probe_receipt(path)
                    self.assertEqual(self.replay(value), udp_probe.PROBE_ERROR_EXIT)
                    for claim in (0, udp_probe.PRODUCT_VIOLATION_EXIT):
                        value["exit_code"] = claim
                        with self.assertRaisesRegex(ValueError, "raw protocol evidence"):
                            self.replay(value)

    def test_early_timeout_cannot_supply_block_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.capture(Path(temporary), "blocked", outcome="timeout", early_timeout=True)
            with self.assertRaisesRegex(ValueError, "full timeout"):
                self.replay(udp_probe.read_probe_receipt(path))

    def test_publication_failure_and_duplicate_publication_never_replace_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(udp_probe.os, "link", side_effect=OSError("fixture publication failure")):
                path, error = self.capture(root, "ntp")
            self.assertIsInstance(error, OSError)
            self.assertFalse(path.exists())
            path, error = self.capture(root, "ntp")
            self.assertIsNone(error)
            original = path.read_bytes()
            _, error = self.capture(root, "ntp")
            self.assertIsInstance(error, FileExistsError)
            self.assertEqual(path.read_bytes(), original)

    def test_receipt_reader_rejects_incomplete_duplicate_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            with self.assertRaises(OSError):
                udp_probe.read_probe_receipt(path)
            value = probe_receipt_fixture("ntp", os.getpid(), "162.159.200.1:123")
            content = json.dumps(value)
            for raw in ("", content[:-1], content[:-1] + ',"exit_code":0}',
                        " " * (udp_probe.PROBE_RECEIPT_MAX_BYTES + 1)):
                with self.subTest(length=len(raw)):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        udp_probe.read_probe_receipt(path)


class ModernStatusTests(unittest.TestCase):
    def test_accepts_exact_hardened_status(self):
        self.assertEqual(parse_signed_udp_status_lines(passing_status()), 0)

    def test_rejects_weakened_cardinality_and_generation_evidence(self):
        for key, value in (
            ("echo_flow_count", "63"),
            ("echo_exact_echo_count", "63"),
            ("http3_flow_count", "11"),
            ("http3_duration_ms", "1999"),
            ("dial9_matched_requirement_count", "66"),
            ("engine_generations_sha256", "none"),
            ("concurrent_load_timed_out", "1"),
            ("active_workload_forced_termination_count", "1"),
            ("provider_identity", "b" * 64),
        ):
            with self.subTest(key=key):
                self.assertIsNone(parse_signed_udp_status_lines(replace(passing_status(), key, value)))

        self.assertIsNone(
            parse_signed_udp_status_lines(replace(passing_status(), "echo_socket_count", "127"))
        )

    def test_pressure_window_is_bound_to_run_provider_and_flow(self):
        decision = (
            f"udp_e2e_decision run_uuid={RUN_UUID} provider_pid=9001 "
            "provider_generation=7 rama_decision=intercept flow_id=77 "
            "remote_endpoint=127.0.0.1:123 local_endpoint=127.0.0.1:50001 "
            "source_app=com.apple.python3 source_pid=42"
        )
        result = pressure_window_observation(
            [decision], 0, 42, "127.0.0.1:123", "com.apple.python3",
            RUN_UUID, 9001,
        )
        self.assertEqual(result["flow_id"], 77)
        wrong = pressure_window_observation(
            [decision], 0, 42, "127.0.0.1:123", "com.apple.python3",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 9001,
        )
        self.assertIsNone(wrong["flow_id"])

        malformed = pressure_window_observation(
            [decision, "udp_e2e_decision source_pid=42"], 0, 42,
            "127.0.0.1:123", "com.apple.python3", RUN_UUID, 9001,
        )
        self.assertFalse(malformed["terminal"])

        wrong_provider = pressure_window_observation(
            [decision], 0, 42, "127.0.0.1:123", "com.apple.python3",
            RUN_UUID, 9002,
        )
        self.assertIsNone(wrong_provider["flow_id"])


class StrictBundleTests(unittest.TestCase):
    def test_echo_socket_maps_are_required_by_sealed_raw_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            self.assertEqual(verify_bundle(root), 0)
            for filename, key in (("controlled-echo-client.json", "socket_endpoints"),
                                  ("controlled-echo-server.json", "socket_peers")):
                path = root / filename
                original = path.read_bytes()
                for mutation in ("missing", "index", "reused", "schema"):
                    value = json.loads(original)
                    if mutation == "missing":
                        value.pop(key)
                    elif mutation == "index":
                        value[key][0][0] = 1
                    elif mutation == "reused":
                        value[key][1][1] = value[key][0][1]
                    else:
                        value["schema_version"] = 1
                    with self.subTest(filename=filename, mutation=mutation):
                        path.write_text(json.dumps(value))
                        reseal_test_manifest(root)
                        with self.assertRaises(BundleVerificationError):
                            verify_bundle(root)
                    path.write_bytes(original)

    def test_intercepted_http3_requires_raw_tuple_phase_result_and_transport_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            self.assertEqual(verify_bundle(root), 0)
            cases = (
                ("provider.log", "local_endpoint=192.0.2.1:54000", "local_endpoint=192.0.2.1:54001"),
                ("provider.log", "provider_generation=8 rama_decision=intercept", "provider_generation=7 rama_decision=intercept"),
                ("provider.log", "source_pid=3500", "source_pid=3501"),
                ("provider.log", "rama_decision=intercept flow_id=2500", "rama_decision=passthrough flow_id=2500"),
                ("provider-log-phases.tsv", "http3_intercept_end_line\t143", "http3_intercept_end_line\t142"),
                ("http3-intercept-result.tsv", "3500\t0", "3500\t20"),
                ("http3-url.txt", "/cdn-cgi/trace", "/another-response"),
                ("http3-intercept-body.txt", "http=http/3", "http=http/2"),
                ("http3-intercept-client.json", '"start_epoch_ms": 8600', '"start_epoch_ms": 8500'),
                ("http3-intercept-client.json", '"start_monotonic_ns": 9600000000', '"start_monotonic_ns": 9500000000'),
                ("dial9-requirements.tsv", "http3-intercept\t9001\t8", "http3-intercept\t9001\t7"),
                ("dial9-requirements.tsv", "\t1\t16777216\t1\t16777216", "\t0\t16777216\t1\t16777216"),
                ("dial9-requirements.tsv", "\t1\t16777216\t1\t16777216", "\t1\t33554432\t1\t16777216"),
            )
            for filename, old, new in cases:
                path = root / filename
                original = path.read_text()
                self.assertIn(old, original)
                with self.subTest(file=filename, mutation=new):
                    path.write_text(original.replace(old, new))
                    reseal_test_manifest(root)
                    with self.assertRaises(BundleVerificationError):
                        verify_bundle(root)
                path.write_text(original)
            for filename in ("http3-intercept-client.json", "http3-intercept-body.txt", "http3-intercept-result.tsv"):
                path = root / filename
                original = path.read_bytes()
                with self.subTest(missing=filename):
                    path.unlink()
                    reseal_test_manifest(root)
                    with self.assertRaises(BundleVerificationError):
                        verify_bundle(root)
                path.write_bytes(original)

    @staticmethod
    def append_provider_log(root, message):
        provider_log = root / "provider.log"
        provider_log.write_text(provider_log.read_text() + message + "\n")
        phases = root / "provider-log-phases.tsv"
        phases.write_text(re.sub(
            r"(?m)^provider_log_end_line\t[0-9]+$",
            f"provider_log_end_line\t{len(provider_log.read_text().splitlines())}",
            phases.read_text(),
        ))
        reseal_test_manifest(root)

    def test_http3_unavailable_local_preserves_raw_workload_identity_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            provider_log = root / "provider.log"
            baseline = [
                re.sub(r"local_endpoint=[^ ]+", "local_endpoint=unavailable", line)
                if "source_app=com.apple.nscurl " in line else line
                for line in provider_log.read_text().splitlines()
            ]
            provider_log.write_text("\n".join(baseline) + "\n")
            reseal_test_manifest(root)
            self.assertEqual(verify_bundle(root), 0)
            h3 = next(i for i, line in enumerate(baseline) if "source_pid=3000" in line)
            echo = next(i for i, line in enumerate(baseline) if "source_pid=2002" in line)
            for case, index, old, new in (
                ("python", h3, "com.apple.nscurl", "com.apple.python3"),
                ("echo", echo, "local_endpoint=127.0.0.1:50000", "local_endpoint=unavailable"),
                ("port", h3, "remote_endpoint=1.1.1.1:443", "remote_endpoint=1.1.1.1:53"),
                ("intercept", h3, "rama_decision=passthrough", "rama_decision=intercept"),
                ("blocked", h3, "rama_decision=passthrough", "rama_decision=blocked"),
                ("zero-local", h3, "local_endpoint=unavailable", "local_endpoint=127.0.0.1:0"),
                ("unknown-local", h3, "local_endpoint=unavailable", "local_endpoint=missing"),
                ("pid", h3, "source_pid=3000", "source_pid=9999"),
                ("run", h3, RUN_UUID, "00000000-0000-4000-8000-000000000001"),
                ("generation", h3, "provider_generation=7", "provider_generation=8"),
                ("provider", h3, "provider_pid=9001", "provider_pid=9002"),
                ("remote", h3, "remote_endpoint=1.1.1.1:443", "remote_endpoint=8.8.8.8:443"),
                ("duplicate-flow", h3, "flow_id=2000", "flow_id=2001"),
            ):
                with self.subTest(case=case):
                    lines = baseline.copy()
                    self.assertIn(old, lines[index])
                    lines[index] = lines[index].replace(old, new)
                    provider_log.write_text("\n".join(lines) + "\n")
                    reseal_test_manifest(root)
                    with self.assertRaises(BundleVerificationError):
                        verify_bundle(root)
            # Moving a valid unavailable decision outside its H3 phase cannot
            # substitute for a current worker, even with unchanged identities.
            lines = baseline.copy()
            lines[0], lines[h3] = lines[h3], lines[0]
            provider_log.write_text("\n".join(lines) + "\n")
            reseal_test_manifest(root)
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_ntp_requirements_match_exact_receipt_bytes_in_both_directions(self):
        for label, requirement_label in (("ntp", "ntp"), ("recovery", "recovery-ntp")):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build_strict_bundle(root)
                receipt_path = root / f"udp-probe-{label}.json"
                receipt = json.loads(receipt_path.read_text())
                # Preserve the existing probe's variable-length NTP response
                # contract, while requiring its exact observed length in Dial9.
                receipt["response_hex"] += "00" * 20
                receipt_path.write_text(json.dumps(receipt) + "\n")
                requirements = root / "dial9-requirements.tsv"
                rows = requirements.read_text().splitlines()
                row_index = next(index for index, row in enumerate(rows)
                                 if row.startswith(requirement_label + "\t"))
                prefix = rows[row_index].split("\t")[:7]

                def write_bounds(bounds):
                    rows[row_index] = "\t".join(prefix + list(map(str, bounds)))
                    requirements.write_text("\n".join(rows) + "\n")
                    status = root / "udp-evidence-status.tsv"
                    status.write_text(re.sub(
                        r"(?m)^dial9_requirements_sha256\t[0-9a-f]{64}$",
                        f"dial9_requirements_sha256\t{hashlib.sha256(requirements.read_bytes()).hexdigest()}",
                        status.read_text(),
                    ))
                    reseal_test_manifest(root)

                write_bounds((48, 48, 68, 68))
                self.assertEqual(verify_bundle(root), 0)
                for bounds in ((48, 65535, 48, 65535), (49, 49, 68, 68),
                               (96, 96, 68, 68), (48, 48, 48, 48),
                               (48, 48, 69, 69), (48, 48, 67, 69)):
                    with self.subTest(bounds=bounds):
                        write_bounds(bounds)
                        with self.assertRaisesRegex(BundleVerificationError,
                                                    "representative Dial9 requirement mismatch"):
                            verify_bundle(root)

    def test_ntp_producer_derives_requirements_from_bound_successful_receipts(self):
        helper = BoundedCommandCleanupTests.shell_function
        for label, pid, flow_id, requirement_label in (
            ("ntp", 1003, 103, "ntp"), ("recovery", 1006, 106, "recovery-ntp"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                receipt_path = root / f"udp-probe-{label}.json"
                receipt = probe_receipt_fixture(label, pid, "162.159.200.1:123")
                receipt["response_hex"] += "00" * 20
                receipt_path.write_text(json.dumps(receipt) + "\n")
                requirements = root / "requirements.tsv"
                program = helper("check_exact_decision") + helper("append_dial9_requirement") + textwrap.dedent(f"""\
                    TMP_DIR={shlex.quote(str(root))}
                    PROBE={shlex.quote(str(SCRIPT_DIR / 'modern_udp_e2e_probe.py'))}
                    DIAL9_REQUIREMENTS={shlex.quote(str(requirements))}
                    RUN_UUID={RUN_UUID} PROVIDER_PID=9001
                    decision_records() {{ printf '%s\\n' 'intercept\t{flow_id}\t162.159.200.1:123\t127.0.0.1:5555\tcom.apple.python3\t{pid}\t{RUN_UUID}\t9001\t7'; }}
                    decision_marker_count_for_pid() {{ printf '1\\n'; }}
                    is_canonical_udp_endpoint() {{ return 0; }}
                    add_issue() {{ printf '%s\\n' "$1" >&2; }}
                    add_failure() {{ printf '%s\\n' "$1" >&2; }}
                    check_exact_decision 0 1 intercept 162.159.200.1:123 \\
                      com.apple.python3 {pid} {label} {label}
                """)
                result = subprocess.run(["/bin/bash", "-c", program], capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(requirements.read_text(),
                    f"{requirement_label}\t9001\t7\t{flow_id}\t2\t{pid}\t1\t48\t48\t68\t68\n")
                # A missing, wrong-generation-source, or failed probe cannot
                # produce a new permissive Dial9 row.
                for error in ("missing", "pid", "protocol"):
                    with self.subTest(error=error):
                        bad = dict(receipt)
                        if error == "missing":
                            receipt_path.unlink()
                        else:
                            if error == "pid":
                                bad["source_pid"] += 1
                            else:
                                bad["response_hex"] = "00" * 48
                                bad["exit_code"] = 20
                            receipt_path.write_text(json.dumps(bad) + "\n")
                        requirements.unlink(missing_ok=True)
                        result = subprocess.run(["/bin/bash", "-c", program], capture_output=True,
                                                text=True, timeout=5)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(requirements.exists())

    def test_pressure_requirements_allow_accepted_bytes_but_require_a_drop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            self.assertEqual(verify_bundle(root), 0)
            requirements = root / "dial9-requirements.tsv"
            original = requirements.read_text()
            for bounds in (
                "2097152\t2097152",  # Old contradictory all-sent equality.
                "0\t2093056",        # No accepted packet required.
                "4096\t2097152",     # No rejected packet required.
                "4097\t2093056",     # Requirements cannot silently narrow.
            ):
                with self.subTest(bounds=bounds):
                    requirements.write_text(original.replace("4096\t2093056", bounds))
                    status = root / "udp-evidence-status.tsv"
                    status.write_text(re.sub(
                        r"(?m)^dial9_requirements_sha256\t[0-9a-f]{64}$",
                        f"dial9_requirements_sha256\t{hashlib.sha256(requirements.read_bytes()).hexdigest()}",
                        status.read_text(),
                    ))
                    reseal_test_manifest(root)
                    with self.assertRaisesRegex(
                        BundleVerificationError, "representative Dial9 requirement mismatch"
                    ):
                        verify_bundle(root)

    def test_rejects_unexpected_udp_callback_errors_after_workload_decisions(self):
        for operation in ("open", "read", "write"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build_strict_bundle(root)
                self.assertEqual(verify_bundle(root), 0)
                self.append_provider_log(
                    root,
                    "1970-01-01 00:00:04.500 E provider[9001:1] "
                    "[org.ramaproxy.example.tproxy.dev.provider:udp] "
                    f"flow_callback_error operation=udp_flow.{operation} "
                    "classification=unexpected_provider_runtime",
                )
                # All workload decisions and phase ends are unchanged. This
                # models a callback arriving during Dial9/finalization after
                # the live shell's earlier error scan, then entering the seal.
                with self.assertRaisesRegex(
                    BundleVerificationError, "unexpected UDP flow callback error"
                ):
                    verify_bundle(root)

    def test_callback_error_replay_preserves_pre_run_and_benign_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            provider_log = root / "provider.log"
            provider_log.write_text(
                "flow_callback_error operation=udp_flow.write "
                "classification=unexpected_provider_runtime\n"
                + provider_log.read_text()
            )
            phases = root / "provider-log-phases.tsv"
            phases.write_text(re.sub(
                r"(?m)^([a-z0-9_]+_line)\t([0-9]+)$",
                lambda match: f"{match[1]}\t{int(match[2]) + 1}",
                phases.read_text(),
            ))
            for message in (
                "udp flow.write ended during normal flow shutdown already in progress: domain=NEAppProxyErrorDomain code=2",
                "udp flow.read ended after peer reset the flow: domain=NEAppProxyErrorDomain code=3",
                "udp flow.write failed because the network path was unavailable: domain=NEAppProxyErrorDomain code=5",
                "flow_callback_error operation=tcp_flow.write classification=unexpected_provider_runtime",
            ):
                self.append_provider_log(root, message)
            self.assertEqual(verify_bundle(root), 0)

    def test_late_callback_error_cannot_hide_beyond_declared_log_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            provider_log = root / "provider.log"
            provider_log.write_text(
                provider_log.read_text()
                + "flow_callback_error operation=udp_flow.write "
                "classification=unexpected_provider_runtime\n"
            )
            # Resealing the bytes while keeping the earlier end boundary
            # cannot exclude the late callback from semantic replay.
            reseal_test_manifest(root)
            with self.assertRaisesRegex(
                BundleVerificationError, "provider-log terminal boundary is stale"
            ):
                verify_bundle(root)

    def test_replays_complete_raw_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            self.assertEqual(verify_bundle(root), 0)
            result = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / "modern_udp_evidence.py"),
                 "verify-bundle", str(root)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "0\n")
            self.assertEqual(result.stderr, "")

    def test_rejects_missing_duplicate_mismatched_and_failed_probe_receipts(self):
        cases = (
            "missing", "truncated", "duplicate-key", "duplicate-row", "missing-row",
            "wrong-run", "wrong-label", "wrong-pid", "wrong-endpoint", "child-exit",
            "bad-dns-id", "dns-timeout", "bad-ntp-originate", "wrong-peer",
            "short-ntp", "raw-failure", "short-block-timeout", "bad-request",
            "receipt-after-run", "receipt-reordered", "oversized-packet", "extra-field",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build_strict_bundle(root)
                label = "blocked" if case == "short-block-timeout" else (
                    "passthrough" if case in ("bad-dns-id", "dns-timeout") else "recovery"
                )
                path = root / f"udp-probe-{label}.json"
                value = json.loads(path.read_text())
                results = root / "udp-probe-results.tsv"
                if case == "missing":
                    path.unlink()
                elif case == "truncated":
                    path.write_text(path.read_text()[:-3])
                elif case == "duplicate-key":
                    path.write_text(json.dumps(value)[:-1] + ',"exit_code":0}\n')
                elif case == "duplicate-row":
                    results.write_text(results.read_text() + "recovery\t1006\t0\n")
                elif case == "missing-row":
                    results.write_text(results.read_text().replace("recovery\t1006\t0\n", ""))
                elif case == "child-exit":
                    results.write_text(results.read_text().replace("recovery\t1006\t0", "recovery\t1006\t20"))
                else:
                    if case == "wrong-run":
                        value["run_uuid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                    elif case == "wrong-label":
                        value["probe_label"] = "ntp"
                    elif case == "wrong-pid":
                        value["source_pid"] += 1
                    elif case == "wrong-endpoint":
                        value["endpoint"] = "162.159.200.2:123"
                    elif case == "bad-dns-id":
                        value["response_hex"] = "ffff" + value["response_hex"][4:]
                    elif case == "dns-timeout":
                        value.update(receive_outcome="timeout", response_hex=None, response_peer=None, exit_code=20)
                    elif case in ("bad-ntp-originate", "raw-failure"):
                        packet = bytearray.fromhex(value["response_hex"])
                        packet[24] ^= 1
                        value["response_hex"] = packet.hex()
                        if case == "raw-failure":
                            value["exit_code"] = 20
                    elif case == "wrong-peer":
                        value["response_peer"] = ["127.0.0.1", 123]
                    elif case == "short-ntp":
                        value["response_hex"] = "00" * 47
                    elif case == "short-block-timeout":
                        value["receive_completed_monotonic_ns"] -= 1
                    elif case == "bad-request":
                        value["request_hex"] = "00" * 48
                    elif case == "receipt-after-run":
                        value["start_epoch_ms"] += 10000
                        value["end_epoch_ms"] += 10000
                    elif case == "receipt-reordered":
                        for key in ("start_monotonic_ns", "receive_started_monotonic_ns",
                                    "receive_completed_monotonic_ns", "end_monotonic_ns"):
                            value[key] -= 1_000_000_000
                    elif case == "oversized-packet":
                        value["response_hex"] = "00" * 65536
                    elif case == "extra-field":
                        value["passed"] = True
                    path.write_text(json.dumps(value) + "\n")
                reseal_test_manifest(root)
                with self.assertRaisesRegex(BundleVerificationError, "UDP probe|UDP blocked"):
                    verify_bundle(root)

    def test_common_release_dispatch_replays_archived_probe_bytes(self):
        import signed_run_evidence as evidence
        from test_signed_run_evidence import (
            HEAD, current_script_source, write_generation_samples, write_identity, write_tsv,
        )
        from modern_udp_evidence import PRODUCER_SOURCE_NAMES

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            build, generation = write_identity(root, pid=9001, start=500)
            identity_path = root / evidence.PROVIDER_IDENTITY_NAME
            identity_path.write_text(identity_path.read_text().replace(
                "running_executable_path\t/fixture/running/provider\n",
                f"running_executable_path\t/fixture/running/{evidence.DEV_PROVIDER_BUNDLE_ID}\n",
            ))
            for path in root.rglob("*"):
                if path.is_file() and path.name != evidence.PROVIDER_IDENTITY_NAME:
                    path.write_text(path.read_text().replace(DIGEST, generation))
            for name in PRODUCER_SOURCE_NAMES:
                (root / name).write_bytes((SCRIPT_DIR / name.removeprefix("source-")).read_bytes())
            producer_digest = producer_sources_sha256(root)
            for name in ("udp-evidence-status.tsv", "workload-claims.tsv"):
                path = root / name
                path.write_text(re.sub(r"(?m)^producer_sources_sha256\t[0-9a-f]{64}$",
                                      f"producer_sources_sha256\t{producer_digest}", path.read_text()))
            udp = dict(line.split("\t") for line in (root / "udp-evidence-status.tsv").read_text().splitlines())
            common = {key: udp[key] for key in (
                "complete", "passed", "exit_code", "evidence_kind", "run_uuid",
                "run_start_epoch_ms", "run_end_epoch_ms", "provider_generation_identity", "schema_complete",
            )}
            common.update(git_head=HEAD, git_dirty="0", provider_build_identity=build,
                          workload_claims_sha256=evidence.sha256_file(root / evidence.CLAIMS_NAME))
            write_tsv(root / evidence.STATUS_NAME, ((key, common[key]) for key in evidence.STATUS_ORDER))
            write_generation_samples(root, dict(common, run_end_epoch_ms="11000"))
            # The native decoder has separate fixture coverage. This regression
            # exercises the actual common -> archived Python replay boundary.
            for name in ("dial9-baseline.json", "dial9-evidence.json"):
                (root / name).write_text("{}\n")
            with mock.patch.object(evidence, "_source_blob_at_head", side_effect=current_script_source), \
                    mock.patch.object(evidence, "_validate_modern_dial9"):
                evidence.seal(root)
                evidence._validate_modern_semantics(evidence._verify_and_capture(root))
                requirements_path = root / "dial9-requirements.tsv"
                original_requirements = requirements_path.read_text()
                status_path = root / "udp-evidence-status.tsv"
                original_status = status_path.read_text()
                requirements_path.write_text(original_requirements.replace(
                    "ntp\t9001\t7\t103\t2\t1003\t1\t48\t48\t48\t48",
                    "ntp\t9001\t7\t103\t2\t1003\t1\t48\t65535\t48\t65535",
                ))
                status_path.write_text(re.sub(
                    r"(?m)^dial9_requirements_sha256\t[0-9a-f]{64}$",
                    f"dial9_requirements_sha256\t{hashlib.sha256(requirements_path.read_bytes()).hexdigest()}",
                    original_status,
                ))
                evidence.seal(root)
                with self.assertRaisesRegex(evidence.EvidenceError,
                        "raw-bundle validator rejected.*representative Dial9 requirement mismatch"):
                    evidence._validate_modern_semantics(evidence._verify_and_capture(root))
                requirements_path.write_text(original_requirements)
                status_path.write_text(original_status)
                receipt = root / "udp-probe-ntp.json"
                value = json.loads(receipt.read_text())
                value["response_peer"] = ["127.0.0.1", 123]
                receipt.write_text(json.dumps(value) + "\n")
                evidence.seal(root)
                with self.assertRaisesRegex(evidence.EvidenceError, "raw-bundle validator rejected.*UDP probe receipt"):
                    evidence._validate_modern_semantics(evidence._verify_and_capture(root))

    def test_rejects_scalar_only_fabricated_modern_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_status(root, {})
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_rejects_missing_raw_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            (root / "provider.log").unlink()
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_rejects_missing_resealed_crash_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            (root / "crashes/crash-snapshot.tsv").unlink()
            reseal_test_manifest(root)
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_rejects_resealed_crash_snapshot_for_another_generation_or_window(self):
        for old, new in ((DIGEST, "b" * 64), ("snapshot_epoch_ms\t11000", "snapshot_epoch_ms\t4999")):
            with self.subTest(mutation=new):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    build_strict_bundle(root)
                    snapshot = root / "crashes/crash-snapshot.tsv"
                    snapshot.write_text(snapshot.read_text().replace(old, new))
                    reseal_test_manifest(root)
                    with self.assertRaises(BundleVerificationError):
                        verify_bundle(root)

    def test_rejects_missing_or_altered_resealed_producer_source(self):
        for remove in (True, False):
            with self.subTest(remove=remove):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    build_strict_bundle(root)
                    producer = root / "source-modern_udp_e2e_probe.py"
                    if remove:
                        producer.unlink()
                    else:
                        producer.write_bytes(producer.read_bytes() + b"# altered\n")
                    reseal_test_manifest(root)
                    with self.assertRaises(BundleVerificationError):
                        verify_bundle(root)

    def test_rejects_legacy_callback_mutation_after_reseal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            status = root / "udp-evidence-status.tsv"
            status.write_text(status.read_text().replace(
                "callback_generation\tmodern", "callback_generation\tlegacy"
            ))
            reseal_test_manifest(root)
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_rejects_removed_reused_or_gapped_generation_timeline_after_reseal(self):
        mutations = (
            None,
            ("sample_000001\t900|9001|", "sample_000001\t900|9002|"),
            ("sample_000003\t6000|", "sample_000003\t9001|"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    build_strict_bundle(root)
                    timeline = root / "provider-generation-samples.tsv"
                    if mutation is None:
                        timeline.unlink()
                    else:
                        original = timeline.read_text()
                        self.assertIn(mutation[0], original)
                        timeline.write_text(original.replace(*mutation))
                    reseal_test_manifest(root)
                    with self.assertRaises(BundleVerificationError):
                        verify_bundle(root)

    def test_rejects_tampered_and_resealed_http3_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            reseal_test_manifest(root)
            output = root / "http3-1-1.log"
            output.write_bytes(output.read_bytes().replace(b"http=http/3", b"http=http/2"))
            reseal_test_manifest(root)
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_rejects_tampered_and_resealed_pressure_flow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            log = root / "provider.log"
            log.write_text(log.read_text().replace(
                "dropped datagram flow_id=104", "dropped datagram flow_id=999"
            ))
            reseal_test_manifest(root)
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_rejects_restore_slice_with_evidence_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            restore = root / "restore-container.log"
            restore.write_text(restore.read_text().replace(
                "container app launched", f"container app launched {RUN_UUID}"
            ))
            receipt = root / "restore-receipt.tsv"
            receipt.write_text(re.sub(
                r"(?m)^slice_sha256\t[0-9a-f]{64}$",
                f"slice_sha256\t{hashlib.sha256(restore.read_bytes()).hexdigest()}",
                receipt.read_text(),
            ))
            reseal_test_manifest(root)
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)


class PressureProbePacingTests(unittest.TestCase):
    class Clock:
        def __init__(self):
            self.now = 100.0
            self.sleeps = []
            self.oversleep = {}

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.sleeps.append((self.now, seconds))
            self.now += seconds + self.oversleep.get(len(self.sleeps), 0.0)

    class Socket:
        def __init__(self, clock):
            self.clock = clock
            self.attempts = []
            self.delays = {}
            self.errors = {}
            self.partial = set()
            self.timeout = None
            self.closes = 0
            self.binds = []
            self.bind_error = None

        def bind(self, endpoint):
            self.binds.append(endpoint)
            if self.bind_error is not None:
                raise self.bind_error

        def settimeout(self, seconds):
            self.timeout = seconds

        def sendto(self, packet, peer):
            if self.binds != [("0.0.0.0", 0)]:
                raise AssertionError("pressure probe sent before ephemeral bind")
            sequence = len(self.attempts)
            started = self.clock.now
            self.clock.now += self.delays.get(sequence, 0.0)
            self.attempts.append((
                bytes(packet), peer, started, self.clock.now, self.timeout,
            ))
            if sequence in self.errors:
                raise self.errors[sequence]
            return len(packet) - int(sequence in self.partial)

        def close(self):
            self.closes += 1

    def setUp(self):
        self.clock = self.Clock()
        self.socket = self.Socket(self.clock)
        self.factory = mock.Mock(return_value=self.socket)
        self.output = mock.Mock()

    def run_probe(self, *, count=512, payload_bytes=4096, deadline=120.0):
        with mock.patch.object(udp_probe.time, "monotonic", self.clock.monotonic), \
                mock.patch.object(udp_probe.time, "sleep", self.clock.sleep), \
                mock.patch.object(udp_probe.socket, "socket", self.factory), \
                mock.patch.object(udp_probe, "print", self.output, create=True), \
                mock.patch.object(udp_probe, "PRESSURE_DEADLINE_SECONDS", deadline):
            pressure_burst("162.159.200.1", count, payload_bytes, 4.0)

    def assert_once_only_sequences(self):
        marker = b"rama-udp-e2e-pressure-v1 162.159.200.1:123\0"
        for sequence, (packet, peer, _, _, _) in enumerate(self.socket.attempts):
            self.assertEqual(len(packet), 4096)
            self.assertEqual(packet[:len(marker)], marker)
            self.assertEqual(int.from_bytes(packet[len(marker):len(marker) + 8], "big"), sequence)
            self.assertEqual(peer, ("162.159.200.1", 123))

    def test_canonical_workload_primes_recovers_and_sends_every_packet_once(self):
        self.run_probe()
        self.assertEqual(len(self.socket.attempts), 512)
        self.assert_once_only_sequences()
        self.factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertEqual(self.socket.binds, [("0.0.0.0", 0)])
        self.assertEqual(self.socket.closes, 1)
        self.output.assert_called_once()
        self.assertLess(self.socket.attempts[65][3] - 100, 2.0)
        for sequence in range(1, 512):
            previous = self.socket.attempts[sequence - 1]
            current = self.socket.attempts[sequence]
            self.assertAlmostEqual(current[2] - previous[3], 2.5 if sequence == 66 else 0.02)
        self.assertEqual(self.clock.sleeps[-1][1], 4.0)
        self.assertAlmostEqual(self.clock.now - 100, 16.7)
        self.assertTrue(all(row[4] == 5.0 for row in self.socket.attempts))

    def test_bind_failure_closes_without_sending_or_pacing(self):
        self.socket.bind_error = OSError("ordinary mocked bind error")
        with self.assertRaisesRegex(OSError, "bind error"):
            self.run_probe()
        self.assertEqual(self.socket.binds, [("0.0.0.0", 0)])
        self.assertEqual(self.socket.attempts, [])
        self.assertEqual(self.socket.closes, 1)
        self.assertEqual(self.clock.sleeps, [])
        self.output.assert_not_called()

    def test_scheduler_and_send_delays_do_not_compress_later_intervals(self):
        self.clock.oversleep[40] = 0.7
        self.socket.delays[45] = 0.3
        self.run_probe()
        self.assert_once_only_sequences()
        for sequence in range(1, 512):
            previous = self.socket.attempts[sequence - 1]
            current = self.socket.attempts[sequence]
            self.assertGreaterEqual(current[2] - previous[3], 0.02 - 1e-9)
        self.assertAlmostEqual(self.socket.attempts[40][2] - self.socket.attempts[39][3], 0.72)
        self.assertAlmostEqual(self.clock.now - 100, 17.7)

    def test_socket_errors_and_partial_datagrams_never_retry(self):
        for sequence, error in (
            (0, socket.timeout("blocked send")),
            (65, socket.timeout("blocked send")),
            (66, socket.timeout("blocked send")),
            (511, OSError("socket unavailable")),
            (66, None),
        ):
            with self.subTest(sequence=sequence, error=error):
                self.setUp()
                if error is None:
                    self.socket.partial.add(sequence)
                else:
                    self.socket.errors[sequence] = error
                with self.assertRaises(RuntimeError if error is None else OSError):
                    self.run_probe()
                self.assertEqual(len(self.socket.attempts), sequence + 1)
                self.assert_once_only_sequences()
                self.assertEqual(self.socket.closes, 1)
                self.output.assert_not_called()

    def test_unschedulable_load_is_rejected_before_socket_creation(self):
        # This byte product is admissible, but its pacing cannot fit in 120s.
        with self.assertRaisesRegex(ValueError, "schedule exceeds"):
            self.run_probe(count=100_000, payload_bytes=64)
        self.factory.assert_not_called()
        self.output.assert_not_called()

    def test_short_load_deadline_omits_a_recovery_pause_that_is_never_reached(self):
        for count in (64, 65, 66):
            with self.subTest(count=count):
                self.setUp()
                self.run_probe(count=count, deadline=5.5)
                self.assertEqual(len(self.socket.attempts), count)
                self.assert_once_only_sequences()
                self.assertAlmostEqual(self.clock.now - 100, (count - 1) * 0.02 + 4.0)
                self.assertTrue(all(seconds == 0.02 for _, seconds in self.clock.sleeps[:-1]))
                self.output.assert_called_once()

    def test_whole_deadline_rejects_late_sleep_or_send_completion(self):
        for late_operation in ("sleep", "send"):
            with self.subTest(late_operation=late_operation):
                self.setUp()
                if late_operation == "sleep":
                    self.clock.oversleep[1] = 120.0
                else:
                    # Even an unexpectedly late successful syscall cannot
                    # bypass the total deadline when it returns to Python.
                    self.socket.delays[0] = 120.0
                with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                    self.run_probe()
                self.assertEqual(len(self.socket.attempts), 1)
                self.assertEqual(self.socket.closes, 1)
                self.output.assert_not_called()

    def test_send_timeout_uses_remaining_deadline_and_settle_is_bounded(self):
        self.run_probe(deadline=17.0)
        self.assertAlmostEqual(self.socket.attempts[-1][4], 4.3)
        self.assertTrue(all(0 < row[4] <= 5.0 for row in self.socket.attempts))
        self.setUp()
        self.socket.delays[50] = 0.5
        with self.assertRaisesRegex(TimeoutError, "cannot finish its pause after 512 sends"):
            self.run_probe(deadline=17.0)
        self.assertEqual(len(self.socket.attempts), 512)
        self.assertEqual(self.socket.closes, 1)
        self.output.assert_not_called()


class QuicShapedEchoTests(unittest.TestCase):
    def test_actual_receiver_preserves_payload_socket_to_peer_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, result = root / "ready.json", root / "server.json"
            command = [
                sys.executable, str(SCRIPT_DIR / "modern_udp_e2e_probe.py"), "echo-server",
                "--run-uuid", RUN_UUID, "--expected-count", "12", "--max-seconds", "5",
                "--ready-file", str(ready), "--result-file", str(result),
            ]
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as server:
                try:
                    deadline = time.monotonic() + 3
                    while not ready.exists() and server.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), "receiver published readiness")
                    readiness = json.loads(ready.read_text())
                    port = int(readiness["endpoint"].rsplit(":", 1)[1])
                    client_path = root / "client.json"
                    controlled_echo_load(
                        "127.0.0.1", port, RUN_UUID, 4, 3, 1200, 4, 2, str(client_path), 20
                    )
                    stdout, stderr = server.communicate(timeout=5)
                    self.assertEqual((server.returncode, stdout, stderr), (0, b"", b""))
                    client, receiver = json.loads(client_path.read_text()), json.loads(result.read_text())
                    self.assertEqual(client["schema_version"], 2)
                    self.assertEqual(receiver["schema_version"], 2)
                    self.assertEqual(readiness["schema_version"], 2)
                    validate_echo_socket_maps(client, receiver, 4)
                    self.assertEqual(client["socket_endpoints"], receiver["socket_peers"])
                    self.assertEqual(receiver["payload_set_sha256"], client["echo_set_sha256"])
                    self.assertEqual(receiver["echo_count"], 12)
                finally:
                    if server.poll() is None:
                        server.kill()
                    server.communicate(timeout=5)

    def test_receiver_rejects_changed_reused_and_out_of_bounds_socket_identities(self):
        packets = [
            (0, 0, ("127.0.0.1", 50001)),
            (0, 1, ("127.0.0.1", 50002)),  # same index changed peer
            (1, 0, ("127.0.0.1", 50001)),  # another index reused peer
            (512, 0, ("127.0.0.1", 50003)),
            (0, 64, ("127.0.0.1", 50001)),
        ]
        receiver = mock.Mock()
        receiver.getsockname.return_value = ("127.0.0.1", 44444)
        receiver.sendto.side_effect = lambda payload, _peer: len(payload)
        receiver.recvfrom.side_effect = [
            (quic_shaped_payload(RUN_UUID, index, sequence, 1200), peer)
            for index, sequence, peer in packets
        ] + [OSError("fixture input ended")]
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "server.json"
            with mock.patch.object(udp_probe.socket, "socket", return_value=receiver), \
                    mock.patch.object(udp_probe.signal, "signal"):
                with self.assertRaisesRegex(OSError, "fixture input ended"):
                    udp_probe.controlled_echo_server(
                        "127.0.0.1", 44444, RUN_UUID, 2, 5,
                        str(Path(directory) / "ready.json"), str(result),
                    )
            value = json.loads(result.read_text())
            self.assertFalse(value["passed"])
            self.assertEqual(value["peer_mismatch_count"], 2)
            self.assertEqual(value["malformed_count"], 2)
            self.assertEqual(value["socket_peers"], [[0, "127.0.0.1:50001"]])
            self.assertEqual(value["received_count"], 1)
            receiver.sendto.assert_called_once()
            receiver.close.assert_called_once()
            receiver.reset_mock()
            receiver.recvfrom.side_effect = [
                (quic_shaped_payload(RUN_UUID, index, 0, 1200), ("127.0.0.1", 50001 + index))
                for index in range(2)
            ]
            with mock.patch.object(udp_probe.socket, "socket", return_value=receiver), \
                    mock.patch.object(udp_probe.signal, "signal"), \
                    mock.patch.object(udp_probe, "MAX_LOAD_BYTES", 1200):
                with self.assertRaisesRegex(RuntimeError, "did not receive one exact payload"):
                    udp_probe.controlled_echo_server(
                        "127.0.0.1", 44444, RUN_UUID, 2, 5,
                        str(Path(directory) / "ready.json"), str(result),
                    )
            limited = json.loads(result.read_text())
            self.assertFalse(limited["passed"])
            self.assertEqual(limited["received_count"], 1)
            self.assertEqual(limited["malformed_count"], 1)
            receiver.sendto.assert_called_once()
            receiver.close.assert_called_once()
        with mock.patch.object(udp_probe.socket, "socket") as factory:
            with self.assertRaises(ValueError):
                udp_probe.controlled_echo_server("127.0.0.1", 0, RUN_UUID, 32769, 5, "", "")
            factory.assert_not_called()

    def test_socket_map_replay_keeps_nat_address_spaces_distinct_and_rejects_mutations(self):
        client = {
            "socket_endpoints": [[0, "192.168.0.7:50001"], [1, "192.168.0.7:50002"]],
            "local_endpoints": ["192.168.0.7:50001", "192.168.0.7:50002"],
        }
        receiver = {
            "socket_peers": [[0, "203.0.113.7:60001"], [1, "203.0.113.7:60002"]],
            "peer_mismatch_count": 0,
        }
        validate_echo_socket_maps(client, receiver, 2)
        for which, key in (("client", "socket_endpoints"), ("server", "socket_peers")):
            for mutation in ("missing", "duplicate", "swapped", "boolean", "reused", "wildcard", "port", "scope"):
                c, s = json.loads(json.dumps(client)), json.loads(json.dumps(receiver))
                rows = (c if which == "client" else s)[key]
                if mutation == "missing":
                    rows.pop()
                elif mutation == "duplicate":
                    rows[1][0] = 0
                elif mutation == "swapped":
                    rows.reverse()
                elif mutation == "boolean":
                    rows[0][0] = False
                elif mutation == "reused":
                    rows[1][1] = rows[0][1]
                elif mutation == "wildcard":
                    rows[0][1] = "0.0.0.0:50001"
                elif mutation == "port":
                    rows[0][1] = "127.0.0.1:050001"
                else:
                    rows[0][1] = "[fe80::1%en0]:50001"
                with self.subTest(which=which, mutation=mutation), self.assertRaises(BundleVerificationError):
                    validate_echo_socket_maps(c, s, 2)
        for mismatch in (1, False, "0"):
            with self.subTest(mismatch=mismatch), self.assertRaises(BundleVerificationError):
                validate_echo_socket_maps(client, {**receiver, "peer_mismatch_count": mismatch}, 2)
        with self.assertRaises(BundleVerificationError):
            validate_echo_socket_maps({**client, "local_endpoints": []}, receiver, 2)

    def test_paced_socket_load_records_and_rederives_every_packet_window(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        port = server.getsockname()[1]

        def echo():
            try:
                for _ in range(12):
                    payload, peer = server.recvfrom(65535)
                    server.sendto(payload, peer)
            finally:
                server.close()

        thread = threading.Thread(target=echo)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                result = Path(directory) / "result.json"
                controlled_echo_load(
                    "127.0.0.1", port, RUN_UUID, 4, 3, 1200, 4, 2, str(result), 40
                )
                value = json.loads(result.read_text())
                status = {
                    "run_start_epoch_ms": str(value["start_epoch_ms"]),
                    "run_end_epoch_ms": str(value["end_epoch_ms"]),
                    "concurrent_load_deadline_seconds": "180",
                }
                self.assertTrue(value["passed"])
                self.assertEqual(value["exact_echo_count"], 12)
                self.assertEqual(value["independent_socket_count"], 4)
                _validate_echo_timing(value, status, 4, 3)
                for index in range(4):
                    rows = value["packet_timings_ns"][index * 3:index * 3 + 3]
                    self.assertGreaterEqual(rows[-1][2] - rows[0][2], 80_000_000)
                for mutation in ("missing", "duplicate", "unpaced", "outside", "clock"):
                    altered = json.loads(json.dumps(value))
                    if mutation == "missing":
                        altered["packet_timings_ns"].pop()
                    elif mutation == "duplicate":
                        altered["packet_timings_ns"][1] = altered["packet_timings_ns"][0]
                    elif mutation == "unpaced":
                        altered["packet_timings_ns"][1][2] = altered["packet_timings_ns"][0][2]
                    elif mutation == "outside":
                        altered["packet_timings_ns"][-1][3] = altered["end_monotonic_ns"] + 1
                    else:
                        altered["end_epoch_ms"] += 10_000
                    with self.subTest(mutation=mutation), self.assertRaises(BundleVerificationError):
                        _validate_echo_timing(altered, status, 4, 3)
        finally:
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_load_byte_products_are_bounded_before_socket_work(self):
        with self.assertRaises(ValueError):
            pressure_burst("127.0.0.1", 100_000, 60_000, 0)
        with self.assertRaises(ValueError):
            controlled_echo_load(
                "127.0.0.1", 9, RUN_UUID, 512, 64, 60_000, 128, 2,
                "/does/not/matter.json",
            )
        for interval in (-1, 10_001, True, 0.5):
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                controlled_echo_load(
                    "127.0.0.1", 9, RUN_UUID, 1, 1, 1200, 1, 2,
                    "/does/not/matter.json", interval,
                )

    def test_echo_provider_mapping_requires_endpoint_flow_bijection(self):
        endpoints = ["127.0.0.1:50001", "127.0.0.1:50002"]
        base = [
            "intercept", "101", "127.0.0.1:44444", endpoints[0],
            "com.apple.python3", "42", RUN_UUID, "9001", "7",
        ]
        second = base.copy()
        second[1], second[3] = "102", endpoints[1]
        self.assertEqual(
            len(validate_echo_decision_bijection(
                [base, second], endpoints, 2, 42, RUN_UUID, 9001,
                "127.0.0.1:44444",
            )),
            2,
        )
        duplicate_local = second.copy()
        duplicate_local[3] = endpoints[0]
        bypass = second.copy()
        bypass[3] = "127.0.0.1:59999"
        for rows in ([base, duplicate_local], [base, bypass]):
            with self.assertRaises(ValueError):
                validate_echo_decision_bijection(
                    rows, endpoints, 2, 42, RUN_UUID, 9001,
                    "127.0.0.1:44444",
                )

    def test_echo_load_rejects_effectively_unbounded_serial_work(self):
        with self.assertRaises(ValueError):
            controlled_echo_load(
                "127.0.0.1", 9, RUN_UUID, 17, 1, 1200, 1, 2,
                "/does/not/matter.json",
            )

    def test_payload_is_explicitly_shaped_and_tamper_evident(self):
        payload = quic_shaped_payload(RUN_UUID, 7, 3, 1200)
        self.assertEqual(parse_quic_shaped_payload(payload, RUN_UUID), (7, 3))
        self.assertIn(b"not-valid-quic", payload)
        tampered = bytearray(payload)
        tampered[-1] ^= 1
        with self.assertRaises(ValueError):
            parse_quic_shaped_payload(bytes(tampered), RUN_UUID)

    def test_independent_socket_load_records_exact_echo_cardinality(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        port = server.getsockname()[1]
        observed_endpoints = set()
        socket_factory = socket.socket
        clients = []

        def client_socket(*args):
            client = mock.Mock(wraps=socket_factory(*args))
            clients.append(client)
            return client

        def echo():
            for _ in range(8):
                payload, peer = server.recvfrom(65535)
                observed_endpoints.add(f"{peer[0]}:{peer[1]}")
                server.sendto(payload, peer)
            server.close()

        thread = threading.Thread(target=echo)
        thread.start()
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.json"
            with mock.patch.object(udp_probe.socket, "socket", side_effect=client_socket):
                controlled_echo_load(
                    "127.0.0.1", port, RUN_UUID, 8, 1, 1200, 4, 2, str(result)
                )
            value = json.loads(result.read_text())
            self.assertTrue(value["passed"])
            self.assertEqual(value["exact_echo_count"], 8)
            self.assertEqual(value["independent_socket_count"], 8)
            self.assertEqual(set(value["local_endpoints"]), observed_endpoints)
            self.assertEqual(value["payload_set_sha256"], value["echo_set_sha256"])
            self.assertEqual(len(clients), 8)
            for client in clients:
                client.bind.assert_called_once_with(("0.0.0.0", 0))
                calls = [call[0] for call in client.method_calls]
                self.assertLess(calls.index("bind"), calls.index("connect"))
                self.assertLess(calls.index("connect"), calls.index("send"))
                client.close.assert_called_once()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_echo_setup_failures_close_every_created_socket_before_traffic(self):
        for server, family, wildcard in (
            ("127.0.0.1", socket.AF_INET, "0.0.0.0"),
            ("::1", socket.AF_INET6, "::"),
        ):
            for failing_step in ("bind", "settimeout", "connect"):
                with self.subTest(server=server, failing_step=failing_step):
                    first, second = mock.Mock(), mock.Mock()
                    first.getsockname.return_value = (server, 50001)
                    getattr(second, failing_step).side_effect = OSError("ordinary setup failure")
                    with mock.patch.object(udp_probe.socket, "socket", side_effect=[first, second]) as factory:
                        with self.assertRaisesRegex(OSError, "ordinary setup failure"):
                            controlled_echo_load(
                                server, 44444, RUN_UUID, 3, 1, 1200, 3, 2,
                                "/does/not/matter.json",
                            )
                    self.assertEqual(factory.call_args_list, [
                        mock.call(family, socket.SOCK_DGRAM),
                        mock.call(family, socket.SOCK_DGRAM),
                    ])
                    for client in (first, second):
                        client.bind.assert_called_once_with((wildcard, 0))
                        client.send.assert_not_called()
                        client.recvfrom.assert_not_called()
                        client.close.assert_called_once()
                    self.assertEqual(first.method_calls[:3], [
                        mock.call.bind((wildcard, 0)), mock.call.settimeout(2),
                        mock.call.connect((server, 44444)),
                    ])

    def test_mutated_echo_is_a_product_violation(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        port = server.getsockname()[1]

        def mutate():
            payload, peer = server.recvfrom(65535)
            server.sendto(payload[:-1] + bytes((payload[-1] ^ 1,)), peer)
            server.close()

        thread = threading.Thread(target=mutate)
        thread.start()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ProductViolation):
                controlled_echo_load(
                    "127.0.0.1", port, RUN_UUID, 1, 1, 1200, 1, 2,
                    str(Path(directory) / "result.json"),
                )
        thread.join(timeout=2)


class HarnessSourceContractTests(unittest.TestCase):
    def test_intercepted_http3_shell_requirement_preserves_exact_identity(self):
        helper = BoundedCommandCleanupTests.shell_function
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_strict_bundle(root)
            requirement = root / "h3-requirement.tsv"
            program = helper("check_http3_intercept_decision") + helper("append_dial9_requirement") + textwrap.dedent(f"""\
                TMP_DIR={shlex.quote(str(root))}
                MODERN_EVIDENCE={shlex.quote(str(SCRIPT_DIR / 'modern_udp_evidence.py'))}
                PROBE={shlex.quote(str(SCRIPT_DIR / 'modern_udp_e2e_probe.py'))}
                PROVIDER_LOG="$TMP_DIR/provider.log"
                HTTP3_INTERCEPT_RESULT="$TMP_DIR/http3-intercept-client.json"
                HTTP3_INTERCEPT_BODY="$TMP_DIR/http3-intercept-body.txt"
                HTTP3_ENDPOINTS="$TMP_DIR/http3-endpoints.txt"
                HTTP3_URL=https://cloudflare.com/cdn-cgi/trace
                DIAL9_REQUIREMENTS={shlex.quote(str(requirement))}
                RUN_UUID={shlex.quote(RUN_UUID)} PROVIDER_PID=9001
                HTTP3_INTERCEPT_SOURCE_PID=3500 BLOCKED_PROVIDER_GENERATION="$1"
                HTTP3_INTERCEPT_LOG_START=142 HTTP3_INTERCEPT_LOG_END=143
                add_issue() {{ printf '%s\\n' "$1" >&2; exit 2; }}
                check_http3_intercept_decision
            """)
            for generation, expected_exit in ((8, 0), (7, 2)):
                if requirement.exists():
                    requirement.unlink()
                result = subprocess.run(["/bin/bash", "-c", program, "fixture", str(generation)],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
                if expected_exit == 0:
                    self.assertEqual(requirement.read_text(),
                        "http3-intercept\t9001\t8\t2500\t2\t3500\t1\t1\t16777216\t1\t16777216\n")
                else:
                    self.assertFalse(requirement.exists())

    def test_echo_and_pressure_callers_use_captured_sources_and_nested_dependency(self):
        helper = BoundedCommandCleanupTests.shell_function
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            live = root / "live"
            live.mkdir()
            for name in ("modern_udp_evidence.py", "soak_pressure_log.py"):
                (root / f"source-{name}").write_bytes((SCRIPT_DIR / name).read_bytes())
                (live / name).write_text("raise RuntimeError('live source must not be imported')\n")
            (root / "provider.log").write_text("\n".join((
                _decision(RUN_UUID, 9001, 7, "intercept", 1000,
                          "127.0.0.1:443", "127.0.0.1:50000", "com.apple.python3", 2002),
                _decision(RUN_UUID, 9001, 7, "intercept", 104,
                          "162.159.200.1:123", "127.0.0.1:41004", "com.apple.python3", 1004),
                'UDP ingress pressure dropped datagram flow_id=104 pressure="global_bytes" cumulative_drops=1 global_retained_bytes=4096 global_max_retained_bytes=4096',
                'UDP ingress pressure resumed flow flow_id=104 pressure="global_bytes" cumulative_resumptions=1 global_retained_bytes=0 global_max_retained_bytes=4096',
            )) + "\n")
            (root / "echo-client.json").write_text(json.dumps({
                "local_endpoints": ["127.0.0.1:50000"],
            }))
            program = "".join(helper(name) for name in (
                "decision_records", "decision_marker_count_for_pid", "append_dial9_requirement",
                "close_pressure_probe_window", "check_echo_decisions", "check_udp_pressure_logs",
            )) + textwrap.dedent(f"""\
                TMP_DIR={shlex.quote(str(root))}
                SCRIPT_DIR={shlex.quote(str(live))}
                MODERN_EVIDENCE="$TMP_DIR/source-modern_udp_evidence.py"
                PROVIDER_LOG="$TMP_DIR/provider.log"
                DIAL9_REQUIREMENTS="$TMP_DIR/requirements.tsv"
                : > "$DIAL9_REQUIREMENTS"
                ECHO_CLIENT_RESULT="$TMP_DIR/echo-client.json"
                RUN_UUID={RUN_UUID} PROVIDER_PID=9001 UNBLOCKED_PROVIDER_GENERATION=7
                ECHO_SOURCE_PID=2002 ECHO_ENDPOINT=127.0.0.1:443 ECHO_SOCKET_COUNT=1
                ECHO_DATAGRAMS_PER_SOCKET=1 ECHO_PAYLOAD_BYTES=1200 ECHO_LOG_START=0 ECHO_LOG_END=1
                PASSTHROUGH_DNS_FLOW_ID=101 CONTROL_DNS_FLOW_ID=102 NTP_FLOW_ID=103
                PRESSURE_FLOW_ID=none RECOVERY_NTP_FLOW_ID=106 BLOCKED_DNS_FLOW_ID=105
                UNBLOCKED_LOG_LINE=0 PRESSURE_LOG_LINE=1 PRESSURE_END_LOG_LINE=4 BLOCKED_LOG_LINE=4
                ISSUES=0 FAILURES=0
                add_issue() {{ ISSUES=$((ISSUES + 1)); printf '%s\\n' "$1" >&2; }}
                add_failure() {{ FAILURES=$((FAILURES + 1)); printf '%s\\n' "$1" >&2; }}
                provider_log_line() {{ wc -l < "$PROVIDER_LOG"; }}
                sleep() {{ :; }}
                close_pressure_probe_window 1 1004 162.159.200.1:123 com.apple.python3 || exit 1
                [[ "$PRESSURE_FLOW_ID" == 104 && "$LAST_PROBE_LOG_END" -eq 4 ]] || exit 1
                check_echo_decisions || exit 1
                check_udp_pressure_logs || exit 1
                printf '%s %s %s %s %s %s %s %s %s\\n' "$ISSUES" "$FAILURES" \\
                  "$ECHO_FLOW_COUNT" "$UDP_PRESSURE_LOG_CHECKED" "$RUST_UDP_DROP_TRANSITIONS" \\
                  "$RUST_UDP_RESUME_TRANSITIONS" "$PRESSURE_DROP_REASONS" \\
                  "$PRESSURE_RECOVERED_REASONS" "$OUTSIDE_PRESSURE_EVENTS"
                [[ "$ISSUES" == 0 && "$FAILURES" == 0 ]]
            """)
            for generation, issues in ((7, 0), (8, 1)):
                with self.subTest(generation=generation):
                    result = subprocess.run(
                        ["/bin/bash", "-c", program.replace(
                            "UNBLOCKED_PROVIDER_GENERATION=7", f"UNBLOCKED_PROVIDER_GENERATION={generation}"
                        )], cwd=live, capture_output=True, text=True, timeout=10,
                        env={**{key: value for key, value in os.environ.items()
                                if key != "PYTHONDONTWRITEBYTECODE"}, "PYTHONPATH": str(live)},
                    )
                    self.assertEqual(result.returncode, issues, result.stdout + result.stderr)
                    self.assertEqual(result.stdout,
                                     f"{issues} 0 1 1 1 1 global_bytes global_bytes 0\n", result.stderr)
                    self.assertEqual(result.stderr, "" if issues == 0 else
                                     "controlled echo flow used a different unblocked provider generation\n")
                    self.assertEqual((root / "echo-identities.tsv").read_text(), "7\t1000\t127.0.0.1:50000\n")
                    self.assertEqual((root / "requirements.tsv").read_text(),
                                     "echo-0\t9001\t7\t1000\t2\t2002\t1\t1200\t1200\t1200\t1200\n")
            self.assertEqual(list(root.rglob("__pycache__")), [])

    def test_http3_shell_gate_uses_the_same_typed_local_endpoint_rule(self):
        helper = BoundedCommandCleanupTests.shell_function
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "http3-pids.tsv").write_text("".join(
                f"{index // 2 + 1}\t{index % 2 + 1}\t{3000 + index}\n" for index in range(6)
            ))
            (root / "http3-endpoints.txt").write_text("1.1.1.1:443\n")
            (root / "echo-identities.tsv").write_text("7\t1000\t127.0.0.1:50000\n")
            (root / "source-modern_udp_evidence.py").write_bytes(
                (SCRIPT_DIR / "modern_udp_evidence.py").read_bytes()
            )
            baseline = [
                _decision(RUN_UUID, 9001, 7, "passthrough", 2000 + index,
                          "1.1.1.1:443", "unavailable", "com.apple.nscurl", 3000 + index)
                for index in range(6)
            ]
            program = (
                helper("decision_records") + helper("decision_marker_count_for_pid")
                + helper("check_http3_decisions") + textwrap.dedent(f"""\
                    TMP_DIR={shlex.quote(str(root))}
                    MODERN_EVIDENCE="$TMP_DIR/source-modern_udp_evidence.py"
                    PROVIDER_LOG="$TMP_DIR/provider.log"
                    HTTP3_PIDS="$TMP_DIR/http3-pids.tsv"
                    HTTP3_ENDPOINTS="$TMP_DIR/http3-endpoints.txt"
                    HTTP3_PROVIDER_LOG_LINE=0 HTTP3_PROVIDER_LOG_END=6 HTTP3_REQUEST_COUNT=6
                    RUN_UUID={RUN_UUID} PROVIDER_PID=9001 UNBLOCKED_PROVIDER_GENERATION=7
                    PASSTHROUGH_DNS_FLOW_ID=101 CONTROL_DNS_FLOW_ID=102 NTP_FLOW_ID=103
                    PRESSURE_FLOW_ID=104 RECOVERY_NTP_FLOW_ID=106 BLOCKED_DNS_FLOW_ID=105
                    ISSUES=0
                    add_issue() {{ ISSUES=$((ISSUES + 1)); }}
                    check_http3_decisions
                    result=$?
                    [[ "$result" == 0 && "$ISSUES" == 0 ]]
                """)
            )
            for old, new, passed in (
                ("local_endpoint=unavailable", "local_endpoint=unavailable", True),
                ("local_endpoint=unavailable", "local_endpoint=127.0.0.1:52000", True),
                ("local_endpoint=unavailable", "local_endpoint=127.0.0.1:0", False),
                ("com.apple.nscurl", "com.apple.python3", False),
                ("remote_endpoint=1.1.1.1:443", "remote_endpoint=1.1.1.1:53", False),
                ("rama_decision=passthrough", "rama_decision=intercept", False),
                ("provider_generation=7", "provider_generation=8", False),
                ("source_pid=3000", "source_pid=3001", False),
            ):
                with self.subTest(old=old, new=new):
                    lines = baseline.copy()
                    lines[0] = lines[0].replace(old, new)
                    (root / "provider.log").write_text("\n".join(lines) + "\n")
                    result = subprocess.run(["/bin/bash", "-c", program], capture_output=True,
                                            text=True, timeout=5)
                    self.assertEqual(result.returncode == 0, passed, result.stdout + result.stderr)

    def test_run_probe_cross_checks_joined_exit_before_counting_a_pass(self):
        helper = BoundedCommandCleanupTests.shell_function
        for case in ("pass", "missing", "failed-raw", "bad-response", "child-exit", "blocked-violation"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                label = "blocked" if case == "blocked-violation" else "control"
                receipt = probe_receipt_fixture(label, 42, "8.8.8.8:53")
                child_exit = 20 if case == "child-exit" else 0
                if case in ("failed-raw", "bad-response"):
                    receipt["response_hex"] = "00"
                    receipt["exit_code"] = 20 if case == "failed-raw" else 0
                if case == "blocked-violation":
                    response = probe_receipt_fixture("control", 42, "8.8.8.8:53")
                    receipt.update(receive_outcome="response", response_hex=response["response_hex"],
                                   response_peer=response["response_peer"], exit_code=10)
                    child_exit = 10
                if case != "missing":
                    (root / f"udp-probe-{label}.json").write_text(json.dumps(receipt) + "\n")
                program = helper("run_probe") + textwrap.dedent(f"""\
                    TMP_DIR={shlex.quote(str(root))}
                    PROBE={shlex.quote(str(SCRIPT_DIR / 'modern_udp_e2e_probe.py'))}
                    RUN_UUID={shlex.quote(RUN_UUID)}
                    PROBE_RESULTS="$TMP_DIR/udp-probe-results.tsv"
                    printf 'label\\tsource_pid\\texit_code\\n' > "$PROBE_RESULTS"
                    UDP_PROBE_ATTEMPT_COUNT=0 UDP_PROBE_PASS_COUNT=0 ISSUES=0 FAILURES=0
                    provider_log_line() {{ printf '1\\n'; }}
                    start_owned_command() {{ OWNED_COMMAND_SOURCE_PID=42; OWNED_COMMAND_PID=41; }}
                    join_owned_command() {{ OWNED_JOIN_REAPED=1; return {child_exit}; }}
                    close_probe_decision_window() {{ :; }}
                    add_issue() {{ ISSUES=$((ISSUES + 1)); }}
                    add_failure() {{ FAILURES=$((FAILURES + 1)); }}
                    run_probe fixture {'10' if label == 'blocked' else 'none'} {label} dns 8.8.8.8
                    printf '%s %s %s %s\\n' "$UDP_PROBE_ATTEMPT_COUNT" \\
                      "$UDP_PROBE_PASS_COUNT" "$ISSUES" "$FAILURES"
                """)
                result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                expected = "1 1 0 0\n" if case == "pass" else (
                    "1 0 0 1\n" if case == "blocked-violation" else "1 0 1 0\n"
                )
                self.assertEqual(result.stdout, expected, result.stderr)
                self.assertEqual((root / "udp-probe-results.tsv").read_text(),
                                 f"label\tsource_pid\texit_code\n{label}\t42\t{child_exit}\n")

    def test_pressure_producer_records_accepted_not_sent_byte_bounds(self):
        helper = BoundedCommandCleanupTests.shell_function
        with tempfile.TemporaryDirectory() as temporary:
            requirements = Path(temporary) / "requirements.tsv"
            program = helper("check_exact_decision") + helper("append_dial9_requirement") + textwrap.dedent(f"""\
                DIAL9_REQUIREMENTS={shlex.quote(str(requirements))}
                RUN_UUID={shlex.quote(RUN_UUID)} PROVIDER_PID=9001
                PRESSURE_PAYLOAD_BYTES=4096 PRESSURE_EXPECTED_BYTES=2097152
                decision_records() {{
                  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \\
                    intercept 104 162.159.200.1:123 127.0.0.1:41004 \\
                    com.apple.python3 1004 "$RUN_UUID" 9001 7
                }}
                decision_marker_count_for_pid() {{ printf '1\\n'; }}
                is_canonical_udp_endpoint() {{ return 0; }}
                add_issue() {{ printf '%s\\n' "$1" >&2; exit 1; }}
                add_failure() {{ printf '%s\\n' "$1" >&2; exit 1; }}
                check_exact_decision 0 1 intercept 162.159.200.1:123 \\
                  com.apple.python3 1004 pressure pressure
            """)
            result = subprocess.run(
                ["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(requirements.read_text(),
                "pressure\t9001\t7\t104\t2\t1004\t1\t4096\t2093056\t0\t0\n")

    def test_finalizer_captures_late_collection_and_restoration_errors(self):
        helper = BoundedCommandCleanupTests.shell_function
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parser = root / "parser.py"
            parser.write_text("import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text().strip())\n")
            program = helper("finalize") + helper("check_final_provider_logs") + textwrap.dedent(f"""\
                TMP_DIR={shlex.quote(str(root))}
                BOUNDED_CLEANUP_FAILED="$TMP_DIR/failed"
                PROVIDER_LOG="$TMP_DIR/provider.log"
                EVIDENCE_STATUS="$TMP_DIR/status"
                MODERN_EVIDENCE={shlex.quote(str(parser))}
                : > "$PROVIDER_LOG"
                FINALIZING=0 MAIN_FINISHED=1 RUN_START_EPOCH_MS=1
                UDP_ERROR_PROVIDER_LOG_LINE=0 LOG_STREAM_JOINED=0
                UDP_PROBE_ATTEMPT_COUNT=9 UDP_PROBE_PASS_COUNT=9
                UDP_PRESSURE_LOG_CHECKED=1 PRESSURE_PROBE_ATTEMPTED=1 PRESSURE_PROBE_PASSED=1
                ISSUES=() FAILURES=() OBSERVED_FAILURES=()
                add_issue() {{ ISSUES+=("$1"); }}
                add_failure() {{ FAILURES+=("$1"); }}
                event() {{ printf '%s\\n' "$1" >> "$TMP_DIR/order"; }}
                stop_active_workloads() {{ event workloads; }}
                stop_echo_server() {{ event echo; }}
                collect_dial9_evidence() {{
                  event dial9
                  printf '%s\\n' 'flow_callback_error operation=udp_flow.read' >> "$PROVIDER_LOG"
                }}
                restore_profile() {{ event restore; printf 'late-pressure\\n' >> "$PROVIDER_LOG"; }}
                require_provider_identity() {{ :; }}
                capture_provider_generation_sample() {{ event generation; }}
                sleep() {{ :; }}
                stop_log_capture() {{ event log-stop; LOG_STREAM_JOINED=1; }}
                write_provider_log_phases() {{ event phases; wc -l < "$PROVIDER_LOG" > "$TMP_DIR/line-count"; }}
                check_udp_pressure_logs() {{
                  event pressure-verdict
                  if grep -q late-pressure "$PROVIDER_LOG"; then add_failure 'late pressure'; fi
                }}
                stop_provider_generation_monitor() {{ :; }}
                stop_remaining_owned_commands() {{ :; }}
                write_workload_claims() {{ :; }}
                write_evidence_status() {{ printf '%s\\n' "$3" > "$EVIDENCE_STATUS"; }}
                write_common_evidence_status() {{ printf '%s %s %s %s\\n' "$@" "${{#FAILURES[@]}}" > "$TMP_DIR/common-status"; }}
                run_bounded() {{ printf 'crash_count\\t0\\n'; }}
                finalize
            """)
            result = subprocess.run(["/bin/bash", "-c", program], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual((root / "common-status").read_text(), "1 0 1 2\n")
            self.assertEqual(int((root / "line-count").read_text()), 2)
            order = (root / "order").read_text().splitlines()
            self.assertEqual(order[:8], ["workloads", "echo", "restore", "dial9", "generation", "log-stop", "phases", "pressure-verdict"])

    def test_separate_clock_processes_measure_the_same_elapsed_window(self):
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        helper = re.search(r"^monotonic_ms_now\(\) \{\n.*?^\}", shell, re.M | re.S)
        self.assertIsNotNone(helper)
        started = time.monotonic()
        result = subprocess.run(
            ["bash", "-c", helper.group() + "\n"
             "first=$(monotonic_ms_now)\n"
             "sleep 0.1\n"
             "second=$(monotonic_ms_now)\n"
             "printf '%s %s\\n' \"$first\" \"$second\"\n"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=5,
        )
        elapsed_ms = (time.monotonic() - started) * 1000
        first, second = map(int, result.stdout.split())
        self.assertGreaterEqual(second - first, 90)
        self.assertLessEqual(second - first, elapsed_ms + 100)

    def test_restore_is_only_narrowly_exempted_for_paired_empty_overrides(self):
        swift = (SCRIPT_DIR.parent / "tproxy_app/Container/main.swift").read_text()
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        self.assertIn("lazy var isPersistedDefaultRestart", swift)
        self.assertIn("requestedUdpPassthroughPorts == []", swift)
        self.assertIn("requestedUdpBlockedEndpoints == []", swift)
        self.assertIn('"--udp-passthrough-ports="', shell)
        self.assertIn('"--udp-blocked-endpoints="', shell)

    def test_concurrent_load_has_one_outer_sub_ten_minute_deadline(self):
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        self.assertIn("CONCURRENT_LOAD_DEADLINE=$((SECONDS +", shell)
        self.assertIn("wait_for_child_until \"$ACTIVE_PRESSURE_PID\"", shell)
        self.assertIn("wait_for_child_until \"$ACTIVE_ECHO_PID\"", shell)
        self.assertIn("CONCURRENT_LOAD_DEADLINE_SECONDS >= 600", shell)
        self.assertGreaterEqual(
            shell.count("ACTIVE_WORKLOAD_FORCED_TERMINATION_COUNT=$(("), 1
        )

    def test_runtime_identity_uses_common_generation_samples_through_crash_snapshot(self):
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        self.assertIn("capture-provider-generation", shell)
        self.assertIn("PROVIDER_IDENTITY=\"$PROVIDER_GENERATION_IDENTITY\"", shell)
        finalizer = shell[shell.index("finalize() {"):shell.index("trap finalize EXIT")]
        before = finalizer.index('capture_provider_generation_sample --append')
        boundary = finalizer.index('RUN_END_EPOCH_MS="', before)
        crash = finalizer.index("snapshot-crashes", boundary)
        after = finalizer.index(
            'capture_provider_generation_sample --append', crash
        )
        stop = finalizer.index("stop_provider_generation_monitor", after)
        self.assertLess(before, boundary)
        self.assertLess(boundary, crash)
        self.assertLess(crash, after)
        self.assertLess(after, stop)

    def test_release_evidence_is_modern_only_and_sources_are_snapshotted(self):
        shell = (SCRIPT_DIR / "test_modern_udp_flow.sh").read_text()
        parser = (SCRIPT_DIR / "modern_udp_evidence.py").read_text()
        for name in (
            "source-test_modern_udp_flow.sh",
            "source-modern_udp_e2e_probe.py",
            "source-install_tproxy_app_bundle.sh",
            "source-modern_udp_evidence.py",
            "source-soak_pressure_log.py",
            "source-signed_run_evidence.py",
        ):
            self.assertIn(name, shell)
            self.assertIn(name, parser)
        self.assertIn('values["callback_generation"] == "modern"', parser)


if __name__ == "__main__":
    unittest.main()
