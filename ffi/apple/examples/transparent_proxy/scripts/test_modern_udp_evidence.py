#!/usr/bin/env python3
"""Adversarial unit coverage for the signed modern UDP evidence path."""

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
import subprocess
import sys
import tempfile
import threading
import textwrap
import time
import unittest
from unittest import mock


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
                UDP_PROBE_ATTEMPT_COUNT=8 UDP_PROBE_PASS_COUNT=8
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
        "udp_probe_attempt_count": "8", "udp_probe_pass_count": "8",
        "udp_pressure_log_checked": "1", "rust_udp_drop_transitions": "1",
        "rust_udp_resume_transitions": "1", "swift_udp_staging_drop_samples": "0",
        "log_stream_started": "1", "log_stream_alive_end": "1",
        "log_stream_joined": "1", "profile_restored": "1",
        "dial9_baseline_max_index": "7", "callback_generation": "modern",
        "dial9_required_flow_id": "103", "dial9_current_segment_count": "1",
        "dial9_required_pair_count": "131", "dial9_required_close_reason": "1",
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
        "dial9_requirement_count": "131", "dial9_matched_requirement_count": "131",
        "schema_version": "5", "schema_complete": "1",
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
    (directory / "provider.log").write_text("\n".join(lines) + "\n")

    phase_rows = (
        ("schema_version", 1), ("unblocked_start_line", 0),
        ("udp_error_start_line", 0), ("passthrough_start_line", 0),
        ("passthrough_end_line", 1), ("ntp_start_line", 1), ("ntp_end_line", 2),
        ("control_start_line", 2), ("control_end_line", 3),
        ("pressure_start_line", 3), ("pressure_end_line", 134),
        ("echo_start_line", 3), ("echo_end_line", 134),
        ("recovery_start_line", 134), ("recovery_end_line", 135),
        ("http3_start_line", 135), ("http3_end_line", 141),
        ("blocked_profile_start_line", 141), ("blocked_start_line", 141),
        ("blocked_end_line", 142), ("provider_log_end_line", 142),
        ("schema_complete", 1),
    )
    (directory / "provider-log-phases.tsv").write_text(
        "".join(f"{key}\t{value}\n" for key, value in phase_rows)
    )

    client = {
        "schema_version": 1, "kind": "controlled_echo_client", "run_uuid": RUN_UUID,
        "endpoint": echo_endpoint, "socket_count": 128, "datagrams_per_socket": 1,
        "payload_bytes": 1200, "expected_count": 128, "sent_count": 128,
        "received_count": 128, "exact_echo_count": 128, "unique_echo_count": 128,
        "independent_socket_count": 128, "local_endpoints": echo_endpoints,
        "local_endpoint_set_sha256": hashlib.sha256("\n".join(echo_endpoints).encode()).hexdigest(),
        "payload_set_sha256": echo_digest, "echo_set_sha256": echo_digest,
        "error_count": 0, "passed": True, "schema_complete": True,
        "interval_ms": 0, "start_epoch_ms": 1500, "end_epoch_ms": 1501,
        "start_monotonic_ns": 1000000000, "end_monotonic_ns": 1001000000,
        "packet_timings_ns": [[index, 0, 1000000000, 1001000000] for index in range(128)],
    }
    server = {
        "schema_version": 1, "kind": "controlled_echo_server", "run_uuid": RUN_UUID,
        "endpoint": echo_endpoint, "expected_count": 128, "received_count": 128,
        "echo_count": 128, "duplicate_count": 0, "malformed_count": 0,
        "payload_set_sha256": echo_digest, "passed": True, "schema_complete": True,
    }
    ready = {
        "schema_version": 1, "run_uuid": RUN_UUID, "endpoint": echo_endpoint,
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

    requirement_rows = [
        "label\tprovider_pid\tprovider_generation\tflow_id\tprotocol\tsource_pid\tclose_reason\tmin_bytes_in\tmax_bytes_in\tmin_bytes_out\tmax_bytes_out\n",
        "ntp\t9001\t7\t103\t2\t1003\t1\t48\t65535\t48\t65535\n",
        "pressure\t9001\t7\t104\t2\t1004\t1\t4096\t2093056\t0\t0\n",
        "recovery-ntp\t9001\t7\t106\t2\t1006\t1\t48\t65535\t48\t65535\n",
    ]
    requirement_rows.extend(
        f"echo-{index}\t9001\t7\t{flow_id}\t2\t2002\t1\t1200\t1200\t1200\t1200\n"
        for index, flow_id in enumerate(echo_flows)
    )
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
        f"[1970-01-01T00:00:04Z] INFO: {message}\n" for message in restore_messages
    )
    (directory / "restore-container.log").write_text(restore_slice)
    (directory / "restore.log").write_text(
        "restore_invocation schema=1 mode=dev reset_profile=0 "
        "udp_passthrough_ports=empty udp_blocked_endpoints=empty evidence_identity=absent\n"
    )
    restore_rows = (
        ("schema_version", 1), ("run_uuid", RUN_UUID), ("provider_pid", provider_pid),
        ("replaced_provider_generation", blocked_generation),
        ("restore_started_epoch_ms", 4000), ("restore_completed_epoch_ms", 4500),
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
        "dial9_requirement_count\t131\n"
        "dial9_matched_requirement_count\t131\n"
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
        "snapshot_epoch_ms\t6000\n"
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
        "sample_count\t3\n"
        f"sample_000001\t900|{generation_tail}\n"
        f"sample_000002\t3000|{generation_tail}\n"
        f"sample_000003\t6000|{generation_tail}\n"
        "schema_complete\t1\n"
    )
    engine_digest = hashlib.sha256(b"9001:7:8").hexdigest()
    _write_status(directory, {
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
        for old, new in ((DIGEST, "b" * 64), ("snapshot_epoch_ms\t6000", "snapshot_epoch_ms\t4999")):
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

        def settimeout(self, seconds):
            self.timeout = seconds

        def sendto(self, packet, peer):
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

        def echo():
            for _ in range(8):
                payload, peer = server.recvfrom(65535)
                server.sendto(payload, peer)
            server.close()

        thread = threading.Thread(target=echo)
        thread.start()
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.json"
            controlled_echo_load(
                "127.0.0.1", port, RUN_UUID, 8, 1, 1200, 4, 2, str(result)
            )
            value = json.loads(result.read_text())
            self.assertTrue(value["passed"])
            self.assertEqual(value["exact_echo_count"], 8)
            self.assertEqual(value["independent_socket_count"], 8)
            self.assertEqual(value["payload_set_sha256"], value["echo_set_sha256"])
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

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
                UDP_PROBE_ATTEMPT_COUNT=8 UDP_PROBE_PASS_COUNT=8
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
            self.assertEqual(order[:8], ["workloads", "echo", "dial9", "restore", "generation", "log-stop", "phases", "pressure-verdict"])

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
