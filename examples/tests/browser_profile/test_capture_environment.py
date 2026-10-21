"""Guard capture admission and restoration, including failed setup paths."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import capture_environment as environment


class EnvironmentTests(unittest.TestCase):
    def test_feature_parser_rejects_missing_ambiguous_and_malformed_states(self):
        for text in ("", "tx-udp-segmentation: unknown", "tx-udp-segmentation: off\ntx-udp-segmentation: on",
                     "tx-udp-segmentation: off [unknown]"):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                environment.udp_segmentation(text)
        self.assertEqual(environment.udp_segmentation("tx-udp-segmentation: off [fixed]\n"), "off")
        self.assertEqual(environment.udp_segmentation("other: off\ntx-udp-segmentation: on\n"), "on")

    def test_unsafe_interface_fails_without_mutation_or_probe(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment.sys, "platform", "linux"), patch.object(
            environment, "offload_state", return_value="on"
        ), patch.object(environment, "segmented_probe") as probe, patch.object(environment.subprocess, "run") as mutate:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "sudo ethtool -K lo"):
                environment.require_capture_environment("lo", root)
            probe.assert_not_called()
            mutate.assert_not_called()
            report = json.loads((root / environment.REPORT).read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report[environment.FEATURE], "on")

    def test_unavailable_tools_fail_with_persistent_bounded_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment.sys, "platform", "linux"), patch.object(
            environment, "offload_state", side_effect=subprocess.CalledProcessError(1, "ethtool", stderr="private-output")
        ):
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "install packet tools"):
                environment.require_capture_environment("lo", root)
            self.assertNotIn("private-output", (root / environment.REPORT).read_text())

    def test_off_is_not_enough_without_real_packet_probe(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment.sys, "platform", "linux"), patch.object(
            environment, "offload_state", return_value="off"
        ), patch.object(environment, "segmented_probe", side_effect=RuntimeError("bad capture")):
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "bad capture"):
                environment.require_capture_environment("lo", root)
            self.assertEqual(json.loads((root / environment.REPORT).read_text())["status"], "failed")

    def test_probe_rejects_coalescing_loss_duplicates_and_unexpected_sizes(self):
        environment.check_lengths([1208] * 3)
        for lengths in ([3608], [], [1208] * 2, [1208] * 4, [1208, 1208, 1209]):
            with self.subTest(lengths=lengths), self.assertRaises(RuntimeError):
                environment.check_lengths(lengths)

    def test_failed_probe_records_numeric_boundary_evidence(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment.sys, "platform", "linux"), patch.object(
            environment, "offload_state", return_value="off"
        ), patch.object(environment, "segmented_probe", side_effect=environment.PacketBoundaryError([3608])):
            root = Path(directory)
            with self.assertRaises(environment.PacketBoundaryError):
                environment.require_capture_environment("lo", root)
            report = json.loads((root / environment.REPORT).read_text())
            self.assertEqual(report["stage"], "segmented_udp_probe")
            self.assertEqual(report["probe"], {"captured_udp_lengths": [3608], "captured_datagrams": 1})

    def test_macos_does_not_need_or_change_linux_features(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment.sys, "platform", "darwin"), patch.object(
            environment, "offload_state"
        ) as read, patch.object(environment, "segmented_probe") as probe:
            environment.require_capture_environment("lo0", Path(directory))
            read.assert_not_called()
            probe.assert_not_called()

    def test_unrelated_linux_interface_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment.sys, "platform", "linux"), patch.object(
            environment, "offload_state"
        ) as read:
            with self.assertRaisesRegex(RuntimeError, "require --interface lo"):
                environment.require_capture_environment("eth0", Path(directory))
            read.assert_not_called()


class RestorationTests(unittest.TestCase):
    def test_already_disabled_feature_is_never_enabled(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment, "offload_state", return_value="off"), patch.object(
            environment.subprocess, "run"
        ) as mutate:
            path = Path(directory) / "state"
            environment.configure_ci("prepare-ci", path)
            environment.configure_ci("restore-ci", path)
            mutate.assert_not_called()
            self.assertFalse(path.exists())

    def test_failed_preparation_keeps_original_state_for_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment, "offload_state", return_value="on"), patch.object(
            environment.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "ethtool")
        ):
            path = Path(directory) / "state"
            with self.assertRaises(subprocess.CalledProcessError):
                environment.configure_ci("prepare-ci", path)
            self.assertEqual(path.read_text(), "on\n")
            # A partially successful command may have changed the feature before
            # failing. Cleanup must still restore the saved original value.
            with patch.object(environment, "offload_state", side_effect=["off", "on"]), patch.object(
                environment.subprocess, "run"
            ) as mutate:
                environment.configure_ci("restore-ci", path)
                self.assertEqual(mutate.call_args.args[0][-2:], [environment.FEATURE, "on"])
                self.assertFalse(path.exists())

    def test_prepare_cannot_overwrite_saved_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment, "offload_state", return_value="off"), patch.object(
            environment.subprocess, "run"
        ) as mutate:
            path = Path(directory) / "state"
            path.write_text("on\n")
            with self.assertRaises(FileExistsError):
                environment.configure_ci("prepare-ci", path)
            self.assertEqual(path.read_text(), "on\n")
            mutate.assert_not_called()

    def test_silent_restore_failure_retains_recovery_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment, "offload_state", return_value="off"), patch.object(
            environment.subprocess, "run"
        ):
            path = Path(directory) / "state"
            path.write_text("on\n")
            with self.assertRaisesRegex(RuntimeError, "did not take effect"):
                environment.configure_ci("restore-ci", path)
            self.assertEqual(path.read_text(), "on\n")

    def test_missing_state_is_noop_invalid_state_cannot_be_executed(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(environment, "offload_state") as read:
            path = Path(directory) / "state"
            environment.configure_ci("restore-ci", path)
            path.write_text("on --other-device eth0")
            with self.assertRaisesRegex(RuntimeError, "invalid saved"):
                environment.configure_ci("restore-ci", path)
            read.assert_not_called()
