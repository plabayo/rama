"""Exercise the actual runner's report/strict decision with real packet fixtures."""

from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch

from identity import Identity
from comparison import compare_legs
from run import execute, main

FIXTURES = Path(__file__).parent / "tests/fixtures"


class NativeRunnerTests(unittest.TestCase):
    def run_fixture(
        self,
        root,
        *,
        allow_differences,
        ua_enabled=False,
        protocol="h1",
        websocket=None,
        http_fidelity=None,
        h2_policy=False,
        matching_credit=False,
        without_mirroring=False,
    ):
        ports = json.loads((FIXTURES / "http-contract-captures.json").read_text())[
            protocol
        ]["ports"]
        ingress, egress = ports["ingress"], ports["egress"]
        args = SimpleNamespace(
            output=root,
            protocol=protocol,
            quic_version=1,
            peer=Path("peer"),
            fixture=Path("fixture"),
            interface="lo",
            allow_differences=allow_differences,
            without_mirroring=without_mirroring,
            retry=None,
            h2_ingress_credit_max=64 * 1024 * 1024 if h2_policy else None,
            h2_egress_credit_max=1536 * 1024 * 1024 if h2_policy else None,
        )
        authority = Identity(root / "ca.pem", root / "ca.key")
        origin = Identity(root / "origin.pem", root / "origin.key")

        def start(command, _log, environment=None):
            if command[0] == "peer":
                (root / "origin.log").write_text(
                    json.dumps(dict(ready=f"127.0.0.1:{egress}"))
                )
            elif command[0] == "fixture":
                (root / "relay-ready.json").write_text(
                    json.dumps(
                        dict(
                            listen=f"127.0.0.1:{ingress}",
                            ua_enabled=ua_enabled,
                        )
                    )
                )
            elif command[0] == "dumpcap":
                (root / "wire.pcapng").write_bytes(b"owned capture")
            return nullcontext(Mock(returncode=0))

        def command(arguments, **kwargs):
            if arguments[0] == "peer":
                return subprocess.CompletedProcess(arguments, 0, stdout="{}\n{}\n")
            if arguments[0] == "tshark":
                decode = arguments[arguments.index("-d") + 1]
                keylog = arguments[arguments.index("-o") + 1]
                side = "ingress" if str(ingress) in decode else "egress"
                self.assertTrue(
                    keylog.endswith(
                        "client.keys" if side == "ingress" else "origin.keys"
                    )
                )
                data = (FIXTURES / (protocol + "-" + side + ".pdml")).read_bytes()
                if matching_credit and protocol == "h2" and side == "egress":
                    document = ET.fromstring(data)
                    # Make the actual egress client's literal increment equal ingress.
                    update = next(
                        document.iterfind(
                            ".//field[@name='http2.window_update.window_size_increment']"
                        )
                    )
                    self.assertEqual(update.get("unmaskedvalue"), "004f0001")
                    update.set("value", "40000000")
                    update.set("unmaskedvalue", "40000000")
                    data = ET.tostring(document)
                kwargs["stdout"].write(data)
                return subprocess.CompletedProcess(arguments, 0)
            raise AssertionError(arguments)

        def comparison(*args, **kwargs):
            report = compare_legs(*args, **kwargs)
            if http_fidelity is not None:
                # Isolate runner aggregation from the known old HTTP differences;
                # the real comparison and functional checks still ran above.
                report["fingerprint_match"] = http_fidelity
            return report

        with patch("run.local_identities", return_value=(authority, origin)), patch(
            "run.running",
            side_effect=start,
        ), patch("run.wait_ready"), patch(
            "run.run_probe",
            return_value=(
                websocket if websocket is not None else {"byte_preservation": True}
            ),
        ), patch(
            "run.subprocess.run", side_effect=command
        ), patch(
            "run.compare_legs", side_effect=comparison
        ):
            return execute(args)

    def test_strict_mode_persists_the_real_report_before_refusing_differences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "native fingerprint differs"):
                self.run_fixture(root, allow_differences=False)
            report = json.loads((root / "comparison.json").read_text())
            self.assertFalse(report["fingerprint_match"])
            self.assertTrue(report["supported_tls_facts_match"])
            self.assertFalse(report["ua_enabled"])

    def test_contract_mode_keeps_the_fingerprint_failure_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(self.run_fixture(root, allow_differences=True), 0)
            report = json.loads((root / "comparison.json").read_text())
            self.assertFalse(report["fingerprint_match"])
            self.assertTrue(report["bodies_and_trailers_match"])

    def test_h2_websocket_credit_difference_is_strict_and_remains_visible(self):
        for allow in (False, True):
            with self.subTest(
                allow_differences=allow
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                options = dict(
                    allow_differences=allow,
                    protocol="h2",
                    http_fidelity=True,
                    websocket={
                        "byte_preservation": True,
                        "h2_initial_credit_match": False,
                    },
                )
                if allow:
                    self.assertEqual(self.run_fixture(root, **options), 0)
                else:
                    with self.assertRaisesRegex(
                        ValueError, "native fingerprint differs"
                    ):
                        self.run_fixture(root, **options)
                report = json.loads((root / "comparison.json").read_text())
                self.assertTrue(report["http_fingerprint_match"])
                self.assertFalse(report["fingerprint_match"])
                self.assertTrue(report["bodies_and_trailers_match"])
                self.assertFalse(report["websocket"]["h2_initial_credit_match"])

    def test_paired_mirroring_credit_is_required_even_when_differences_allowed(self):
        for http_match, ws_match in ((False, True), (True, False)):
            with self.subTest(
                http=http_match, websocket=ws_match
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaisesRegex(
                    ValueError, "mirrored H2 initial credit differs"
                ):
                    self.run_fixture(
                        root,
                        allow_differences=True,
                        protocol="h2",
                        h2_policy=True,
                        matching_credit=http_match,
                        websocket={
                            "byte_preservation": True,
                            "h2_initial_credit_match": ws_match,
                        },
                    )
                report = json.loads((root / "comparison.json").read_text())
                self.assertEqual(report["h2_initial_credit_match"], http_match)
                self.assertEqual(
                    report["websocket"]["h2_initial_credit_match"], ws_match
                )
                self.assertFalse(report["fingerprint_match"])
                self.assertTrue(report["bodies_and_trailers_match"])

    def test_paired_mirroring_credit_does_not_hide_other_fingerprint_differences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(
                self.run_fixture(
                    root,
                    allow_differences=True,
                    protocol="h2",
                    h2_policy=True,
                    matching_credit=True,
                    websocket={
                        "byte_preservation": True,
                        "h2_initial_credit_match": True,
                    },
                ),
                0,
            )
            report = json.loads((root / "comparison.json").read_text())
            self.assertTrue(report["h2_initial_credit_match"])
            self.assertFalse(report["fingerprint_match"])

    def test_without_mirroring_keeps_credit_difference_as_negative_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(
                self.run_fixture(
                    root,
                    allow_differences=True,
                    protocol="h2",
                    h2_policy=True,
                    without_mirroring=True,
                    websocket={
                        "byte_preservation": True,
                        "h2_initial_credit_match": False,
                    },
                ),
                0,
            )
            report = json.loads((root / "comparison.json").read_text())
            self.assertFalse(report["mirror_requested"])
            self.assertFalse(report["h2_initial_credit_match"])
            self.assertFalse(report["fingerprint_match"])

    def test_h2_websocket_credit_witness_cannot_be_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                ValueError, "missing WebSocket H2 initial-credit"
            ):
                self.run_fixture(Path(directory), allow_differences=True, protocol="h2")

    def test_runtime_ua_feature_must_be_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "must have UA disabled"):
                self.run_fixture(
                    Path(directory), allow_differences=True, ua_enabled=True
                )


class DecoderAdmissionTests(unittest.TestCase):
    def test_missing_h3_decoder_fails_before_allocating_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unused"
            args = SimpleNamespace(
                protocol="h3",
                output=output,
                inside_disposable_database=False,
                postgres_image="unused",
            )
            with patch("run.parse_args", return_value=args), patch(
                "run.require_h3_tshark", side_effect=RuntimeError("missing H3 decoder")
            ), patch("run.build_binaries", return_value=0) as allocate, patch(
                "run.execute", return_value=0
            ):
                with self.assertRaisesRegex(RuntimeError, "missing H3 decoder"):
                    main()
            allocate.assert_not_called()
            self.assertFalse(output.exists())
