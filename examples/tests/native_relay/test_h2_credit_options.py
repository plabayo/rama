"""Exercise native fixture configuration through the shared runner."""

from contextlib import nullcontext, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from identity import Identity
from run import execute, parse_args


class FixtureStarted(Exception):
    """Stop before launching any fixture or packet recorder."""


class H2CreditOptionsTests(unittest.TestCase):
    def arguments(self, root, protocol="h2", extra=()):
        with patch("run.shutil.which", return_value="/test/tool"):
            return parse_args(["--output", str(root), "--protocol", protocol, *extra])

    def fixture_config(self, root, protocol="h2", extra=()):
        args = self.arguments(root, protocol, extra)
        args.peer, args.fixture = Path("peer"), Path("fixture")
        authority = Identity(root / "ca.pem", root / "ca.key")
        identity = Identity(root / "origin.pem", root / "origin.key")
        captured = {}

        def start(command, _log, environment=None):
            if command[0] == "peer":
                (root / "origin.log").write_text(
                    json.dumps({"ready": "127.0.0.1:51234"})
                )
                return nullcontext(Mock(returncode=0))
            self.assertEqual(command[0], "fixture")
            captured.update(json.loads((root / "relay-config.json").read_text()))
            raise FixtureStarted

        with patch("run.local_identities", return_value=(authority, identity)), patch(
            "run.running", side_effect=start
        ), patch("run.wait_ready"), patch("run.subprocess.run") as external:
            with self.assertRaises(FixtureStarted):
                execute(args)
            external.assert_not_called()
        return captured

    def test_actual_fixture_config_preserves_explicit_directional_budgets_in_negative(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            maxima = (
                "--h2-ingress-credit-max",
                "131072",
                "--h2-egress-credit-max",
                "262144",
            )
            normal = self.fixture_config(root, extra=maxima)
            negative = self.fixture_config(root, extra=(*maxima, "--without-mirroring"))
            self.assertEqual(normal["h2_ingress_initial_credit_max"], 131072)
            self.assertEqual(normal["h2_egress_initial_credit_max"], 262144)
            self.assertTrue(normal.pop("mirror"))
            self.assertFalse(negative.pop("mirror"))
            self.assertEqual(normal, negative)

    def test_mother_command_supplies_finite_h2_budgets_in_both_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            normal = self.fixture_config(root)
            negative = self.fixture_config(root, extra=("--without-mirroring",))
            for name in (
                "h2_ingress_initial_credit_max",
                "h2_egress_initial_credit_max",
            ):
                self.assertIsInstance(normal[name], int)
                self.assertGreater(normal[name], 65535)
                self.assertLess(normal[name], 2147483647)
                self.assertEqual(normal[name], negative[name])

    def test_non_h2_fixture_configuration_has_no_credit_options(self):
        with tempfile.TemporaryDirectory() as directory:
            for protocol in ("h1", "h3"):
                config = self.fixture_config(Path(directory), protocol)
                self.assertNotIn("h2_ingress_initial_credit_max", config)
                self.assertNotIn("h2_egress_initial_credit_max", config)

    def test_partial_and_foreign_protocol_options_fail_before_resource_checks(self):
        cases = [
            ("h2", ("--h2-ingress-credit-max", "65535"), "together"),
            ("h2", ("--h2-egress-credit-max", "65535"), "together"),
            (
                "h1",
                ("--h2-ingress-credit-max", "65535", "--h2-egress-credit-max", "65535"),
                "require --protocol h2",
            ),
            (
                "h3",
                ("--h2-ingress-credit-max", "65535", "--h2-egress-credit-max", "65535"),
                "require --protocol h2",
            ),
        ]
        for protocol, extra, message in cases:
            with self.subTest(protocol=protocol, extra=extra), patch(
                "run.shutil.which"
            ) as tools, redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as error:
                    parse_args(["--output", "/unused", "--protocol", protocol, *extra])
                self.assertEqual(error.exception.code, 2)
                self.assertIn(message, stderr.getvalue())
                tools.assert_not_called()

    def test_invalid_budget_range_or_type_is_not_silently_clamped(self):
        for name in ("--h2-ingress-credit-max", "--h2-egress-credit-max"):
            other = (
                "--h2-egress-credit-max"
                if "ingress" in name
                else "--h2-ingress-credit-max"
            )
            for value in ("0", "65534", "-1", "2147483648", "1.5", "True"):
                with self.subTest(name=name, value=value), patch(
                    "run.shutil.which"
                ) as tools, redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        parse_args(
                            [
                                "--output",
                                "/unused",
                                "--protocol",
                                "h2",
                                name,
                                value,
                                other,
                                "65535",
                            ]
                        )
                    self.assertEqual(error.exception.code, 2)
                    tools.assert_not_called()

    def test_exact_protocol_bounds_reach_fixture_without_reinterpretation(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.fixture_config(
                Path(directory),
                extra=(
                    "--h2-ingress-credit-max",
                    "65535",
                    "--h2-egress-credit-max",
                    "2147483647",
                ),
            )
            self.assertEqual(config["h2_ingress_initial_credit_max"], 65535)
            self.assertEqual(config["h2_egress_initial_credit_max"], 2147483647)
