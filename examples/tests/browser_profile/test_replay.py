"""Replay inputs must preserve flow identity and explicit current TLS policy."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
import subprocess
import sys
import tempfile
from unittest.mock import patch

from flows import ReplayTarget, compare_requests, replay_args
from replay import (
    run_replay,
    connection_variants,
    current_trust_ids,
    replay_environment,
    requests_from_wire,
)
from test_flow_bodies import fixture
from wire import HeaderBlock


class ReplayTests(unittest.TestCase):
    def test_websocket_replay_keeps_input_open_and_checks_the_echo(self):
        # This peer responds before EOF, like the CLI's actual line-based socket.
        peer = (
            "import sys, select; line=sys.stdin.readline(); "
            "sys.exit(9) if select.select([sys.stdin], [], [], .05)[0] else None; "
            "print(line, end='', flush=True)"
        )
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "replay.log"
            run_replay([sys.executable, "-c", peer], flow="ws", log=log)
            for peer in (
                "import sys; sys.stdin.readline(); print('wrong')",
                "import sys; line=sys.stdin.readline(); print(line*2, end='')",
            ):
                with self.assertRaisesRegex(ValueError, "echo"):
                    run_replay([sys.executable, "-c", peer], flow="ws", log=log)
            with self.assertRaises(subprocess.CalledProcessError):
                run_replay(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdin.readline(); sys.exit(7)",
                    ],
                    flow="ws",
                    log=log,
                )

    def test_body_fragments_are_bound_to_their_connection_and_stream(self):
        for protocol in ("h2", "h3"):
            frames = fixture(protocol)
            expected = frames[2].data
            frames[2] = replace(frames[2], data=b"")
            frames += [
                HeaderBlock(protocol, 20, 0, 1, False, (), expected),
                HeaderBlock(protocol, 21, 99, 1, False, (), b"other connection"),
                HeaderBlock(protocol, 22, 0, 3, False, (), b"\x88\x00"),
            ]
            requests = requests_from_wire(frames)
            self.assertEqual(requests["fetch"][0].body, expected)
            self.assertEqual(requests["ws"][0].body, b"")
            self.assertEqual(len(requests), 6)
            with self.assertRaisesRegex(ValueError, "coverage"):
                requests_from_wire(frames[2:])

    def test_te_trailers_is_a_current_binding_on_every_multiplexed_flow(self):
        for protocol in ("h2", "h3"):
            frames = fixture(protocol)
            frames = [
                (
                    replace(frame, headers=frame.headers + (("te", "trailers"),))
                    if frame.headers and not frame.from_server
                    else frame
                )
                for frame in frames
            ]
            requests = requests_from_wire(frames)
            for flow, rows in requests.items():
                with self.subTest(protocol=protocol, flow=flow):
                    request = rows[0]
                    if flow == "ws":
                        request.bindings["sec-websocket-protocol"] = "a,b"
                    self.assertEqual(request.bindings.get("te"), "trailers")
                    args = replay_args(
                        Path("rama"),
                        Path("profiles.json"),
                        Path("response"),
                        ReplayTarget(protocol, "https://localhost:4433"),
                        flow,
                        request,
                    )
                    self.assertIn("te: trailers", args)
            invalid = list(frames)
            first = next(
                index
                for index, frame in enumerate(invalid)
                if frame.headers and not frame.from_server
            )
            for changed in [
                (("te", "gzip"),),
                (("te", "trailers"), ("te", "trailers")),
            ]:
                invalid[first] = replace(
                    frames[first],
                    headers=tuple(
                        (key, value)
                        for key, value in frames[first].headers
                        if key != "te"
                    )
                    + changed,
                )
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    requests_from_wire(invalid)

    def test_tls_replay_preserves_protocol_and_current_bindings(self):
        request = requests_from_wire(fixture("h2"))["ws"][0]
        request.bindings["sec-websocket-protocol"] = "a, b"
        request.bindings["origin"] = "https://original.invalid"
        for protocol, flag in (("h2", "--http2"), ("h3", "--http3")):
            args = replay_args(
                Path("rama"),
                Path("profiles.json"),
                Path("response"),
                ReplayTarget(
                    protocol, "https://localhost:4433", Path("fixture.pem"), "ab,cd"
                ),
                "ws",
                request,
            )
            self.assertIn(flag, args)
            self.assertNotIn("--http1.1", args)
            self.assertEqual(args[-1], "wss://localhost:4433/api/ws")
            self.assertEqual(args[args.index("--cacert") + 1], "fixture.pem")
            self.assertEqual(
                args[args.index("--tls-requested-trust-anchors") + 1], "ab,cd"
            )
            self.assertIn("origin: https://localhost:4433", args)
            self.assertIn("CONNECT", args)

    def test_actual_replay_cannot_change_a_request_bound_field_or_body(self):
        reference = requests_from_wire(fixture("h2"))
        replayed = {flow: list(requests) for flow, requests in reference.items()}
        self.assertTrue(
            all(row["match"] for row in compare_requests(reference, replayed))
        )
        original = replayed["fetch"][0]
        for altered in (
            replace(original, body=b"wrong"),
            replace(
                original,
                headers=original.headers + (("origin", "https://wrong.invalid"),),
            ),
        ):
            replayed["fetch"] = [altered]
            result = {row["flow"]: row for row in compare_requests(reference, replayed)}
            self.assertFalse(result["fetch"]["match"])

    def test_all_connection_variants_are_enumerated_and_explicitly_pinned(self):
        inspected = {
            "profiles": [
                {
                    "scopes": [
                        {
                            "variants": [
                                {"id": [1] * 32, "capture": {"level": "Connection"}},
                                {"id": [2] * 32, "capture": {"level": "Connection"}},
                                {"id": [3] * 32, "capture": {"level": "Request"}},
                            ]
                        }
                    ]
                }
            ]
        }
        variants = connection_variants(inspected)
        self.assertEqual(variants, ["01" * 32, "02" * 32])
        request = requests_from_wire(fixture("h2"))["navigate"][0]
        for variant in variants:
            args = replay_args(
                Path("rama"),
                Path("profiles.json"),
                Path("output"),
                ReplayTarget("h2", "https://localhost:4433"),
                "navigate",
                request,
                connection_variant=variant,
            )
            self.assertEqual(
                args[args.index("--emulate-connection-variant") + 1], variant
            )

    def test_current_ids_have_the_retained_shape_and_use_new_bytes(self):
        for length in (2, 4, 186, 257, 258, 259, 65535):
            hello = SimpleNamespace(
                capture={
                    "extensions": [
                        {"id": 51764, "value": {"ConnectionLength": length}},
                    ]
                }
            )
            with patch(
                "replay.secrets.token_bytes", side_effect=lambda size: b"x" * size
            ):
                value = current_trust_ids([hello])
            ids = [bytes.fromhex(item) for item in value.split(",")] if value else []
            self.assertTrue(all(1 <= len(item) <= 255 for item in ids))
            self.assertTrue(all(set(item) == {ord("x")} for item in ids))
            self.assertEqual(2 + sum(1 + len(item) for item in ids), length)
        for length in (0, 1, 3, 65536, 1 << 63):
            hello.capture["extensions"][0]["value"]["ConnectionLength"] = length
            with self.assertRaisesRegex(ValueError, "length"):
                current_trust_ids([hello])

    def test_replay_database_cannot_mix_with_reference_or_parent_storage(self):
        dsn = "host=127.0.0.1 port=1234 dbname=rama_fp_capture"
        parent = {
            key: dsn
            for key in (
                "DATABASE_URL",
                "RAMA_FP_DATABASE_URL",
                "RAMA_BROWSER_CAPTURE_DATABASE_URL",
            )
        }
        parent["RAMA_BROWSER_TEST_PG_CONTAINER"] = "owned"
        with patch("replay.subprocess.run") as run:
            replay = replay_environment(parent)
            self.assertTrue(
                all(
                    "dbname=rama_fp_replay" in replay[key]
                    for key in parent
                    if key.endswith("URL")
                )
            )
            self.assertEqual(parent["DATABASE_URL"], dsn)
            self.assertIn("owned", run.call_args.args[0])
            parent["DATABASE_URL"] = "production"
            run.reset_mock()
            with self.assertRaisesRegex(ValueError, "identities differ"):
                replay_environment(parent)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
