"""Replay inputs must preserve flow identity and explicit current TLS policy."""

import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from flows import ReplayTarget, compare_requests, replay_args, request_segments
from pathlib import Path
from replay import (
    check_missing_tls_bindings,
    check_tls_hostname,
    connection_variants,
    connection_warmups,
    current_trust_ids,
    replay_environment,
    requests_from_wire,
    run_replay,
)
from types import SimpleNamespace
from unittest.mock import patch
from wire import HeaderBlock, Request
from wire_fixtures import flow_fixture as fixture


def warmup_pins(command):
    """Connection pins of the bootstrap warmup segments preceding the operation."""
    pins = []
    for segment in request_segments(command)[:-1]:
        if "--emulate-connection-bootstrap" not in segment:
            raise AssertionError("warmup segment lacks its bootstrap marker")
        pins.append(segment[segment.index("--emulate-connection-variant") + 1])
    return pins


def main_pin(command):
    segment = request_segments(command)[-1]
    return segment[segment.index("--emulate-connection-variant") + 1]


class ReplayTests(unittest.TestCase):
    def test_replay_keeps_actual_fetch_context_for_every_protocol_and_flow(self):
        methods = {
            "navigate": "GET",
            "fetch": "POST",
            "xhr": "POST",
            "ws": "CONNECT",
            "form": "POST",
            "form_get": "GET",
        }
        for protocol in ("h1", "h2", "h3"):
            for flow, method in methods.items():
                for activation in (None, "?1"):
                    with self.subTest(
                        protocol=protocol, flow=flow, activation=activation
                    ):
                        expected = {
                            "sec-fetch-mode": (
                                "navigate" if flow == "navigate" else "cors"
                            ),
                            "sec-fetch-site": "none" if activation else "same-origin",
                            "sec-fetch-dest": (
                                "document" if flow == "navigate" else "empty"
                            ),
                        }
                        if activation is not None:
                            expected["sec-fetch-user"] = activation
                        request = Request(
                            "GET" if flow == "ws" and protocol == "h1" else method,
                            "/api/ws" if flow == "ws" else "/report",
                            tuple(
                                (
                                    name.upper() + ": \t" + value
                                    if protocol == "h1"
                                    else (name.upper(), value)
                                )
                                for name, value in expected.items()
                            ),
                            b"",
                            {"sec-websocket-protocol": "a,b"} if flow == "ws" else {},
                            protocol,
                        )
                        command = replay_args(
                            Path("rama"),
                            Path("profiles.json"),
                            Path("response"),
                            ReplayTarget(protocol, "https://localhost:4433"),
                            flow,
                            request,
                        )
                        emitted = dict(
                            item.removeprefix("--header=").split(": ", 1)
                            for item in command
                            if item.startswith("--header=")
                        )
                        self.assertEqual(emitted, expected)
                        self.assertNotIn("--emulate-request-variant", command)

    def test_replay_does_not_invent_absent_fetch_context(self):
        request = Request("POST", "/api/fetch/number/1", (), b"", {})
        command = replay_args(
            Path("rama"),
            Path("profiles.json"),
            Path("response"),
            ReplayTarget("h3", "https://localhost:4433"),
            "fetch",
            request,
        )
        self.assertFalse(any(item.startswith("--header") for item in command))

    def test_replay_rejects_duplicate_fetch_context_case_insensitively(self):
        for name in (
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-dest",
            "sec-fetch-user",
        ):
            request = Request(
                "GET", "/report", ((name, "first"), (name.upper(), "second")), b"", {}
            )
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "ambiguous replay Fetch context"),
            ):
                replay_args(
                    Path("rama"),
                    Path("profiles.json"),
                    Path("response"),
                    ReplayTarget("h3", "https://localhost:4433"),
                    "navigate",
                    request,
                )


    def test_absent_alt_used_is_not_invented_from_bindings_or_other_headers(self):
        for protocol in ("h1", "h2", "h3"):
            for raw in (False, True):
                observed = (
                    ("Authorization", "Bearer private-main"),
                    ("Cookie", "session=private-main"),
                    ("X-Alt-Used", "stale-route.invalid:1234"),
                )
                headers = (
                    tuple(name + ": " + value for name, value in observed)
                    if raw
                    else observed
                )
                request = Request(
                    "GET",
                    "/report",
                    headers,
                    b"",
                    {"alt-used": "stale-route.invalid:1234"},
                )
                with self.subTest(protocol=protocol, raw=raw):
                    args = replay_args(
                        Path("rama"),
                        Path("profile"),
                        Path("output"),
                        ReplayTarget(protocol, "https://current.example:8443"),
                        "navigate",
                        request,
                    )
                    self.assertFalse(
                        any(value.lower().startswith("alt-used:") for value in args)
                    )
                    self.assertNotIn("private-main", " ".join(args))
                    self.assertNotIn("stale-route", " ".join(args))

    def test_ambiguous_alt_used_observations_are_rejected(self):
        for raw in (False, True):
            observed = (
                ("Alt-Used", "old-a.invalid:443"),
                ("alt-used", "old-b.invalid:443"),
            )
            headers = (
                tuple(name + ": " + value for name, value in observed)
                if raw
                else observed
            )
            request = Request("GET", "/report", headers, b"", {})
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(ValueError, "ambiguous replay Alt-Used route"),
            ):
                replay_args(
                    Path("rama"),
                    Path("profile"),
                    Path("output"),
                    ReplayTarget("h3", "https://current.example:8443"),
                    "navigate",
                    request,
                )

    def test_missing_ca_requires_a_certificate_error_or_quic_unknown_ca(self):
        command = ["rama", "send", "--cacert", "fixture.pem", "https://localhost/"]
        unknown_ca = (
            "the cryptographic handshake failed: error 48: TLS handshake failed"
        )
        for protocol, error, accepted in [
            ("h3", unknown_ca, True),
            ("h2", unknown_ca, False),
            ("h3", "resumed TLS requires a current peer-issued ticket", False),
            (
                "h3",
                "the cryptographic handshake failed: error 80: TLS handshake failed",
                False,
            ),
        ]:
            with (
                self.subTest(protocol=protocol, error=error),
                tempfile.TemporaryDirectory() as root,
            ):
                calls = []

                def reject(arguments, **kwargs):
                    calls.append(arguments)
                    if "--cacert" in arguments:
                        self.assertIn("--resolve", arguments)
                        kwargs["stdout"].write(
                            "certificate verify failed: hostname mismatch"
                        )
                    else:
                        kwargs["stdout"].write(error)
                    return SimpleNamespace(returncode=1)

                with patch("replay.subprocess.run", side_effect=reject):
                    if accepted:
                        check_missing_tls_bindings(
                            command,
                            {},
                            Path(root),
                            protocol=protocol,
                        )
                        self.assertEqual(len(calls), 2)
                        self.assertIn("--cacert", calls[-1])
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "unexpected missing-binding"
                        ):
                            check_missing_tls_bindings(
                                command,
                                {},
                                Path(root),
                                protocol=protocol,
                            )

    def test_hostname_control_keeps_trust_and_requires_a_certificate_failure(self):
        command = [
            "rama",
            "send",
            "--cacert",
            "fixture.pem",
            "https://localhost:24443/report",
        ]
        bad_certificate = (
            "the cryptographic handshake failed: error 42: TLS handshake failed"
        )
        for flag, code, message, accepted in [
            ("--http2", 1, "CERTIFICATE_VERIFY_FAILED", True),
            ("--http3", 1, bad_certificate, True),
            ("--http2", 1, bad_certificate, False),
            ("--http3", 1, bad_certificate.replace("42", "48"), False),
            ("--http2", 0, "certificate", False),
            ("--http2", 1, "connection refused", False),
        ]:
            arguments = [command[0], flag, *command[1:]]
            with (
                self.subTest(code=code, message=message),
                tempfile.TemporaryDirectory() as root,
            ):

                def run(arguments, **kwargs):
                    self.assertEqual(
                        arguments[arguments.index("--cacert") + 1],
                        "fixture.pem",
                    )
                    self.assertEqual(
                        arguments[-3:],
                        [
                            "--resolve",
                            "wronghost:24443:127.0.0.1",
                            "https://wronghost:24443/report",
                        ],
                    )
                    kwargs["stdout"].write(message)
                    return SimpleNamespace(returncode=code)

                with patch("replay.subprocess.run", side_effect=run):
                    if accepted:
                        check_tls_hostname(arguments, {}, Path(root))
                    else:
                        with self.assertRaises(ValueError):
                            check_tls_hostname(arguments, {}, Path(root))

    def test_psk_priming_uses_a_full_recipe_from_the_same_profile(self):
        def variant(identifier, needs_ticket):
            extensions = [{"id": 41}] if needs_ticket else []
            return {
                "id": [identifier] * 32,
                "capture": {
                    "level": "Connection",
                    "slots": [
                        {
                            "kind": "QuicTls",
                            "capture": {"extensions": extensions},
                        }
                    ],
                },
            }

        def profile(*variants):
            return {"scopes": [{"variants": list(variants)}]}

        first = profile(variant(1, True), variant(2, False))
        second = profile(variant(3, True), variant(4, False))
        self.assertEqual(
            connection_warmups({"profiles": [first, second]}, "h3"),
            {
                "01" * 32: ["02" * 32, "01" * 32],
                "02" * 32: ["02" * 32],
                "03" * 32: ["04" * 32, "03" * 32],
                "04" * 32: ["04" * 32],
            },
        )
        with self.assertRaisesRegex(ValueError, "full-handshake recipe"):
            connection_warmups({"profiles": [first, profile(variant(3, True))]}, "h3")
        self.assertEqual(
            connection_warmups({"profiles": [profile(variant(3, True))]}, "h2"), {}
        )
        self.assertEqual(
            connection_warmups({"profiles": [profile(variant(2, False))]}, "h3"),
            {"02" * 32: ["02" * 32]},
        )

    def test_websocket_replay_uses_the_page_observed_probe_exactly(self):
        probe = "rama-fp echo: current page 🐢 #" + "ef" * 16
        peer = "import sys; line=sys.stdin.readline(); print(line, end='', flush=True)"
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "replay.log"
            run_replay(
                [sys.executable, "-c", peer], flow="ws", log=log, websocket_probe=probe
            )
            self.assertEqual(log.read_text(), probe + "\n")
            wrong = "import sys; sys.stdin.readline(); print('another page')"
            with self.assertRaisesRegex(ValueError, "echo"):
                run_replay(
                    [sys.executable, "-c", wrong],
                    flow="ws",
                    log=log,
                    websocket_probe=probe,
                )

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

    def test_replay_inputs_keep_tcp_and_quic_streams_separate(self):
        frames = fixture("h2") + fixture("h3")
        requests = requests_from_wire(frames)
        self.assertEqual(len(requests), 6)
        for flow, observations in requests.items():
            with self.subTest(flow=flow):
                self.assertEqual(len(observations), 2)
                self.assertEqual(observations[0].body, observations[1].body)

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
                    self.assertIn("--header=te: trailers", args)
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
            self.assertIn("--header=origin: https://localhost:4433", args)
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
