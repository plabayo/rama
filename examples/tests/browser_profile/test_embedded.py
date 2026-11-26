from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import embedded

PLANNED = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0"
HEADERS = ["user-agent", "accept", "te"]


def echoed(*, user_agent=PLANNED, ja4=True, ja4h=True, version="HTTP/2.0", method="GET",
           headers=HEADERS, extensions=()):
    return json.dumps({
        "ua": {"user_agent": user_agent},
        "http": {"version": version, "method": method,
                 "ja4h": {"hash": "h", "verbose": "ge20cn03enus_" + ",".join(headers) + "__",
                          "profile": {"hash": "h", "matched": ja4h}}},
        "tls": {"ja4": {"hash": "t", "profile": {"hash": "t", "matched": ja4}},
                "extensions": [{"id": f"X (0x{identifier:04x})"} for identifier in extensions]},
    }).encode()


def planned_flow(*, version="HTTP/2.0", method="GET", initiator="navigate", fetch=None,
                 request_fields=("cookie", "te"), resumed_only=False, http1_reference=False,
                 plaintext=False, ja4h_headers=HEADERS, modes=("forced",),
                 variant_headers=None, auto_narrowed=False):
    label = embedded.flow_label({"version": version, "method": method,
                                 "initiator": initiator, "fetch": fetch}, plaintext)
    kind = "websocket" if initiator == "ws" else "ordinary"
    return {"label": label, "kind": kind, "version": version, "method": method,
            "initiator": initiator,
            "fetch": fetch, "variant": "ab" * 32, "plaintext": plaintext,
            "request_fields": list(request_fields),
            "ja4h_headers": ja4h_headers, "trust_anchors": False,
            "variant_headers": variant_headers or [ja4h_headers],
            "auto_narrowed": auto_narrowed, "flow_narrowed": False,
            "resumed_only": resumed_only, "http1_reference": http1_reference,
            "modes": list(modes)}


def handshake_headers(*, version="HTTP/2.0", method="CONNECT", ja4=True, headers=HEADERS):
    """`rama send -v` output of a handshake response carrying echo's report."""
    facts = {"ua": PLANNED, "http-version": version, "http-method": method, "ja4h": "h",
             "ja4h-verbose": "co20nn03enus_" + ",".join(headers) + "__",
             "ja4h-profile": "h", "ja4h-matched": "true", "ja4": "t", "ja4-profile": "t",
             "ja4-matched": "true" if ja4 else "false"}
    return "".join(f"< x-rama-fingerprint-{name}: {value}\n"
                   for name, value in facts.items()).encode()


class VerdictTests(unittest.TestCase):
    def verdict(self, stdout, *, returncode=0, mode="forced", stderr=b"", **flow):
        flow = planned_flow(**flow)
        result = SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)
        with tempfile.TemporaryDirectory() as root, patch.object(
            embedded.subprocess, "run", return_value=result
        ) as run:
            verdict = embedded.emulate(
                SimpleNamespace(rama=Path("rama")), {"user_agent": PLANNED},
                flow, 443, Path(root), mode,
            )
        command = run.call_args.args[0]
        self.command = command
        self.assertIn("user-agent: " + PLANNED, command)
        self.assertIn("cookie: c0=1", command)
        self.assertIn("te: trailers", command)
        if mode == "forced":
            self.assertEqual(command[command.index("--emulate-request-variant") + 1],
                             "ab" * 32)
        else:
            self.assertNotIn("--emulate-request-variant", command)
            self.assertIn("--emulate-seed", command)
        return verdict

    def test_matching_fingerprints_of_the_planned_profile_pass(self):
        self.assertTrue(self.verdict(echoed())["passed"])

    def test_another_profile_judged_by_echo_never_passes(self):
        other = PLANNED.replace("157.0", "156.0")
        self.assertFalse(self.verdict(echoed(user_agent=other))["passed"])

    def test_each_fingerprint_and_the_exit_status_must_hold(self):
        self.assertFalse(self.verdict(echoed(ja4=False))["passed"])
        self.assertFalse(self.verdict(echoed(ja4h=False))["passed"])
        self.assertFalse(self.verdict(echoed(), returncode=1)["passed"])
        self.assertFalse(self.verdict(b"not json")["passed"])

    def test_another_recorded_shape_than_the_pinned_variant_fails(self):
        verdict = self.verdict(echoed(headers=["user-agent", "te", "accept"]))
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["ja4h_headers"]["expected"], [HEADERS])

    def test_the_echoed_http_version_must_be_the_planned_one(self):
        self.assertFalse(self.verdict(echoed(version="HTTP/1.1"))["passed"])

    def test_the_auto_form_sends_no_version_flag_and_requires_ja4(self):
        for version in ("HTTP/1.1", "HTTP/2.0"):
            verdict = self.verdict(echoed(version=version), version=version, mode="auto")
            self.assertTrue(verdict["passed"])
            self.assertEqual(verdict["mode"], "auto")
            self.assertFalse(set(embedded.FORCED.values()) & set(self.command))
            stdout = echoed(ja4=False, version=version)
            self.assertFalse(self.verdict(stdout, version=version, mode="auto")["passed"])
        # HTTP/2 must be negotiated in the auto form of an HTTP/2 flow.
        stdout = echoed(version="HTTP/1.1")
        self.assertFalse(self.verdict(stdout, version="HTTP/2.0", mode="auto")["passed"])

    def test_an_auto_run_may_send_any_stored_variant_of_the_flow(self):
        other = ["accept", "user-agent"]
        stdout = echoed(headers=other)
        verdict = self.verdict(stdout, mode="auto", variant_headers=[HEADERS, other])
        self.assertTrue(verdict["passed"])
        self.assertFalse(self.verdict(stdout, mode="auto")["passed"])
        # A forced run must send the pinned variant itself.
        self.assertFalse(self.verdict(stdout, variant_headers=[HEADERS, other])["passed"])

    def test_a_narrowed_auto_run_is_judged_like_the_forced_form(self):
        stdout = echoed(ja4=False, version="HTTP/1.1")
        verdict = self.verdict(stdout, version="HTTP/1.1", mode="auto", auto_narrowed=True)
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["tls"], "http/1.1-only offer")
        self.assertFalse(self.verdict(stdout, version="HTTP/1.1", mode="auto",
                                      auto_narrowed=True, http1_reference=True)["passed"])
        self.assertFalse(self.verdict(stdout, version="HTTP/1.1", mode="auto")["passed"])

    def test_the_forced_form_sends_the_version_flag(self):
        for version, flag in embedded.FORCED.items():
            self.verdict(echoed(version=version), version=version)
            self.assertIn(flag, self.command)

    def test_a_forced_http1_offer_without_a_reference_reports_tls(self):
        stdout = echoed(ja4=False, version="HTTP/1.1")
        verdict = self.verdict(stdout, version="HTTP/1.1")
        self.assertIn("--http1.1", self.command)
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["tls"], "http/1.1-only offer")
        stdout = echoed(ja4h=False, version="HTTP/1.1")
        self.assertFalse(self.verdict(stdout, version="HTTP/1.1")["passed"])

    def test_resumption_only_references_are_judged_by_ja4h(self):
        verdict = self.verdict(echoed(ja4=False), resumed_only=True)
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["tls"], "resumption-only reference")
        self.assertFalse(self.verdict(echoed(ja4h=False), resumed_only=True)["passed"])

    def test_a_post_flow_carries_its_method_body_and_fetch_metadata(self):
        fetch = {"site": "same-origin", "mode": "cors", "destination": "empty",
                 "user_activation": None}
        verdict = self.verdict(
            echoed(method="POST"), method="POST", initiator="fetch", fetch=fetch,
            request_fields=("cookie", "te", "origin", "content-type", "content-length"))
        self.assertTrue(verdict["passed"])
        command = self.command
        self.assertEqual(command[command.index("-X") + 1], "POST")
        self.assertEqual(command[command.index("-d") + 1], embedded.FORM_BODY)
        self.assertEqual(command[command.index("--emulate-initiator") + 1], "fetch")
        for header in ("sec-fetch-site: same-origin", "sec-fetch-mode: cors",
                       "sec-fetch-dest: empty", "content-type: application/x-www-form-urlencoded"):
            self.assertIn(header, command)
        self.assertTrue(any(part.startswith("origin: https://") for part in command))
        self.assertFalse(any(part.startswith("content-length") for part in command))
        self.assertFalse(any(part.startswith("sec-fetch-user") for part in command))
        self.assertFalse(self.verdict(echoed(), method="POST")["passed"])

    def test_a_post_variant_without_framing_is_sent_without_a_body(self):
        verdict = self.verdict(echoed(method="POST"), method="POST", initiator="fetch",
                               request_fields=("cookie", "te", "origin"))
        self.assertTrue(verdict["passed"])
        self.assertEqual(self.command[self.command.index("-X") + 1], "POST")
        self.assertNotIn("-d", self.command)

    def test_http1_header_casing_must_match_the_pinned_variant(self):
        captured = ["Host", "User-Agent", "Accept"]
        verdict = self.verdict(echoed(version="HTTP/1.1", headers=captured),
                               version="HTTP/1.1", ja4h_headers=captured)
        self.assertTrue(verdict["passed"])
        lowered = [name.lower() for name in captured]
        verdict = self.verdict(echoed(version="HTTP/1.1", headers=lowered),
                               version="HTTP/1.1", ja4h_headers=captured)
        self.assertFalse(verdict["passed"])
        self.assertFalse(verdict["ja4h_flow"])

    def test_an_http1_only_reference_hello_requires_ja4(self):
        stdout = echoed(ja4=False, version="HTTP/1.1")
        verdict = self.verdict(stdout, http1_reference=True, version="HTTP/1.1")
        self.assertFalse(verdict["passed"])
        self.assertIs(verdict["tls"], False)
        stdout = echoed(version="HTTP/1.1")
        self.assertTrue(self.verdict(stdout, http1_reference=True,
                                     version="HTTP/1.1")["passed"])

    def test_an_alt_svc_run_sends_the_pinned_variant_twice_through_the_alternative(self):
        flow = planned_flow(version="HTTP/3.0", request_fields=("cookie", "te"))
        flow.update(alt_used=True, alt_variant="cd" * 32, alt_request_fields=["cookie"],
                    alt_headers=["user-agent", "alt-used", "accept"])
        args = SimpleNamespace(rama=Path("rama"), ca=Path("ca.pem"))
        command = embedded.send_command(args, {"user_agent": PLANNED}, flow, 4433,
                                        embedded.ALT_SVC)
        for flag in ("--http3", "--cacert", "--last-response-only", "--next"):
            self.assertIn(flag, command)
        for absent in ("-k", "--resolve"):
            self.assertNotIn(absent, command)
        first, second = " ".join(command).split(" --next ")
        self.assertEqual(first.count("--emulate-request-variant " + "cd" * 32), 1)
        self.assertEqual(second.count("--emulate-request-variant " + "cd" * 32), 1)
        self.assertIn("user-agent: " + PLANNED, second)
        self.assertTrue(command[-1].startswith("https://localhost:4433/"))
        result = SimpleNamespace(stderr=b"", returncode=0, stdout=echoed(
            version="HTTP/3.0", headers=["user-agent", "alt-used", "accept"]))
        with tempfile.TemporaryDirectory() as root, patch.object(
                embedded.subprocess, "run", return_value=result):
            verdict = embedded.emulate(args, {"user_agent": PLANNED}, flow, 4433, Path(root),
                                       embedded.ALT_SVC)
        self.assertTrue(verdict["passed"])
        result.stdout = echoed(version="HTTP/3.0", headers=["user-agent", "accept"])
        with tempfile.TemporaryDirectory() as root, patch.object(
                embedded.subprocess, "run", return_value=result):
            verdict = embedded.emulate(args, {"user_agent": PLANNED}, flow, 4433, Path(root),
                                       embedded.ALT_SVC)
        self.assertFalse(verdict["passed"])
        # The auto form sends no version flag and pins nothing.
        command = embedded.send_command(args, {"user_agent": PLANNED}, flow, 4433,
                                        embedded.ALT_SVC_AUTO)
        self.assertNotIn("--http3", command)
        self.assertNotIn("--emulate-request-variant", command)
        self.assertIn("--next", command)
        self.assertEqual(embedded.run_label(flow, embedded.ALT_SVC_AUTO),
                         flow["label"] + " auto alt-svc")

    def test_a_direct_run_never_supplies_alt_used(self):
        flow = planned_flow(version="HTTP/3.0", request_fields=("cookie", "te", "alt-used"))
        flow["alt_used"] = True
        self.assertEqual(embedded.run_label(flow, "forced"), flow["label"] + " forced direct")
        self.verdict(echoed(version="HTTP/3.0"), version="HTTP/3.0",
                     request_fields=("cookie", "te", "alt-used"))
        self.assertFalse(any(part.lower().startswith("alt-used") for part in self.command))
        self.assertNotIn("--no-alt-svc", self.command)

    def test_an_alt_used_only_flow_is_judged_by_its_exact_header_list(self):
        flow = planned_flow(version="HTTP/3.0")
        flow.update(alt_used=True, alt_used_only=True)
        result = SimpleNamespace(stdout=echoed(ja4h=False, version="HTTP/3.0"), stderr=b"",
                                 returncode=0)
        with tempfile.TemporaryDirectory() as root, patch.object(
                embedded.subprocess, "run", return_value=result):
            verdict = embedded.emulate(SimpleNamespace(rama=Path("rama")),
                                       {"user_agent": PLANNED}, flow, 443, Path(root))
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["ja4h_status"], "recorded only with Alt-Used")
        stdout = echoed(ja4h=False, version="HTTP/3.0", headers=["accept"])
        result.stdout = stdout
        with tempfile.TemporaryDirectory() as root, patch.object(
                embedded.subprocess, "run", return_value=result):
            verdict = embedded.emulate(SimpleNamespace(rama=Path("rama")),
                                       {"user_agent": PLANNED}, flow, 443, Path(root))
        self.assertFalse(verdict["passed"])

    def test_a_subresource_flow_has_no_initiator(self):
        fetch = {"site": "cross-site", "mode": "no-cors", "destination": "image",
                 "user_activation": None}
        self.assertTrue(self.verdict(echoed(), initiator=None, fetch=fetch)["passed"])
        self.assertNotIn("--emulate-initiator", self.command)
        self.assertNotIn("-X", self.command)

    def test_a_websocket_is_judged_by_its_handshake_response_headers(self):
        fields = ("cookie", "te", "upgrade", "sec-websocket-key", "connection",
                  "sec-websocket-protocol")
        for version, method in (("HTTP/1.1", "GET"), ("HTTP/2.0", "CONNECT"),
                                ("HTTP/3.0", "CONNECT")):
            stderr = handshake_headers(version=version, method=method)
            verdict = self.verdict(b"", stderr=stderr, version=version, method=method,
                                   initiator="ws", request_fields=fields)
            self.assertTrue(verdict["passed"], version)
            self.assertTrue(self.command[-1].startswith("wss://"))
            self.assertIn(embedded.FORCED[version], self.command)
            self.assertIn("-v", self.command)
            self.assertFalse(any(part.startswith(("upgrade", "sec-websocket-key"))
                                 for part in self.command))
            # The upgrade keeps its Connection value; echo accepts only its own subprotocol.
            self.assertIn("connection: Upgrade", self.command)
            self.assertEqual(self.command[self.command.index("--subprotocol") + 1], "echo")
        # The auto form leaves the version to ALPN.
        self.assertTrue(self.verdict(b"", stderr=handshake_headers(), mode="auto",
                                     method="CONNECT", initiator="ws",
                                     request_fields=fields)["passed"])
        self.assertIn("--ws-alpn", self.command)
        self.assertFalse(any(flag in self.command for flag in embedded.FORCED.values()))
        # A client that rejects the handshake response afterwards is reported apart.
        stderr = handshake_headers() + b"exit with error: response validation failed\n"
        verdict = self.verdict(b"", stderr=stderr, returncode=1, method="CONNECT",
                               initiator="ws", request_fields=fields)
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["client_error"], "response validation failed")
        # Without the report headers nothing can be judged.
        self.assertFalse(self.verdict(b"", returncode=1, initiator="ws")["passed"])
        self.assertFalse(self.verdict(b"", stderr=handshake_headers(ja4=False),
                                      method="CONNECT", initiator="ws")["passed"])

    def test_a_plaintext_flow_is_judged_without_tls(self):
        verdict = self.verdict(echoed(ja4=None, version="HTTP/1.1"), version="HTTP/1.1",
                               plaintext=True, request_fields=("cookie", "te", "origin"))
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["tls"], "plaintext")
        self.assertTrue(self.command[-1].startswith("http://"))
        self.assertIn("origin: http://h1.fp.ramaproxy.org:443", self.command)


def scope(version="HTTP/1.1", method="GET", initiator="navigate", fetch=None, variant=1,
          connection=None, names=("user-agent",)):
    flow = {"method": method, "version": version, "initiator": initiator, "fetch": fetch,
            "connection": connection or {"token_present": None}}
    fields = [{"name": name, "value": {"Profile": [1]}} for name in names]
    fields.append({"name": "cookie", "value": {"Request": "Cookie"}})
    capture = {"level": "Request", "slots": [{"kind": "Headers",
                                              "capture": {"fields": fields}}]}
    return {"flow": {"Http": flow}, "domain": 6,
            "variants": [{"id": [variant] * 32, "capture": capture}]}


def viewed(components, scopes=None):
    """`rama ua view --embedded --json` with one profile; by default an HTTP/1.1 navigation."""
    profile = {
        "key": {"user_agent": PLANNED},
        "components": dict.fromkeys(components, True),
        "scopes": scopes if scopes is not None else [scope()],
    }
    return json.dumps({"profiles": [profile]}).encode()


class PlanTests(unittest.TestCase):
    def plan(self, *components, scopes=None):
        def view(_command, *, stdout, **_kwargs):
            stdout.write(viewed(components, scopes))
            return SimpleNamespace(returncode=0)

        with patch.object(embedded.subprocess, "run", side_effect=view):
            (plan,) = embedded.profile_plans(Path("rama"))
        return plan

    def test_profiles_are_decoded_one_at_a_time_from_the_view(self):
        view = {"format_version": 1, "profiles": [{"n": 1}, {"n": [2, "]"]}]}

        def run(_command, *, stdout, **_kwargs):
            stdout.write(json.dumps(view, indent=1).encode())
            return SimpleNamespace(returncode=0)

        with patch.object(embedded.subprocess, "run", side_effect=run):
            self.assertEqual(list(embedded.embedded_profiles(Path("rama"))), view["profiles"])

    def test_an_auto_run_narrows_to_the_one_version_holding_its_kind_of_flow(self):
        websocket = scope(initiator="ws", fetch={"mode": "websocket"})
        page = scope("HTTP/2.0", variant=2)
        (flow,) = [flow for flow in self.plan("h1", "h2", "tls_tcp",
                                              scopes=[websocket, page])["flows"]
                   if flow["initiator"] == "navigate"]
        self.assertEqual(flow["modes"], ["forced", "auto"])
        self.assertTrue(flow["auto_narrowed"])
        self.assertTrue(flow["flow_narrowed"])
        # With an HTTP/1.1 page flow beside it, the browser's own offer is sent; the
        # WebSocket, captured only over HTTP/1.1, is narrowed to it.
        plan = self.plan("h1", "h2", "tls_tcp", scopes=[websocket, page, scope(variant=3)])
        for flow in plan["flows"]:
            websocket_flow = flow["kind"] == "websocket"
            self.assertEqual(flow["auto_narrowed"], websocket_flow, flow["label"])
            self.assertEqual(flow["flow_narrowed"], websocket_flow, flow["label"])

    def test_a_profile_lacking_http2_plans_a_narrowed_auto_form(self):
        plan = self.plan("h1", "tls_tcp")
        (flow,) = plan["flows"]
        self.assertEqual(flow["modes"], ["forced", "auto"])
        self.assertTrue(flow["auto_narrowed"])
        self.assertEqual(plan["unselectable"], [])

    def test_a_websocket_runs_forced_and_with_alpn(self):
        ws = {"site": "same-origin", "mode": "websocket", "destination": "websocket",
              "user_activation": None}
        (flow,) = self.plan("h1", "h2", "tls_tcp",
                            scopes=[scope("HTTP/1.1", "GET", "ws", ws)])["flows"]
        self.assertEqual(flow["modes"], ["forced", "auto"])
        self.assertEqual(flow["kind"], "websocket")

    def test_a_profile_lacking_http2_and_tls_is_unselectable(self):
        plan = self.plan("h1")
        self.assertEqual(plan["flows"], [])
        self.assertEqual(plan["unselectable"], ["HTTP/1.1"])
        (unsupported,) = plan["unsupported"]
        self.assertIn("tls_tcp", unsupported["reason"])

    def test_a_profile_with_http1_and_http2_plans_both_forms(self):
        scopes = [scope(), scope("HTTP/2.0", variant=2), scope("HTTP/3.0", variant=3)]
        plan = self.plan("h1", "h2", "h3", "tls_tcp", "tls_quic", "quic", scopes=scopes)
        modes = {flow["version"]: flow["modes"] for flow in plan["flows"]}
        self.assertEqual(modes, {"HTTP/1.1": ["forced", "auto"],
                                 "HTTP/2.0": ["forced", "auto"], "HTTP/3.0": ["forced"]})
        self.assertFalse(any(flow["auto_narrowed"] for flow in plan["flows"]))
        # Without HTTP/1.1 data emulation targets HTTP/2 itself in the auto form.
        (flow,) = self.plan("h2", "tls_tcp", scopes=[scope("HTTP/2.0")])["flows"]
        self.assertEqual(flow["modes"], ["forced", "auto"])
        self.assertTrue(flow["auto_narrowed"])
        self.assertFalse(flow["flow_narrowed"])

    def test_every_distinct_flow_is_planned_once_with_its_pinned_variant(self):
        cors = {"site": "same-site", "mode": "cors", "destination": "empty",
                "user_activation": None}
        image = {"site": "cross-site", "mode": "no-cors", "destination": "image",
                 "user_activation": None}
        scopes = [scope(), scope(variant=2), scope("HTTP/2.0", "POST", "xhr", cors, 3),
                  scope("HTTP/2.0", "OPTIONS", None, cors, 4),
                  scope("HTTP/3.0", "GET", None, image, 5)]
        plan = self.plan("h1", "h2", "h3", "tls_tcp", "tls_quic", "quic", scopes=scopes)
        flows = {flow["label"]: flow for flow in plan["flows"]}
        self.assertEqual(sorted(flows), ["h1 GET navigate no-fetch-metadata",
                                         "h2 OPTIONS - same-site/cors/empty",
                                         "h2 POST xhr same-site/cors/empty",
                                         "h3 GET - cross-site/no-cors/image"])
        self.assertEqual(flows["h1 GET navigate no-fetch-metadata"]["variant"], "01" * 32)
        self.assertEqual(flows["h2 POST xhr same-site/cors/empty"]["request_fields"],
                         ["cookie"])
        self.assertEqual(flows["h2 POST xhr same-site/cors/empty"]["ja4h_headers"],
                         ["user-agent"])
        self.assertEqual(flows["h1 GET navigate no-fetch-metadata"]["variant_headers"],
                         [["user-agent"]])
        self.assertEqual(plan["unsupported"], [])

    def test_a_capture_without_fetch_metadata_beside_ones_with_it_is_plaintext(self):
        image = {"site": "same-origin", "mode": "no-cors", "destination": "image",
                 "user_activation": None}
        scopes = [scope(), scope("HTTP/1.1", "GET", None, image, 2),
                  scope("HTTP/1.1", "GET", "ws", None, 5),
                  scope("HTTP/2.0", "GET", "navigate", None, 3),
                  scope("HTTP/2.0", "GET", None, image, 4)]
        plan = self.plan("h1", "h2", "tls_tcp", scopes=scopes)
        flows = {flow["label"]: flow["plaintext"] for flow in plan["flows"]}
        self.assertEqual(flows, {"h1-plain GET navigate no-fetch-metadata": True,
                                 "h1 GET - same-origin/no-cors/image": False,
                                 "h1 GET ws no-fetch-metadata": False,
                                 "h2 GET - same-origin/no-cors/image": False})
        (unsupported,) = plan["unsupported"]
        self.assertEqual(unsupported["flow"], "h2-plain GET navigate no-fetch-metadata")

    def test_a_fresh_connection_scope_is_preferred(self):
        stale = scope(variant=1, connection={"token_present": True})
        fresh = scope(variant=2, connection={"token_present": False})
        (flow,) = self.plan("h1", "h2", "tls_tcp", scopes=[stale, fresh])["flows"]
        self.assertEqual(flow["variant"], "02" * 32)
        # A token-only flow still replays: selection ignores the token of a new connection.
        (flow,) = self.plan("h1", "h2", "tls_tcp", scopes=[stale])["flows"]
        self.assertEqual(flow["variant"], "01" * 32)

    def test_a_flow_captured_only_on_resumed_connections_is_unsupported(self):
        resumed = scope(connection={"resumption": "Resumed"})
        plan = self.plan("h1", "h2", "tls_tcp", scopes=[resumed])
        self.assertEqual(plan["flows"], [])
        (unsupported,) = plan["unsupported"]
        self.assertIn("resumed", unsupported["reason"])

    def test_http1_names_keep_their_captured_casing(self):
        h1 = scope(names=("Host", "User-Agent"))
        h2 = scope("HTTP/2.0", names=("User-Agent",), variant=2)
        plan = self.plan("h1", "h2", "tls_tcp", scopes=[h1, h2])
        names = {flow["version"]: flow["ja4h_headers"] for flow in plan["flows"]}
        self.assertEqual(names, {"HTTP/1.1": ["Host", "User-Agent"], "HTTP/2.0": ["user-agent"]})

    def test_an_http1_only_reference_hello_is_detected(self):
        def hello(*protocols):
            alpn = {"id": embedded.ALPN_EXTENSION,
                    "value": {"Protocols": [list(name.encode()) for name in protocols]}}
            return {"flow": None, "domain": 6, "variants": [{"id": [9] * 32, "capture": {
                "level": "Connection",
                "slots": [{"kind": "TcpTls", "capture": {"extensions": [alpn]}}]}}]}

        (flow,) = self.plan("h1", "tls_tcp", scopes=[scope(), hello("h2", "http/1.1")])["flows"]
        self.assertFalse(flow["http1_reference"])
        (flow,) = self.plan("h1", "tls_tcp", scopes=[scope(), hello("http/1.1")])["flows"]
        self.assertTrue(flow["http1_reference"])

    def test_an_alt_used_flow_runs_direct_and_reports_its_alt_svc_run(self):
        image = {"site": "same-origin", "mode": "no-cors", "destination": "image",
                 "user_activation": None}
        with_alt = scope("HTTP/3.0", "GET", None, image, 1,
                         names=("user-agent", "alt-used", "accept"))
        plain = scope("HTTP/3.0", "GET", None, image, 2, names=("accept", "user-agent"))
        components = ("h1", "h2", "h3", "tls_tcp", "tls_quic", "quic")
        plan = self.plan(*components, scopes=[with_alt, plain])
        (flow,) = plan["flows"]
        self.assertTrue(flow["alt_used"])
        self.assertEqual(flow["variant"], "02" * 32)
        self.assertEqual(flow["variant_headers"], [["accept", "user-agent"]])
        self.assertEqual(flow["modes"], ["forced", embedded.ALT_SVC, embedded.ALT_SVC_AUTO])
        self.assertEqual(flow["alt_variant"], "01" * 32)
        self.assertEqual(flow["alt_headers"], ["user-agent", "alt-used", "accept"])
        self.assertEqual(flow["alt_auto_headers"],
                         [["user-agent", "alt-used", "accept"], ["accept", "user-agent"]])
        self.assertEqual(plan["unsupported"], [])
        # With only Alt-Used variants the slot stays empty in the expected list.
        (flow,) = self.plan(*components, scopes=[with_alt])["flows"]
        self.assertEqual(flow["ja4h_headers"], ["user-agent", "accept"])
        self.assertEqual(flow["variant_headers"], [["user-agent", "accept"]])
        # An HTTP/2 flow goes through echo's HTTP/2 alternative.
        h2 = scope("HTTP/2.0", "GET", None, image, 3, names=("user-agent", "alt-used"))
        plan = self.plan(*components, scopes=[h2])
        (flow,) = plan["flows"]
        self.assertEqual(flow["modes"], ["forced", "auto", embedded.ALT_SVC,
                                         embedded.ALT_SVC_AUTO])
        self.assertEqual(embedded.server_name(flow, embedded.ALT_SVC), embedded.ALT_SVC_H2)
        self.assertEqual(plan["unsupported"], [])

    def test_a_websocket_runs_in_each_version_it_was_captured(self):
        ws = {"site": "same-origin", "mode": "websocket", "destination": "websocket",
              "user_activation": None}
        scopes = [scope("HTTP/1.1", "GET", "ws", ws),
                  scope("HTTP/2.0", "CONNECT", "ws", ws, 2),
                  scope("HTTP/3.0", "CONNECT", "ws", ws, 3)]
        plan = self.plan("h1", "h2", "h3", "tls_tcp", "tls_quic", "quic", scopes=scopes)
        modes = {flow["label"]: flow["modes"] for flow in plan["flows"]}
        self.assertEqual(modes, {"h1 GET ws same-origin/websocket/websocket": ["forced", "auto"],
                                 "h2 CONNECT ws same-origin/websocket/websocket":
                                     ["forced", "auto"],
                                 "h3 CONNECT ws same-origin/websocket/websocket": ["forced"]})
        self.assertEqual(plan["unsupported"], [])
        # Handshakes under both TCP versions leave the auto offer to ALPN.
        self.assertFalse(any(flow["auto_narrowed"] for flow in plan["flows"]))


@contextmanager
def fixture(*_args, **_kwargs):
    yield None


def identity():
    """Stand-in fixture identity files; their bytes only travel in the echo environment."""
    root = Path(tempfile.mkdtemp())
    for name in ("key.pem", "cert.pem", "ca.pem"):
        (root / name).write_bytes(b"pem")
    return root / "key.pem", root / "cert.pem", root / "ca.pem", "spki"


class RunTests(unittest.TestCase):
    def run_profile(self, results, modes=("forced",)):
        """Run `main` on one profile whose flows echo the given (method, passing) pairs."""
        cors = {"site": "same-origin", "mode": "cors", "destination": "empty",
                "user_activation": None}
        flows = [planned_flow(method=method, initiator="xhr", fetch=cors, modes=modes)
                 for method, _ in results]
        plan = {"user_agent": PLANNED, "key": {}, "flows": flows, "legacy_only": False,
                "unselectable": ["HTTP/3.0"],
                "unsupported": [{"flow": "h3 GET navigate x", "reason": "lacks quic"}]}
        outputs = {method: echoed(method=method, ja4h=ok) for method, ok in results}

        def send(command, **_kwargs):
            method = command[command.index("-X") + 1] if "-X" in command else "GET"
            return SimpleNamespace(stdout=outputs[method], stderr=b"", returncode=0)

        with tempfile.TemporaryDirectory() as root, \
                patch.object(embedded, "profile_plans", return_value=[plan]), \
                patch.object(embedded, "running", fixture), \
                patch.object(embedded, "fixture_certificate", return_value=identity()), \
                patch.object(embedded, "wait_ready"), \
                patch.object(embedded.subprocess, "run", side_effect=send), \
                patch("builtins.print"):
            output = Path(root) / "out"
            code = embedded.main(["--rama", __file__, "--output", str(output), "--jobs", "2"])
            (report,) = json.loads((output / "summary.json").read_text())
        return code, report

    def test_any_failing_flow_fails_the_profile(self):
        code, report = self.run_profile([("GET", True), ("POST", False)])
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["results"]), 2)

    def test_each_mode_is_its_own_result(self):
        code, report = self.run_profile([("GET", True)], modes=("forced", "auto"))
        self.assertEqual(code, 0)
        modes = {label.rsplit(" ", 1)[1]: result["mode"]
                 for label, result in report["results"].items()}
        self.assertEqual(modes, {"forced": "forced", "auto": "auto"})

    def test_unsupported_flows_are_reported_not_dropped(self):
        code, report = self.run_profile([("GET", True), ("POST", True)])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["unsupported"],
                         [{"flow": "h3 GET navigate x", "reason": "lacks quic"}])


if __name__ == "__main__":
    unittest.main()
