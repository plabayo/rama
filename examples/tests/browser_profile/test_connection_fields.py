"""Raw HTTP/2 prefix decoding and joint TLS/HTTP matching regressions."""

from copy import deepcopy
from types import SimpleNamespace
import unittest

from connection_fields import compare_connection_fields, h2_prefixes
from flows import FLOWS


def scalar(name, value, size):
    return f'<field name="{name}" show="{value}" size="{size}" value="{value:0{size * 2}x}"/>'


def document(*, magic=True, setting=4096):
    fields = (
        scalar("tcp.srcport", 12345, 2)
        + scalar("tcp.dstport", 443, 2)
        + scalar("tcp.stream", 7, 4)
    )
    prefix = (
        '<field name="http2.stream"><field name="http2.magic" show="preface"/></field>'
        if magic
        else ""
    )
    settings = (
        '<field name="http2.stream">'
        + scalar("http2.type", 4, 1)
        + scalar("http2.length", 6, 3)
        + scalar("http2.flags", 0, 1)
        + scalar("http2.streamid", 0, 4)
        + '<field name="http2.settings">'
        + scalar("http2.settings.id", 1, 2)
        + scalar("http2.settings.header_table_size", setting, 4)
        + "</field></field>"
    )
    boundary = (
        '<field name="http2.stream">'
        + scalar("http2.type", 1, 1)
        + scalar("http2.streamid", 3, 4)
        + scalar("http2.flags", 4, 1)
        + "</field>"
    )
    return (
        "<pdml><packet>"
        + fields
        + prefix
        + settings
        + boundary
        + settings
        + "</packet></pdml>"
    ).encode()


def fixture():
    prefix = h2_prefixes(document(), 443)[7]
    tls = {"transport": "Tcp", "ciphers": [4865]}
    joint = {
        "level": "Connection",
        "slots": [
            {"kind": "TcpTls", "capture": tls},
            {"kind": "Http2EarlyFrames", "capture": prefix},
        ],
    }
    archive = {
        "format_version": 1,
        "profiles": [
            {
                "key": {"user_agent": "fixture"},
                "scopes": [{"variants": [{"id": [1] * 32, "capture": joint}]}],
            }
        ],
    }
    hello = SimpleNamespace(connection=7, capture=tls)
    request = SimpleNamespace(
        connection=7, from_server=False, headers=(("user-agent", "fixture"),)
    )
    return archive, hello, request, prefix


def post_header_document(
    *, stream=3, increment=100, fragmented=False, ack=False, interposed=None
):
    data = document().decode()
    # Remove the deliberately ignored post-HEADERS SETTINGS in the old fixture.
    last_setting = data.rfind('<field name="http2.stream">')
    data = data[:last_setting] + "</packet></pdml>"
    continuation = ""
    if fragmented:
        data = data.replace(scalar("http2.flags", 4, 1), scalar("http2.flags", 0, 1))
        continuation = (
            '<field name="http2.stream">'
            + scalar("http2.type", 9, 1)
            + scalar("http2.streamid", 3, 4)
            + scalar("http2.flags", 4, 1)
            + "</field>"
        )
    acknowledgement = ""
    if ack:
        acknowledgement = (
            '<field name="http2.stream">'
            + scalar("http2.type", 4, 1)
            + scalar("http2.streamid", 0, 4)
            + scalar("http2.flags", 1, 1)
            + scalar("http2.length", 0, 3)
            + "</field>"
        )
    update = (
        '<field name="http2.stream">'
        + scalar("http2.type", 8, 1)
        + scalar("http2.streamid", stream, 4)
        + scalar("http2.length", 4, 3)
        + scalar("http2.window_update.window_size_increment", increment, 4)
        + "</field>"
    )
    interposed_frame = (
        ""
        if interposed is None
        else (
            '<field name="http2.stream">'
            + scalar("http2.type", interposed, 1)
            + scalar("http2.streamid", 0, 4)
            + "</field>"
        )
    )
    return data.replace(
        "</packet>",
        continuation + acknowledgement + interposed_frame + update + "</packet>",
    ).encode()


class ConnectionFieldTests(unittest.TestCase):
    def test_prefix_stops_at_first_headers_and_checks_raw_integer_coverage(self):
        prefix = h2_prefixes(document(), 443)[7]
        self.assertEqual(len(prefix["frames"]), 1)
        self.assertEqual(
            prefix["frames"][0]["Settings"]["entries"], [{"id": 1, "value": 4096}]
        )
        with self.assertRaisesRegex(ValueError, "incomplete HTTP/2 prefix"):
            h2_prefixes(document(magic=False), 443)
        damaged = document().replace(b'value="00001000"', b'value="1000"')
        with self.assertRaisesRegex(ValueError, "span"):
            h2_prefixes(damaged, 443)
        damaged = document().replace(b'show="4096"', b'show="4097"')
        with self.assertRaisesRegex(ValueError, "mismatch"):
            h2_prefixes(damaged, 443)

    def test_first_request_stream_window_is_a_separate_wire_witness(self):
        observed = h2_prefixes(post_header_document(), 443)[7]
        self.assertEqual(len(observed["frames"]), 1)
        self.assertEqual(
            observed["first_request_window"],
            {"WindowUpdate": {"stream": 3, "increment": 100}},
        )
        # Its presence after HEADERS does not establish the application dispatch
        # cutoff. The recorded policy, when present, must match it exactly.
        archive, hello, request, _ = fixture()
        compare_connection_fields(archive, [hello], {7: observed}, [request])
        slots = archive["profiles"][0]["scopes"][0]["variants"][0]["capture"]["slots"]
        slots[1]["capture"]["frames"].append(observed["first_request_window"])
        compare_connection_fields(archive, [hello], {7: observed}, [request])
        for changed in [
            post_header_document(stream=5),
            post_header_document(increment=101),
            post_header_document(interposed=6),
        ]:
            with self.subTest(changed=changed), self.assertRaisesRegex(
                ValueError, "matching retained joint"
            ):
                compare_connection_fields(
                    archive, [hello], h2_prefixes(changed, 443), [request]
                )

    def test_first_window_cannot_select_another_request_stream_policy(self):
        archive, hello, request, _ = fixture()
        captured = archive["profiles"][0]["scopes"][0]["variants"][0]["capture"][
            "slots"
        ][1]["capture"]
        captured["frames"].append({"WindowUpdate": {"stream": 5, "increment": 100}})
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_connection_fields(
                archive,
                [hello],
                h2_prefixes(post_header_document(stream=5), 443),
                [request],
            )

    def test_first_window_follows_complete_headers_and_may_follow_peer_ack(self):
        observed = h2_prefixes(post_header_document(fragmented=True, ack=True), 443)[7]
        self.assertEqual(
            observed["first_request_window"]["WindowUpdate"],
            {"stream": 3, "increment": 100},
        )
        damaged = post_header_document(fragmented=True).replace(
            (scalar("http2.type", 9, 1) + scalar("http2.streamid", 3, 4)).encode(),
            (scalar("http2.type", 9, 1) + scalar("http2.streamid", 5, 4)).encode(),
        )
        with self.assertRaisesRegex(ValueError, "continuation"):
            h2_prefixes(damaged, 443)
        incomplete = post_header_document(fragmented=True).replace(
            (
                scalar("http2.type", 9, 1)
                + scalar("http2.streamid", 3, 4)
                + scalar("http2.flags", 4, 1)
            ).encode(),
            (
                scalar("http2.type", 9, 1)
                + scalar("http2.streamid", 3, 4)
                + scalar("http2.flags", 0, 1)
            ).encode(),
        )
        with self.assertRaisesRegex(ValueError, "continuation"):
            h2_prefixes(incomplete, 443)

    def test_post_head_window_length_and_increment_are_not_inferred(self):
        for data in [
            post_header_document(increment=0),
            post_header_document().replace(
                (
                    scalar("http2.length", 4, 3)
                    + scalar("http2.window_update.window_size_increment", 100, 4)
                ).encode(),
                (
                    scalar("http2.length", 3, 3)
                    + scalar("http2.window_update.window_size_increment", 100, 4)
                ).encode(),
            ),
        ]:
            with self.subTest(data=data), self.assertRaisesRegex(
                ValueError, "WINDOW_UPDATE"
            ):
                h2_prefixes(data, 443)

    def test_abandoned_preconnections_do_not_override_used_connection_evidence(self):
        abandoned = (
            "<packet>"
            + scalar("tcp.srcport", 12346, 2)
            + scalar("tcp.dstport", 443, 2)
            + scalar("tcp.stream", 8, 4)
            + '<field name="http2.stream">'
            + scalar("http2.type", 7, 1)
            + scalar("http2.streamid", 0, 4)
            + scalar("http2.length", 8, 3)
            + "</field></packet>"
        )
        data = document().replace(b"</pdml>", abandoned.encode() + b"</pdml>")
        self.assertEqual(set(h2_prefixes(data, 443, connections={7})), {7})
        with self.assertRaisesRegex(ValueError, "unmodeled"):
            h2_prefixes(data, 443, connections={8})

    def test_post_head_policy_does_not_allow_ambiguous_joint_credit(self):
        archive, hello, request, _ = fixture()
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        other = deepcopy(variants[0])
        other["id"] = [2] * 32
        other["capture"]["slots"][1]["capture"]["frames"].append(
            {"WindowUpdate": {"stream": 3, "increment": 100}}
        )
        variants.append(other)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            compare_connection_fields(
                archive, [hello], h2_prefixes(post_header_document(), 443), [request]
            )

    def test_tls_and_prefix_must_belong_to_the_same_joint(self):
        archive, hello, request, prefix = fixture()
        self.assertEqual(
            compare_connection_fields(archive, [hello], {7: prefix}, [request])[
                "connections_checked"
            ],
            1,
        )
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        other = deepcopy(variants[0])
        other["id"] = [2] * 32
        other["capture"]["slots"][0]["capture"]["ciphers"] = [4866]
        other["capture"]["slots"][1]["capture"] = h2_prefixes(
            document(setting=8192), 443
        )[7]
        variants.append(other)
        # Both isolated components occur, but never together in a retained tuple.
        with self.assertRaisesRegex(ValueError, "matching retained joint"):
            compare_connection_fields(
                archive,
                [hello],
                {7: other["capture"]["slots"][1]["capture"]},
                [request],
            )
        with self.assertRaisesRegex(ValueError, "no wire observation"):
            compare_connection_fields(archive, [hello], {7: prefix}, [request])

    def test_peer_acks_are_excluded_but_unknown_slots_and_ambiguous_tls_fail(self):
        archive, hello, request, prefix = fixture()
        captured = archive["profiles"][0]["scopes"][0]["variants"][0]["capture"]
        captured["slots"][1]["capture"] = deepcopy(prefix)
        captured["slots"][1]["capture"]["frames"].append(
            {"Settings": {"ack": True, "entries": []}}
        )
        result = compare_connection_fields(archive, [hello], {7: prefix}, [request])
        self.assertIn("acknowledgements", result["excluded"])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            compare_connection_fields(archive, [hello, hello], {7: prefix}, [request])
        captured["slots"].append({"kind": "FutureProtocol", "capture": {}})
        with self.assertRaisesRegex(ValueError, "unverified slots"):
            compare_connection_fields(archive, [hello], {7: prefix}, [request])

    def test_each_variant_must_cover_every_flow_not_only_both_marginals(self):
        archive, hello, request, prefix = fixture()
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        other = deepcopy(variants[0])
        other["id"] = [2] * 32
        other["capture"]["slots"][0]["capture"]["ciphers"] = [4866]
        variants.append(other)
        operations = [
            ((":method", "GET"), (":path", "/report")),
            ((":method", "POST"), (":path", "/api/fetch/number/7")),
            ((":method", "POST"), (":path", "/api/xml/number/7")),
            ((":method", "CONNECT"), (":path", "/api/ws"), (":protocol", "websocket")),
            ((":method", "POST"), (":path", "/form")),
            ((":method", "GET"), (":path", "/form?source=web&turtles=yes")),
        ]

        def observations(crossed):
            hellos, prefixes, requests = [], {}, []
            for variant in range(2):
                for flow, operation in enumerate(operations):
                    connection = variant * len(FLOWS) + flow
                    selected = variant if crossed else int(flow >= 3)
                    captured = variants[selected]["capture"]["slots"][0]["capture"]
                    hellos.append(
                        SimpleNamespace(connection=connection, capture=captured)
                    )
                    prefixes[connection] = prefix
                    requests.append(
                        SimpleNamespace(
                            connection=connection,
                            from_server=False,
                            headers=operation + request.headers,
                        )
                    )
            return hellos, prefixes, requests

        complete = compare_connection_fields(
            archive, *observations(True), expected_per_variant_flow=1
        )
        self.assertTrue(
            all(
                count == 1
                for row in complete["variant_flow_counts"].values()
                for count in row.values()
            )
        )
        # Both variants and every flow still occur globally, but half the cells
        # are absent and the other half repeat. Each TLS/prefix pair remains valid.
        incomplete = observations(False)
        compare_connection_fields(archive, *incomplete)
        with self.assertRaisesRegex(ValueError, "variant/flow matrix"):
            compare_connection_fields(archive, *incomplete, expected_per_variant_flow=1)
        hellos, prefixes, requests = observations(True)
        with self.assertRaisesRegex(ValueError, "variant/flow matrix"):
            compare_connection_fields(
                archive,
                hellos,
                prefixes,
                requests + requests[:1],
                expected_per_variant_flow=1,
            )

    def test_indistinguishable_joint_ids_cannot_both_get_credit(self):
        archive, hello, request, prefix = fixture()
        variants = archive["profiles"][0]["scopes"][0]["variants"]
        other = deepcopy(variants[0])
        other["id"] = [2] * 32
        variants.append(other)
        with self.assertRaisesRegex(ValueError, "ambiguous retained connection"):
            compare_connection_fields(archive, [hello], {7: prefix}, [request])


if __name__ == "__main__":
    unittest.main()
