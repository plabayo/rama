"""Raw HTTP/2 prefix decoding and joint TLS/HTTP matching regressions."""

from copy import deepcopy
from types import SimpleNamespace
import unittest

from connection_fields import compare_connection_fields, h2_prefixes


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
    boundary = '<field name="http2.stream">' + scalar("http2.type", 1, 1) + "</field>"
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
                "scopes": [{"variants": [{"capture": joint}]}],
            }
        ],
    }
    hello = SimpleNamespace(connection=7, capture=tls)
    request = SimpleNamespace(
        connection=7, from_server=False, headers=(("user-agent", "fixture"),)
    )
    return archive, hello, request, prefix


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


if __name__ == "__main__":
    unittest.main()
