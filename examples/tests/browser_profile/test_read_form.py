import unittest
from types import SimpleNamespace

from capture_fields import matching_fields
from flows import drawn_wire_tuple
from read_form import tls_read_form
from tls_wire import TlsHello, compare_tls_captures
from wire import Request


def hello(grease, order):
    """A ClientHello with GREASE at both extension ends and `order` between them."""
    cipher, first, group, last = grease
    return dict(
        completeness="Complete",
        transport="Tcp",
        protocol_version=771,
        ciphers=[cipher, 4865],
        compression=[0],
        extensions=[
            {"id": first, "value": {"Literal": []}},
            *[
                {"id": identifier, "value": {"Literal": []}}
                if identifier != 51
                else {
                    "id": 51,
                    "value": {
                        "KeyShares": [
                            {"group": group, "length": 1},
                            {"group": 29, "length": 32},
                        ]
                    },
                }
                for identifier in order
            ],
            {"id": 10, "value": {"U16List": [group, 29]}},
            {"id": last, "value": {"Literal": [0]}},
        ],
    )


ORDER = [0, 23, 51, 65281]
SHUFFLED = {"shuffled_tls_extensions": True}
FIXED = {"shuffled_tls_extensions": False}


def archive(retained, scope):
    variant = {"capture": {"slots": [{"kind": "TcpTls", "capture": retained}]}}
    return {
        "format_version": 1,
        "profiles": [
            {
                "key": {"user_agent": "fixture"},
                "scopes": [{**scope, "variants": [variant]}],
            }
        ],
    }


REQUEST = SimpleNamespace(
    protocol="h2", connection=7, from_server=False, headers=(("user-agent", "fixture"),)
)


class TlsReadFormTests(unittest.TestCase):
    def test_grease_values_read_as_numbered_slots_per_list(self):
        a = tls_read_form(hello([0x3A3A, 0x5A5A, 0x7A7A, 0xCACA], ORDER), FIXED)
        b = tls_read_form(hello([0xBABA, 0x0A0A, 0x2A2A, 0x8A8A], ORDER), FIXED)
        self.assertEqual(a, b)
        self.assertEqual(a["ciphers"], [0x0A0A, 4865])
        ids = [extension["id"] for extension in a["extensions"]]
        # The two GREASE extensions stay distinct slots of their own list.
        self.assertEqual((ids[0], ids[-1]), (0x0A0A, 0x1A1A))
        key_share = next(e for e in a["extensions"] if e["id"] == 51)
        groups = next(e for e in a["extensions"] if e["id"] == 10)
        self.assertEqual(key_share["value"]["KeyShares"][0]["group"], 0x0A0A)
        self.assertEqual(groups["value"]["U16List"], [0x0A0A, 29])

    def test_only_a_shuffled_scope_reads_a_permuted_order_as_its_variant(self):
        grease = [0x3A3A, 0x5A5A, 0x7A7A, 0xCACA]
        retained = tls_read_form(hello(grease, ORDER), SHUFFLED)
        permuted = hello([0xBABA, 0x0A0A, 0x2A2A, 0x8A8A], list(reversed(ORDER)))
        report = compare_tls_captures(
            archive(retained, SHUFFLED), [TlsHello(1, 7, permuted)], [REQUEST]
        )
        self.assertEqual(report["connections_checked"], 1)

        fixed = tls_read_form(hello(grease, ORDER), FIXED)
        with self.assertRaisesRegex(ValueError, "no matching TLS capture"):
            compare_tls_captures(
                archive(fixed, FIXED), [TlsHello(1, 7, permuted)], [REQUEST]
            )

    def test_a_shuffle_does_not_excuse_different_extensions(self):
        grease = [0x3A3A, 0x5A5A, 0x7A7A, 0xCACA]
        retained = tls_read_form(hello(grease, ORDER), SHUFFLED)
        other = hello(grease, [0, 23, 51, 5])
        with self.assertRaisesRegex(ValueError, "no matching TLS capture"):
            compare_tls_captures(
                archive(retained, SHUFFLED), [TlsHello(1, 7, other)], [REQUEST]
            )


def hint_joint():
    def field(name, value):
        return {"name": name, "occurrence": 0, "value": {"Profile": list(value)}}

    return {
        "slots": [
            {
                "kind": "Headers",
                "capture": {
                    "fields": [
                        field("accept", b"*/*"),
                        field("downlink", b""),
                        field("rtt", b""),
                    ]
                },
            },
            {
                "kind": "PseudoHeaders",
                "capture": {"fields": [{"name": ":method"}, {"name": ":path"}]},
            },
        ]
    }


HINT_SCOPE = {
    "network_hints": [
        {"fields": [["downlink", list(b"10")], ["rtt", list(b"50")]], "weight": {}},
        {"fields": [["downlink", list(b"1.5")], ["rtt", list(b"300")]], "weight": {}},
    ]
}


def hint_wire(downlink, rtt):
    return (
        (":method", "GET"),
        (":path", "/"),
        ("accept", "*/*"),
        ("downlink", downlink),
        ("rtt", rtt),
    )


class NetworkHintTests(unittest.TestCase):
    def test_placeholders_accept_every_combination_of_their_scope(self):
        for downlink, rtt in [("10", "50"), ("1.5", "300")]:
            self.assertEqual(
                matching_fields(
                    hint_joint(), hint_wire(downlink, rtt), scope=HINT_SCOPE
                ),
                (3, 0),
            )

    def test_values_from_different_combinations_do_not_match(self):
        self.assertIsNone(
            matching_fields(hint_joint(), hint_wire("10", "300"), scope=HINT_SCOPE)
        )
        self.assertIsNone(
            matching_fields(hint_joint(), hint_wire("4", "50"), scope=HINT_SCOPE)
        )

    def test_placeholders_need_their_scope(self):
        with self.assertRaisesRegex(ValueError, "network hint placeholder"):
            matching_fields(hint_joint(), hint_wire("10", "50"))

    def test_replay_tuples_compare_hint_names_and_positions_only(self):
        def request(headers):
            return Request("GET", "/", headers, b"", {}, "h2")

        a = request((("accept", "*/*"), ("rtt", "50")))
        self.assertEqual(
            drawn_wire_tuple(a), drawn_wire_tuple(request((("accept", "*/*"), ("rtt", "300"))))
        )
        self.assertNotEqual(
            drawn_wire_tuple(a), drawn_wire_tuple(request((("rtt", "50"), ("accept", "*/*"))))
        )
        self.assertNotEqual(
            drawn_wire_tuple(a), drawn_wire_tuple(request((("accept", "x"), ("rtt", "50"))))
        )
        self.assertEqual(
            drawn_wire_tuple(Request("GET", "/", ("RTT:50",), b"", {}, "h1")),
            drawn_wire_tuple(Request("GET", "/", ("RTT:300",), b"", {}, "h1")),
        )


if __name__ == "__main__":
    unittest.main()
