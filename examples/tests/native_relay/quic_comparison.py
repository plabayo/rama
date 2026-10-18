"""Compare native QUIC first flights, parameters and both H3 SETTINGS offers.

Connection IDs are fresh identities: compare their lengths in fingerprints and
check their literal values separately. Every other measured difference remains
visible, including legal native mirroring limits and independently chosen settings.
"""

from flows import require
from quic_wire import VERSION_1, VERSION_2, client_settings, first_flights
from wire import one, pdml_packets

# RFC 9000 section 18.2: the client's per-connection source CID parameter.
INITIAL_SOURCE_CONNECTION_ID = 0x0F


def observe(data, port):
    flights = first_flights(data, port)
    require(len(flights) == 1, "expected one complete QUIC first flight")
    flight = flights[0]
    parameters = [
        {
            "id": identifier,
            "value": (
                {"ConnectionLength": len(body)}
                if identifier == INITIAL_SOURCE_CONNECTION_ID
                else {"Literal": body.hex()}
            ),
        }
        for identifier, body in flight.parameters
    ]
    settings = {}
    for name, from_server in (("client", False), ("server", True)):
        observations = client_settings(data, port, from_server=from_server)
        require(len(observations) == 1, "expected one H3 SETTINGS offer per endpoint")
        settings[name] = next(iter(observations.values()))
    identifiers = set()
    for packet in pdml_packets(data):
        if one(packet, "udp.dstport") != str(port):
            continue
        for field in packet.iter("field"):
            if field.get("name") == "quic.scid" and field.get("value"):
                identifiers.add(field.get("value"))
    require(bool(identifiers), "missing client QUIC connection identities")
    return (
        dict(first_flight=flight.flight, parameters=parameters, settings=settings),
        identifiers,
    )


def compare_quic_legs(ingress, egress, ingress_port, egress_port, version):
    before, ingress_ids = observe(ingress, ingress_port)
    after, egress_ids = observe(egress, egress_port)
    wanted = {1: VERSION_1, 2: VERSION_2}[version]
    require(
        before["first_flight"]["version"] == after["first_flight"]["version"] == wanted,
        "relay QUIC version differs",
    )
    require(ingress_ids.isdisjoint(egress_ids), "relay reused ingress QUIC identity")
    matches = {
        name: before[name] == after[name]
        for name in ("first_flight", "parameters", "settings")
    }
    return dict(
        scope="measured Initial layout, ordered parameter bodies and SETTINGS values",
        limits="no cross-stream startup chronology or compressed QPACK history equality",
        version=version,
        fresh_connection_ids=True,
        matches=matches,
        fingerprint_match=all(matches.values()),
        ingress=before,
        egress=after,
    )
