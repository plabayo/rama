"""Check HTTP/3 recorder prefixes against independently decoded stream bytes.

QUIC reassembly here only joins tshark's decrypted STREAM payloads. Recorder
scheduling across streams is not observable on the wire: these checks establish
prefix contents, not the exact first-request freeze or cross-stream event order.
No request values or QPACK strings are returned in reports.
"""

from dataclasses import dataclass, field as data_field

from quic_wire import H3_SETTINGS, client_settings
from quic_stream_wire import StreamPrefix, stream_prefixes, varint
from qpack_wire import ENCODER_STREAM, encoder_instruction_evidence
from tls_wire import Reader

CONTROL_STREAM = 0
CANCEL_PUSH = 3
GOAWAY = 7
MAX_PUSH_ID = 13
# RFC 9114 §7.2.8 reserved frame types.
FIRST_RESERVED_FRAME = 0x21
RESERVED_FRAME_STEP = 0x1F
PRIORITY_UPDATE_REQUEST = 0xF0700
PRIORITY_UPDATE_PUSH = 0xF0701
# These are role/capability advertisements, added after the decoder context is
# configured. The recorder retains that context, not these two capabilities.
ENABLE_CONNECT_PROTOCOL = 8
H3_DATAGRAM = 0x33
MAX_CONTROL_FRAMES = 256


def control_frames(stream):
    """Decode recorder-visible control metadata and bounded reserved bodies."""
    if stream.stream_type != CONTROL_STREAM:
        raise ValueError("expected HTTP/3 control stream")
    source, result = Reader(stream.payload), []
    while source.remaining():
        kind, length = varint(source), varint(source)
        body = Reader(source.take(length))
        element, value = None, []
        if kind in (CANCEL_PUSH, GOAWAY, MAX_PUSH_ID):
            element = varint(body)
            body.finish()
        elif kind in (PRIORITY_UPDATE_REQUEST, PRIORITY_UPDATE_PUSH):
            element = varint(body)
            value = list(body.take(body.remaining()))
        elif (
            kind >= FIRST_RESERVED_FRAME
            and (kind - FIRST_RESERVED_FRAME) % RESERVED_FRAME_STEP == 0
        ):
            value = list(body.take(body.remaining()))
        # SETTINGS have their own comparison. Other unassigned bodies remain
        # outside the reusable profile's payload policy.
        result.append(
            dict(frame_type=kind, length=length, element_id=element, value=value)
        )
        if len(result) > MAX_CONTROL_FRAMES:
            raise ValueError("HTTP/3 control frame limit")
    if not result or result[0]["frame_type"] != H3_SETTINGS:
        raise ValueError("HTTP/3 control stream must begin with SETTINGS")
    if sum(frame["frame_type"] == H3_SETTINGS for frame in result) != 1:
        raise ValueError("repeated HTTP/3 control SETTINGS")
    return result


@dataclass(frozen=True)
class SequenceEvidence:
    streams: tuple[StreamPrefix, ...]
    controls: tuple[dict, ...]
    local_settings: dict
    encoder_instructions: tuple[dict, ...] = ()
    encoder_bytes: tuple[bytes, ...] = data_field(default=(), repr=False)

    def matches(self, capture):
        return sequence_matches(capture, self)


def sequence_evidence(data, server_port):
    """Associate browser prefixes and server decoder context with one connection."""
    streams = stream_prefixes(data, server_port)
    settings = client_settings(data, server_port, from_server=True)
    instructions = encoder_instruction_evidence(data, server_port, streams)
    result = {}
    for (connection, from_server), prefixes in streams.items():
        if from_server:
            continue
        control = [
            stream for stream in prefixes if stream.stream_type == CONTROL_STREAM
        ]
        if len(control) != 1 or connection not in settings:
            raise ValueError("missing control stream or server decoder SETTINGS")
        context = dict(settings[connection])
        context["fields"] = [
            entry
            for entry in context["fields"]
            if entry["id"] not in (ENABLE_CONNECT_PROTOCOL, H3_DATAGRAM)
        ]
        result[connection] = SequenceEvidence(
            tuple(prefixes),
            tuple(control_frames(control[0])),
            context,
            *instructions.get(connection, ((), ())),
        )
    return result


def sequence_matches(capture, evidence):
    """Require one wire-backed prefix; cross-stream freeze order stays unverified.

    Empty instruction prefixes remain valid despite later table activity. A
    nonempty prefix must match decoded encoder metadata in its own stream order;
    this still does not establish the recorder's exact first-request cutoff.
    """
    if (
        capture.get("completeness") != "Complete"
        or capture.get("local_settings") != evidence.local_settings
    ):
        return False
    instructions = capture.get("encoder_instructions", [])
    if instructions != list(evidence.encoder_instructions[: len(instructions)]):
        return False
    observed = {stream.stream_id: stream.stream_type for stream in evidence.streams}
    seen, controls = set(), []
    control_seen = False
    for event in capture.get("events", []):
        if set(event) == {"Stream"}:
            stream = event["Stream"]
            identifier, kind = stream["stream_id"], stream["stream_type"]
            if identifier in seen or observed.get(identifier) != kind:
                return False
            seen.add(identifier)
            control_seen |= kind == CONTROL_STREAM
        elif set(event) == {"Control"}:
            if not control_seen:
                return False
            controls.append(event["Control"])
        else:
            raise ValueError("unknown captured HTTP/3 sequence event")
    if instructions and not any(
        observed[identifier] == ENCODER_STREAM for identifier in seen
    ):
        return False
    return bool(controls) and controls == list(evidence.controls[: len(controls)])
