"""Verify first-request QPACK associations without retaining inserted values.

The independent ls-qpack decoder resolves raw encoder instructions, including
Huffman strings and static-name references. Names and values live only inside
this comparison; reports contain counts. Recorder freeze timing and ordering
between different QUIC streams remain outside the wire evidence.
"""

import pylsqpack
from capture_fields import matching_fields
from flows import flow_name, scope_matches

MAX_CAPACITY = 65536
from pdml import MAX_PDML_BYTES


def prefixed(value, width, flags=0):
    """Encode a bounded integer for an independent decoder query."""
    if type(value) is not int or not 0 <= value < 1 << 62:
        raise ValueError("invalid QPACK decoder query index")
    maximum = (1 << width) - 1
    result = bytearray([flags | min(value, maximum)])
    if value >= maximum:
        value -= maximum
        while value >= 128:
            result.append(128 | (value & 127))
            value >>= 7
        result.append(value)
    return bytes(result)


def inserted_fields(sequence, evidence):
    """Resolve the retained prefix in a fresh, bounded independent table.

    Query each newly inserted entry before processing later instructions. This
    preserves its actual value even when a later instruction evicts it. These
    transient fields must never be attached to JSON reports or exception text.
    """
    metadata = sequence["encoder_instructions"]
    raw = evidence.encoder_bytes[: len(metadata)]
    if (
        len(raw) != len(metadata)
        or list(evidence.encoder_instructions[: len(metadata)]) != metadata
    ):
        raise ValueError("incomplete QPACK bootstrap instruction evidence")
    capacities = [
        entry["Capacity"]["capacity"] for entry in metadata if "Capacity" in entry
    ]
    maximum = max(capacities, default=0)
    if type(maximum) is not int or not 0 <= maximum <= MAX_CAPACITY:
        raise ValueError("QPACK bootstrap capacity limit")
    decoder = pylsqpack.Decoder(maximum, 0)
    result, total, count = {}, 0, 0
    try:
        for index, (entry, instruction) in enumerate(zip(metadata, raw)):
            decoder.feed_encoder(instruction)
            if "Capacity" in entry:
                continue
            count += 1
            if maximum < 32:
                raise ValueError("QPACK insertion without table capacity")
            required = count % (2 * (maximum // 32)) + 1
            section = prefixed(required, 8) + b"\x00\x80"
            _feedback, fields = decoder.feed_header(index * 4, section)
            if len(fields) != 1:
                raise ValueError("ambiguous independent QPACK insertion")
            name, value = fields[0]
            total += len(name) + len(value)
            if total > MAX_PDML_BYTES:
                raise ValueError("QPACK bootstrap decoded byte limit")
            result[index] = (count - 1, name, value)
    except (
        pylsqpack.DecompressionFailed,
        pylsqpack.EncoderStreamError,
        pylsqpack.StreamBlocked,
    ):
        raise ValueError("independent QPACK bootstrap decoding failed") from None
    return result


def _same_connection(requested, observed):
    """Keep the selection model's resumption, early-data and token constraints."""
    if requested.get("resumption") == "Unknown":
        resumed = observed.get("resumption") != "Resumed"
    else:
        resumed = observed.get("resumption") == requested.get("resumption")
    early = (
        observed.get("early_data") is not True
        if requested.get("early_data") is None
        else observed.get("early_data") == requested["early_data"]
    )
    token = requested.get("token_present")
    return (
        resumed and early and (token is None or observed.get("token_present") == token)
    )


def bootstrap_request(capture, profile, connection_scope, requests, *, rebind_stream=False):
    """Resolve one exact referenced joint and initial head inside its native connection."""
    if set(capture) != {"request", "method", "fields", "bindings"}:
        raise ValueError("unknown or incomplete H3 bootstrap capture")
    reference = capture["request"]
    if (
        not isinstance(reference, list)
        or len(reference) != 32
        or any(type(value) is not int or not 0 <= value <= 255 for value in reference)
    ):
        raise ValueError("invalid H3 bootstrap request identity")
    bindings = capture["bindings"]
    if (
        set(bindings) != {"stream_id", "insertions", "complete"}
        or bindings["complete"] is not True
    ):
        raise ValueError("incomplete H3 bootstrap associations")
    stream = bindings["stream_id"]
    fields = capture["fields"]
    if (
        type(stream) is not int
        or not 0 <= stream < 1 << 62
        or stream & 3
        or type(fields) is not int
        or fields <= 0
    ):
        raise ValueError("invalid H3 bootstrap request coordinates")
    heads = [block for block in requests if not block.from_server and block.headers]
    if not heads:
        raise ValueError("missing H3 bootstrap request")
    first_stream = min(heads, key=lambda block: block.packet).stream
    initial = [block for block in heads if block.stream == first_stream]
    if first_stream != (0 if rebind_stream else stream) or len(initial) != 1:
        raise ValueError("missing or ambiguous initial H3 request head")
    initial = initial[0]
    if (
        len(initial.headers) != fields
        or dict(initial.headers).get(":method") != capture["method"]
    ):
        raise ValueError("H3 bootstrap method or field count mismatch")

    # Resolve the exact retained identity inside this browser/profile and the
    # connection context that supplied the matched connection joint.
    flow = flow_name(initial.headers)
    headers = dict(initial.headers)
    if (
        flow is None
        and headers.get(":method") == "GET"
        and headers.get("sec-fetch-mode") == "navigate"
        and headers.get("sec-fetch-dest") == "document"
    ):
        # The bootstrap --next segment supplies a fresh same-origin URI. Its
        # navigation metadata, rather than the old path, identifies the recipe.
        flow = "navigate"
    candidates = [
        variant["capture"]
        for scope in profile["scopes"]
        if scope_matches(scope, initial, flow)
        and _same_connection(
            connection_scope.get("context", {}).get("connection", {}),
            scope.get("context", {}).get("connection", {}),
        )
        for variant in scope["variants"]
        if variant["id"] == reference
    ]
    if len(candidates) != 1 or matching_fields(candidates[0], initial.headers) is None:
        raise ValueError("H3 bootstrap reference has no matching scoped request joint")

    return initial, candidates[0]


def verify_bootstrap(capture, sequence, evidence, profile, connection_scope, requests, *, rebind_stream=False):
    """Require the referenced joint, first stream and every exact field binding."""
    initial, _request_capture = bootstrap_request(
        capture, profile, connection_scope, requests, rebind_stream=rebind_stream
    )
    bindings = capture["bindings"]
    fields = capture["fields"]
    inserted = inserted_fields(sequence, evidence)
    retained = bindings["insertions"]
    if len(retained) != len(inserted):
        raise ValueError("H3 bootstrap insertion count mismatch")
    wire_fields = [
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in initial.headers
    ]
    if sum(len(name) + len(value) for name, value in wire_fields) > MAX_PDML_BYTES:
        raise ValueError("H3 bootstrap request byte limit")
    for binding, (instruction, (absolute, name, value)) in zip(
        retained, inserted.items()
    ):
        if set(binding) != {"instruction_index", "insertion_index", "field"}:
            raise ValueError("unknown H3 bootstrap insertion binding")
        if (
            type(binding["instruction_index"]) is not int
            or type(binding["insertion_index"]) is not int
            or binding["instruction_index"] != instruction
            or binding["insertion_index"] != absolute
        ):
            raise ValueError("H3 bootstrap insertion identity mismatch")
        association = binding["field"]
        if isinstance(association, dict):
            unique = association.get("Unique")
            if (
                set(association) != {"Unique"}
                or not isinstance(unique, dict)
                or set(unique) != {"field_index"}
                or type(unique["field_index"]) is not int
                or not 0 <= unique["field_index"] < fields
            ):
                raise ValueError("invalid H3 bootstrap field association")
        elif association not in ("Absent", "Ambiguous"):
            # An evicted/unavailable native association is not established by
            # this initial-head oracle. Keep that limitation explicit.
            raise ValueError("unverified H3 bootstrap field association state")
        positions = [
            index for index, pair in enumerate(wire_fields) if pair == (name, value)
        ]
        expected = (
            {"Unique": {"field_index": positions[0]}}
            if len(positions) == 1
            else ("Absent" if not positions else "Ambiguous")
        )
        if binding["field"] != expected:
            raise ValueError("H3 bootstrap field association mismatch")
    return len(inserted)
