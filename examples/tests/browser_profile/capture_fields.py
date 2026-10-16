"""Compare validated retained request fields with independent tshark headers.

Input is `rama ua view --json ARCHIVE`, not the archive's saved analysis. Match
one joint observation: combining unrelated regular/pseudo-header variants could
otherwise accept a request that was never captured. Request-bound values are not
retained in a profile and are counted separately; replay checks must verify them.
Compression, bodies and connection fingerprints require separate comparisons.
"""

from collections import Counter

from flows import FLOW_NAMES, flow_name, scope_matches


def matching_fields(capture, headers):
    """Return literal/bound field counts, or None for a different observation."""
    slots = {slot["kind"]: slot["capture"] for slot in capture.get("slots", [])}
    if not {"Headers", "PseudoHeaders"} <= slots.keys():
        return None
    regular = [(name, value) for name, value in headers if not name.startswith(":")]
    pseudo = [name for name, _ in headers if name.startswith(":")]
    if [field["name"] for field in slots["PseudoHeaders"]["fields"]] != pseudo:
        return None
    fields = slots["Headers"]["fields"]
    if len(fields) != len(regular):
        return None

    # Compare repeated fields in order, keeping request-owned values separate.
    occurrences = Counter()
    literal = bound = 0
    for field, (name, value) in zip(fields, regular):
        if field["name"] != name or field["occurrence"] != occurrences[name]:
            return None
        occurrences[name] += 1
        source = field["value"]
        if len(source) != 1:
            raise ValueError("ambiguous captured value source")
        kind, retained = next(iter(source.items()))
        if kind in ("Profile", "CaptureSafeProfile"):
            # HTTP field values are octets; tshark displays these fixture values
            # losslessly. Fail on non-Latin-1 text instead of replacing bytes.
            if bytes(retained) != value.encode("latin-1"):
                return None
            literal += 1
        elif kind == "Request":
            bound += 1
        else:
            raise ValueError("unknown captured value source")
    return literal, bound


def compare_capture_fields(inspected, blocks):
    if inspected["format_version"] != 1:
        raise ValueError("unsupported inspection format")
    covered = set()
    requests = literal = bound = 0
    for block in blocks:
        if block.from_server:
            continue
        flow = flow_name(block.headers)
        if flow is None:
            continue

        # Require one matching joint observation from this browser and flow.
        user_agent = dict(block.headers).get("user-agent")
        candidates = (
            variant["capture"]
            for profile in inspected["profiles"]
            if profile["key"]["user_agent"] == user_agent
            for scope in profile["scopes"]
            if scope_matches(scope, block, flow)
            for variant in scope["variants"]
        )
        match = next(
            (
                counts
                for capture in candidates
                if (counts := matching_fields(capture, block.headers)) is not None
            ),
            None,
        )
        if match is None:
            raise ValueError(
                f"{block.protocol} {flow} has no matching joint retained fields "
                f"(connection={block.connection}, stream={block.stream})"
            )
        literal += match[0]
        bound += match[1]
        requests += 1
        covered.add(flow)

    if covered != FLOW_NAMES:
        raise ValueError(
            "incomplete wire/profile flow coverage: "
            + str(sorted(FLOW_NAMES - covered))
        )
    return {
        "scope": "joint header order, multiplicity and retained literal values",
        "flows": sorted(covered),
        "requests_checked": requests,
        "literal_values_checked": literal,
        "request_bound_values_not_retained": bound,
    }


def connection_user_agents(requests):
    """Require one unambiguous browser identity on each request-bearing connection."""
    user_agents = {}
    for request in requests:
        if request.from_server:
            continue
        agents = [value for name, value in request.headers if name == "user-agent"]
        if len(agents) != 1:
            raise ValueError("missing or ambiguous request user agent")
        user_agents.setdefault(request.connection, set()).update(agents)
    if not user_agents or any(len(agents) != 1 for agents in user_agents.values()):
        raise ValueError("missing or mixed connection user agent")
    return {
        connection: next(iter(agents)) for connection, agents in user_agents.items()
    }
