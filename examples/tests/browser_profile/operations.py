"""Declare actual browser operations without changing their URIs or protocols.

The six measured flows remain mandatory. H3 discovery and a witnessed Client
Hints retry remain separate operations with their original URIs and protocols.
Native and packet oracles still verify each declared stream independently.
"""

from collections import Counter
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit

from capture_fields import matching_fields
from navigation import client_hint_pair, final_report
from flows import FLOWS, flow_name, require, request_authority, scope_matches
from qpack_bootstrap_wire import _same_connection, bootstrap_request
from qpack_fields_wire import matching_representations

DISCOVERY = "discover_h3"
HINT_DISCOVERY = "discover_client_hints"
DISCOVERIES = {DISCOVERY, HINT_DISCOVERY}


@dataclass(frozen=True)
class Operation:
    name: str
    flow: str
    protocol: str
    method: str
    uri: str
    packet: int
    connection: int
    stream: int
    joint: str | None = None
    request: str | None = None
    capture: dict | None = field(default=None, repr=False, compare=False)

    @property
    def key(self):
        return self.protocol, self.connection, self.stream


@dataclass(frozen=True)
class OperationLedger:
    operations: tuple[Operation, ...]
    replay: bool = False

    def __post_init__(self):
        names = [operation.name for operation in self.operations]
        require(len(names) == len(set(names)), "duplicate declared operation")
        require(
            set(FLOWS) <= set(names) <= set(FLOWS) | DISCOVERIES,
            "six measured operations and bounded explicit discovery required",
        )
        require(
            len({operation.key for operation in self.operations}) == len(names),
            "declared source operations share a stream",
        )
        for operation in self.operations:
            require(
                operation.flow
                == ("navigate" if operation.name in DISCOVERIES else operation.name),
                "operation/profile flow mismatch",
            )
            require(
                operation.protocol in ("h1", "h2", "h3"), "unknown operation protocol"
            )
            expected = flow_name(
                (
                    (":method", operation.method),
                    (":path", operation.uri),
                    *(
                        ((":protocol", "websocket"),)
                        if operation.flow == "ws" and operation.protocol != "h1"
                        else ()
                    ),
                ),
                protocol=operation.protocol,
            )
            require(
                expected == operation.flow
                or (
                    operation.flow == "navigate"
                    and operation.method == "GET"
                    and operation.uri == "/report?h3_probe=1"
                ),
                "undeclared operation URI",
            )
            require(
                all(
                    type(value) is int and value >= 0
                    for value in (
                        operation.packet,
                        operation.connection,
                        operation.stream,
                    )
                ),
                "invalid source operation identity",
            )

    @classmethod
    def from_driver(
        cls, frames, protocols, origin, report_url, *, report_html=None, completed=None
    ):
        require(
            set(protocols) == set(FLOWS), "complete measured browser protocols required"
        )
        require(
            report_url in (origin + "/report", origin + "/report?h3_probe=1"),
            "actual final report URL missing or outside the declared journey",
        )
        path = "/report?h3_probe=1" if report_url.endswith("?h3_probe=1") else "/report"
        authority = urlsplit(origin).netloc
        heads = [frame for frame in frames if frame.headers and not frame.from_server]
        operations, discoveries = [], []
        for flow in FLOWS:
            candidates = [
                frame
                for frame in heads
                if (flow == "navigate" or frame.protocol == protocols[flow])
                and request_authority(frame) == authority
                and (
                    (
                        flow == "navigate"
                        and dict(frame.headers).get(":method") == "GET"
                        and dict(frame.headers).get(":path") == path
                    )
                    or (
                        flow != "navigate"
                        and flow_name(frame.headers, protocol=frame.protocol) == flow
                    )
                )
            ]
            if flow == "navigate" and len(candidates) > 1:
                first, final = final_report(candidates, frames, report_html, completed)
                discoveries.append(cls.observed(HINT_DISCOVERY, "navigate", first))
                candidates = [final]
            require(
                len(candidates) == 1 and candidates[0].protocol == protocols[flow],
                "measured operation has no unique source stream: " + flow,
            )
            operations.append(cls.observed(flow, flow, candidates[0]))
        if path != "/report":
            candidates = [
                frame
                for frame in heads
                if dict(frame.headers).get(":method") == "GET"
                and dict(frame.headers).get(":path") == "/report"
                and request_authority(frame) == authority
            ]
            if len(candidates) == 2:
                first, second = sorted(candidates, key=lambda block: block.packet)
                client_hint_pair(first, second, frames, completed)
                discoveries.append(cls.observed(HINT_DISCOVERY, "navigate", first))
                candidates = [second]
            require(
                len(candidates) == 1, "H3 discovery navigation missing or ambiguous"
            )
            require(
                candidates[0].packet < operations[0].packet,
                "discovery navigation must precede the measured report",
            )
            discoveries.append(cls.observed(DISCOVERY, "navigate", candidates[0]))
        ledger = cls(
            tuple(
                sorted(discoveries, key=lambda operation: operation.packet) + operations
            )
        )
        ledger.validate_heads(heads)
        return ledger

    @staticmethod
    def observed(name, flow, block):
        fields = dict(block.headers)
        return Operation(
            name,
            flow,
            block.protocol,
            fields[":method"],
            fields[":path"],
            block.packet,
            block.connection,
            block.stream,
        )

    @property
    def names(self):
        return tuple(operation.name for operation in self.operations)

    @property
    def protocols(self):
        return {operation.name: operation.protocol for operation in self.operations}

    @property
    def measured_protocols(self):
        return {
            operation.name: operation.protocol
            for operation in self.operations
            if operation.name in FLOWS
        }

    def roles(self, protocol):
        return tuple(
            flow
            for flow in FLOWS
            if any(
                operation.protocol == protocol and operation.flow == flow
                for operation in self.operations
            )
        )

    def name(self, block):
        if block.from_server or not block.headers:
            return None
        fields = dict(block.headers)
        candidates = [
            operation
            for operation in self.operations
            if (
                (block.protocol, fields.get(":method"), fields.get(":path"))
                == (operation.protocol, operation.method, operation.uri)
                if self.replay
                else (block.protocol, block.connection, block.stream, block.packet)
                == (*operation.key, operation.packet)
            )
        ]
        if self.replay and len(candidates) > 1:
            candidates = [
                operation
                for operation in candidates
                if operation.capture is not None
                and matching_fields(
                    operation.capture, block.headers, protocol=block.protocol
                )
                is not None
            ]
            require(len(candidates) == 1, "ambiguous declared operation request fields")
        require(len(candidates) <= 1, "ambiguous declared operation")
        if candidates:
            operation = candidates[0]
            require(
                (fields.get(":method"), fields.get(":path"))
                == (operation.method, operation.uri),
                "declared stream changed method or URI",
            )
            return operation.name
        require(
            flow_name(block.headers, protocol=block.protocol) is None
            and fields.get(":path") != "/report?h3_probe=1",
            "undeclared or duplicated journey operation",
        )
        return None

    def role(self, block):
        name = self.name(block)
        return next(
            (operation.flow for operation in self.operations if operation.name == name),
            None,
        )

    def validate_heads(self, blocks):
        counts = Counter(
            name for block in blocks if (name := self.name(block)) is not None
        )
        require(
            counts == Counter({name: 1 for name in self.names}),
            "missing or duplicated measured/discovery operation",
        )

    def with_joints(self, reports):
        observed = []
        for operation in self.operations:
            joint = reports[operation.protocol]["connection_joints"].get(
                operation.connection
            )
            require(
                isinstance(joint, str)
                and len(joint) == 64
                and all(value in "0123456789abcdef" for value in joint),
                "operation lacks its independently verified connection joint",
            )
            observed.append(replace(operation, joint=joint))
        for protocol, report in reports.items():
            require(
                set(report["connection_joints"].values())
                == {
                    operation.joint
                    for operation in observed
                    if operation.protocol == protocol
                },
                "retained joint has no declared operation",
            )
        return replace(self, operations=tuple(observed))

    @staticmethod
    def connection_recipe(inspected, identifier):
        candidates = [
            (profile, scope, variant)
            for profile in inspected["profiles"]
            for scope in profile["scopes"]
            for variant in scope["variants"]
            if variant["capture"].get("level") == "Connection"
            and isinstance(variant["id"], list)
            and len(variant["id"]) == 32
            and all(type(value) is int and 0 <= value <= 255 for value in variant["id"])
            and bytes(variant["id"]).hex() == identifier
        ]
        require(len(candidates) == 1, "connection recipe is missing or ambiguous")
        return candidates[0]

    def with_requests(self, inspected, blocks, sections):
        observed = []
        for operation in self.operations:
            heads = [block for block in blocks if self.name(block) == operation.name]
            require(len(heads) == 1, "declared request has no unique source head")
            block = heads[0]
            profile, connection_scope, _variant = self.connection_recipe(
                inspected, operation.joint
            )
            candidates, captures = set(), {}
            for scope in profile["scopes"]:
                if not scope_matches(
                    scope, block, operation.flow
                ) or not _same_connection(
                    connection_scope.get("context", {}).get("connection", {}),
                    scope.get("context", {}).get("connection", {}),
                ):
                    continue
                for variant in scope["variants"]:
                    capture = variant["capture"]
                    if (
                        capture.get("level") != "Request"
                        or matching_fields(
                            capture, block.headers, protocol=block.protocol
                        )
                        is None
                    ):
                        continue
                    if block.protocol == "h3":
                        section = sections.get(
                            (block.packet, block.connection, block.stream)
                        )
                        require(
                            section is not None,
                            "declared request lacks raw QPACK evidence",
                        )
                        if not matching_representations(
                            capture, block.headers, section.fields
                        ):
                            continue
                    raw = variant["id"]
                    require(
                        isinstance(raw, list)
                        and len(raw) == 32
                        and all(
                            type(value) is int and 0 <= value <= 255 for value in raw
                        ),
                        "invalid declared request joint ID",
                    )
                    candidates.add(bytes(raw).hex())
                    captures[bytes(raw).hex()] = capture
            require(
                len(candidates) == 1, "declared request joint is missing or ambiguous"
            )
            identifier = candidates.pop()
            observed.append(
                replace(operation, request=identifier, capture=captures[identifier])
            )
        return replace(self, operations=tuple(observed))

    def schedule(self, inspected, blocks, warmups):
        """Replay observed joint/operation pairs; startup exchanges stay separate."""
        plans = []
        for operation in self.operations:
            require(
                operation.joint is not None and operation.request is not None,
                "operation recipes are not independently verified",
            )
            preliminary = list(warmups.get(operation.joint, ()))
            profile, scope, variant = self.connection_recipe(inspected, operation.joint)
            slots = {
                slot["kind"]: slot["capture"] for slot in variant["capture"]["slots"]
            }
            initial = False
            if operation.protocol == "h3" and "Http3Bootstrap" in slots:
                bootstrap = slots["Http3Bootstrap"]
                if operation.stream == bootstrap["bindings"]["stream_id"]:
                    head, _capture = bootstrap_request(
                        bootstrap,
                        profile,
                        scope,
                        [
                            block
                            for block in blocks
                            if block.protocol == "h3"
                            and block.connection == operation.connection
                        ],
                    )
                    require(
                        self.name(head) == operation.name
                        and bytes(bootstrap["request"]).hex() == operation.request,
                        "initial operation does not own its Bootstrap request",
                    )
                    require(
                        preliminary and preliminary[-1] == operation.joint,
                        "initial operation lacks its explicit startup plan",
                    )
                    preliminary.pop()  # The actual operation emits this first section.
                    initial = True
            plans.append(
                dict(operation=operation, warmups=tuple(preliminary), initial=initial)
            )
        return plans

    def for_replay(self):
        require(
            all(
                operation.joint is not None and operation.request is not None
                for operation in self.operations
            ),
            "source operation joints are not verified",
        )
        return replace(self, replay=True)

    def check_matrix(self, blocks, reports):
        self.validate_heads(blocks)
        matrix = Counter()
        for block in blocks:
            if (name := self.name(block)) is None:
                continue
            joint = reports[block.protocol]["connection_joints"].get(block.connection)
            require(joint is not None, "declared operation has no native wire joint")
            matrix[block.protocol, joint, name] += 1
        expected = Counter(
            (operation.protocol, operation.joint, operation.name)
            for operation in self.operations
        )
        require(
            matrix == expected, "incomplete or swapped retained-joint/operation matrix"
        )
        return [
            {"protocol": protocol, "joint": joint, "operation": name, "count": count}
            for (protocol, joint, name), count in sorted(matrix.items())
        ]
