"""Use the same driver, packet and profile oracles for local and remote TLS captures."""

from capture_fields import compare_capture_fields
from flow_bodies import check_flow_bodies
from flows import flow_protocols
from operations import OperationLedger
from qpack_fields_wire import compare_field_metadata, sections_from_wire
from remote.admission import admit, complete_responses
from quic_stream_wire import requestless_connections as requestless_quic_connections
from remote.background import partition
from replay import compare_native_connections, tls_hellos
from tcp_evidence import account_tcp
from tls_wire import compare_tls_captures
from wire import Traffic, parse_pdml


def source_evidence(
    data,
    inspected,
    page,
    origin,
    port,
    *,
    independent_observations=False,
    tcp_evidence=None,
    require_complete_tcp=False,
):
    if require_complete_tcp and tcp_evidence is None:
        raise ValueError("fresh capture requires complete TCP/TLS evidence")
    accounting = (
        account_tcp(data, port, tcp_evidence)
        if tcp_evidence is not None
        else dict(
            complete=False,
            scope="historical decoded projection; full TCP/TLS accounting witness absent",
        )
    )
    requestless = frozenset(
        ("tcp", item["connection"])
        for item in accounting.get("connections", ())
        if item["requestless_h2"] or item["no_application_data"]
    )
    # Native QUIC has no separate byte witness: every packet must decrypt.
    requestless_quic = frozenset(
        ("udp", connection) for connection in requestless_quic_connections(data, port)
    )
    probe = page["page_results"]["websocket"]["probe"]
    frames = parse_pdml(data, "mixed", port, include_data=True, websocket_probe=probe)
    independent, inventory = None, frozenset()
    if independent_observations:
        frames, independent, inventory = partition(
            data,
            frames,
            page,
            origin,
            inspected,
            requestless_connections=requestless | requestless_quic,
        )
    operations = OperationLedger.from_driver(
        frames,
        page["protocols"],
        origin,
        page.get("report_url"),
        report_html=page["report_html"],
        completed=complete_responses(data, port),
    )
    traffic = Traffic(
        tuple(block for block in frames if block.headers),
        tuple(frames),
        check_flow_bodies(frames, websocket_probe=probe, operations=operations),
    )
    admission = admit(
        data,
        frames,
        page,
        origin,
        operations=operations,
        independent_connections=inventory | requestless | requestless_quic,
    )
    plan = flow_protocols(frames, operations=operations)
    if operations.measured_protocols != page["protocols"]:
        raise ValueError("driver protocol plan differs from source wire")
    source = dict(
        tcp_accounting=accounting,
        requestless_quic_connections=sorted(
            connection for _, connection in requestless_quic
        ),
        admission=admission,
        fields=compare_capture_fields(
            inspected, traffic.headers, operations=operations
        ),
        tls=compare_tls_captures(
            inspected, tls_hellos(data, plan.values()), traffic.headers
        ),
        connections=compare_native_connections(
            inspected,
            data,
            port,
            traffic.headers,
            plan,
            same_traffic_native=True,
            operations=operations,
        ),
        bodies=traffic.bodies,
    )
    if independent is not None:
        source["independent_observations"] = independent
    operations = operations.with_joints(source["connections"])
    source["operation_matrix"] = operations.check_matrix(frames, source["connections"])
    sections = sections_from_wire(data, port) if "h3" in plan.values() else {}
    if "h3" in plan.values():
        source["qpack"] = compare_field_metadata(
            inspected,
            traffic.headers,
            sections,
            expected_flows=operations.roles("h3"),
            operations=operations,
            connection_joints=source["connections"]["h3"]["connection_joints"],
        )
    operations = operations.with_requests(inspected, traffic.headers, sections)
    return traffic, operations, source
