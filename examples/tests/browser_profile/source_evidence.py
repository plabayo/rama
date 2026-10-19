"""Use the same driver, packet and profile oracles for local and remote TLS captures."""

from capture_fields import compare_capture_fields
from flow_bodies import check_flow_bodies
from flows import flow_protocols
from operations import OperationLedger
from qpack_fields_wire import compare_field_metadata, sections_from_wire
from remote.admission import admit, complete_responses
from replay import compare_native_connections, tls_hellos
from tls_wire import compare_tls_captures
from wire import Traffic, parse_pdml


def source_evidence(data, inspected, page, origin, port):
    probe = page["page_results"]["websocket"]["probe"]
    frames = parse_pdml(data, "mixed", port, include_data=True, websocket_probe=probe)
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
    admission = admit(data, frames, page, origin, operations=operations)
    plan = flow_protocols(frames, operations=operations)
    if operations.measured_protocols != page["protocols"]:
        raise ValueError("driver protocol plan differs from source wire")
    source = dict(
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
