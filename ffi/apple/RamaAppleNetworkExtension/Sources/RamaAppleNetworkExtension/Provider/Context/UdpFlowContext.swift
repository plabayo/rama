import Foundation
import Network

/// Queue-confined state for a UDP flow's read side.  Replaces
/// `closed: Bool`, `readPending: Bool`, and `demandPending: Bool`.
enum UdpFlowReadState {
    /// No read in flight, no pending demand.
    case idle
    /// A `readDatagrams` call is in flight.
    case reading
    /// A `readDatagrams` call is in flight AND a second demand arrived
    /// while it was pending — re-trigger `requestRead` on completion.
    case readingWithDemand
    /// Terminal — no further reads will be issued.
    case closed
}

/// See `TcpFlowContext` for the `@unchecked Sendable` rationale —
/// same queue-confinement invariant applies on the UDP side.
///
/// UDP egress lives entirely in Rust now (one unconnected
/// `tokio::net::UdpSocket` per intercepted flow); there is no
/// `NWConnection` or egress read pump to retain on the Swift side.
final class UdpFlowContext: @unchecked Sendable {
    init() {
    }

    weak var session: RamaUdpSessionHandle?
    /// Writer pump for client-bound replies; per-datagram `sentBy`
    /// endpoint is set from Rust's per-datagram peer attribution.
    var writer: UdpClientWritePump?
    var requestRead: (() -> Void)?
    var terminate: ((Error?) -> Void)?
    /// Read-side lifecycle — replaces the former `closed: Bool`,
    /// `readPending: Bool`, and `demandPending: Bool` triple.
    var readState: UdpFlowReadState = .idle
    /// Sticky one-shot flag: when `flow.readDatagrams` returns
    /// parallel arrays whose lengths do not match, we log once
    /// per flow instead of spamming. Subsequent mismatches still
    /// take the strict-paired-only code path (surplus datagrams
    /// get `peer = nil`).
    var endpointMismatchLogged: Bool = false
}
