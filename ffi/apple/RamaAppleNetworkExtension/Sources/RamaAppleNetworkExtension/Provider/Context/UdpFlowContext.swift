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

/// One-shot ownership hand-off between Rust's UDP close callback and the
/// core's admission/registry transaction.
///
/// Rust owns the session handle before Swift knows whether the corresponding
/// kernel flow can be claimed. A max-lifetime close in that window must be
/// remembered, but must not close a flow that admission may still return to
/// NetworkExtension for passthrough. The core therefore performs registry
/// publication from inside `claim`; a callback cannot observe `.claimed`
/// until the map and its pressure-accounting mirror are both visible.
struct UdpFlowRegistrationGate: Sendable {
    private enum Phase {
        case pending
        case claimed
        case abandoned
    }

    private struct State {
        var phase: Phase = .pending
        var serverCloseRecorded = false
        var serverCloseForwarded = false
    }

    private let state = Locked(State())

    /// Record a Rust terminal callback. `true` transfers exactly one callback
    /// to normal claimed-flow teardown; `false` means it was retained pending
    /// admission or discarded after rejection.
    func recordServerClose() -> Bool {
        state.withLock { state in
            switch state.phase {
            case .pending:
                state.serverCloseRecorded = true
                return false
            case .claimed:
                guard !state.serverCloseForwarded else { return false }
                state.serverCloseForwarded = true
                return true
            case .abandoned:
                return false
            }
        }
    }

    /// Claim ownership and execute the registry publication while the gate is
    /// held. The publication closure must remain a small, non-callbacking
    /// critical section. Lock order is `core.stateQueue -> gate ->
    /// pressureVictimState`; callback paths release this gate before touching
    /// a writer, flow queue, or core, so the order cannot invert.
    func claim<R>(
        publishing body: (_ pendingServerClose: Bool) -> R
    ) -> (value: R, pendingServerClose: Bool)? {
        state.withLock { state in
            guard case .pending = state.phase else { return nil }
            let pendingServerClose = state.serverCloseRecorded
            state.phase = .claimed
            state.serverCloseForwarded = pendingServerClose
            return (
                body(pendingServerClose),
                pendingServerClose
            )
        }
    }

    /// Permanently decline ownership. A recorded pre-claim close is consumed
    /// without touching the kernel flow, which remains eligible for
    /// passthrough.
    func abandon() {
        state.withLock { state in
            guard case .pending = state.phase else { return }
            state.phase = .abandoned
            state.serverCloseRecorded = false
        }
    }
}

/// See `TcpFlowContext` for the `@unchecked Sendable` rationale —
/// same queue-confinement invariant applies on the UDP side.
///
/// UDP egress lives entirely in Rust now (one unconnected
/// `tokio::net::UdpSocket` per intercepted flow); there is no
/// `NWConnection` or egress read pump to retain on the Swift side.
///
/// Ownership: `TransparentProxyCore` retains the per-flow
/// `UdpFlowSession` directly; the session owns this context as a
/// `let` member. There is no back-reference from context to
/// session — when the session leaves the core's map, both objects
/// deallocate together. The previous `lifetimeAnchor` scheme
/// (context retaining session) was a cycle the watchdog was forced
/// to break; the cycle no longer exists.
final class UdpFlowContext: @unchecked Sendable {
    init() {
    }

    weak var session: RamaUdpSessionHandle?
    /// Coordinates callbacks that can arrive before core admission owns the
    /// NetworkExtension flow.
    let registrationGate = UdpFlowRegistrationGate()
    /// Serial queue that confines this context's mutable lifecycle state.
    var flowQueue: DispatchQueue?
    /// Lifecycle identity captured before registration. Keeping it on the
    /// context prevents a late teardown from losing the generation when its
    /// weak session owner has already deallocated.
    var engineGeneration: UInt64?
    /// Writer pump for client-bound replies; per-datagram `sentBy`
    /// endpoint is set from Rust's per-datagram peer attribution.
    var writer: UdpClientWritePump?
    #if DEBUG || RAMA_TESTING
        var requestRead: (() -> Void)?
    #endif
    /// Probe-aware Rust demand path. The legacy no-argument closure above is
    /// retained for ordinary service demand and focused phase tests.
    var requestReadWithProbe: ((UInt64) -> Void)?
    var terminate: ((Error?) -> Void)?
    /// Read-side lifecycle — replaces the former `closed: Bool`,
    /// `readPending: Bool`, and `demandPending: Bool` triple.
    var readState: UdpFlowReadState = .idle
    /// Valid when `readState == .readingWithDemand`; zero is an ordinary
    /// service demand, not an absence marker.
    var pendingReadProbeId: UInt64 = 0
    /// Queue-confined exception to the generic post-start reconciliation:
    /// graceful close intentionally keeps the registry anchor after closing
    /// reads, until accepted client-bound datagrams drain or hit the backstop.
    var defersRegistryRemovalForGracefulDrain = false
    /// Sticky one-shot flag: when `flow.readDatagrams` returns
    /// parallel arrays whose lengths do not match, we log once
    /// per flow instead of spamming. Subsequent mismatches still
    /// take the strict-paired-only code path (surplus datagrams
    /// get `peer = nil`).
    var endpointMismatchLogged: Bool = false
}
