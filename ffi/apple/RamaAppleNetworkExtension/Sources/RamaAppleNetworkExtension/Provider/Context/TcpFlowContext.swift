import Foundation
import Network

/// `@unchecked Sendable` because every mutable field is read or written
/// only from a block executing on the flow's dedicated serial
/// `flowQueue`. The type system cannot see this invariant; the
/// annotation makes it explicit so the per-flow closures that capture
/// the context (flow.open / connection.receive completions, etc.) stay
/// Swift-6-clean instead of forcing those closures to drop their
/// `@Sendable` requirement.
/// Per-flow data-path mode. Switches from `.viaRust` to
/// `.promoted` when the in-Rust service calls
/// `PromoteHandle::into_passthrough` — from that moment on
/// the per-flow `TcpDirectForwarder` owns the kernel flow and
/// the egress `NWConnection`.
///
/// Mode-aware close handlers (`onServerClosed`, `onCloseEgress`)
/// use `mode != .viaRust` to skip teardown of the kernel flow /
/// egress connection — they are owned by the forwarder until
/// both directions finish.
///
/// Internally the forwarder distinguishes its OWN per-direction
/// phases (buffering / active / finishing / finished) — see
/// `TcpDirectForwarder.DirectionPhase`. Carrying that granularity
/// on `TcpFlowContext.mode` too would be redundant: every other
/// caller only cares about the binary "is the forwarder running
/// or not" question, and the forwarder is the source of truth
/// for the finer states.
enum TcpFlowMode {
    /// Bytes flow through the in-Rust service (default).
    case viaRust
    /// Promote cutover initiated. The `TcpDirectForwarder`
    /// owns the kernel flow and the egress NWConnection
    /// lifecycle from this point. Mode-aware close handlers
    /// observe this and skip their own teardown.
    case promoted
}

final class TcpFlowContext: @unchecked Sendable {
    // Connection is held behind the injectable protocol so unit tests
    // can drive the per-flow state machine via a mock instead of
    // standing up a real NWConnection.
    weak var session: RamaTcpSessionHandle?
    /// Egress NWConnection, reachable from late callbacks that must
    /// still be able to `cancel()` the flow.
    var connection: (any NwConnectionLike)?
    /// Read pumps reachable from the Rust → Swift demand callbacks.
    var clientReadPump: TcpClientReadPump?
    var egressReadPump: NwTcpConnectionReadPump?
    /// Writer pumps retained until terminal teardown so we can
    /// cancel them from dispatcher-owned close paths.
    var clientWritePump: TcpClientWritePump?
    var egressWritePump: NwTcpConnectionWritePump?
    /// Egress `NWConnection` reached `.ready`. Set on `flowQueue`; read
    /// off-queue by the stop-the-world wake reconcile (same relaxation
    /// the sleep teardown already relies on).
    var egressReady = false
    /// A terminal close signal (server EOF / egress close, `viaRust`
    /// mode) was observed on `flowQueue` and the graceful drain +
    /// teardown was kicked off. Set on `flowQueue`; read off-queue by the
    /// periodic maintenance watchdog (same relaxation as `egressReady`).
    /// A flow still in the registry a maintenance tick after this is set
    /// has a wedged drain (the peer stopped reading, so the in-flight
    /// `flow.write` / `connection.send` completion never fired and
    /// `closeWhenDrained` never finished) and is force-torn-down — see
    /// `TcpFlowSession.armTerminalDrainBackstop` /
    /// `TransparentProxyCore.collectMaintenanceKicksLocked`.
    var terminalSignalled = false
    /// Mode of the per-flow data path. Mutated only on the
    /// per-flow `DispatchQueue`. See [`TcpFlowMode`].
    var mode: TcpFlowMode = .viaRust
    /// Active when `mode == .promoted`. Owns the kernel ↔
    /// NWConnection direct read/write loops + cutover
    /// buffer.
    var directForwarder: TcpDirectForwarder?
    /// Single source of truth for terminal-state cleanup.
    /// Initialised once by `TcpFlowSession.init`. Every closure
    /// that needs to tear the flow down reaches it via
    /// `ctx?.teardown?`, which is a no-op if the context has
    /// already been dropped by a racing path. See
    /// `TcpFlowTeardown`.
    var teardown: TcpFlowTeardown?
    /// The per-flow serial queue that confines every mutation of this
    /// context (and the teardown's `done` flag). Set once by
    /// `TcpFlowSession.init`. Lifecycle paths that originate off this
    /// queue — system sleep/wake and engine detach — dispatch their
    /// teardown onto it so it stays single-threaded with the kernel /
    /// NWConnection callbacks rather than racing them.
    var flowQueue: DispatchQueue?

    init() {
    }
}
