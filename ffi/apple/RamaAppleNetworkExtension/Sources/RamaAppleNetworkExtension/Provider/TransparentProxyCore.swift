import Foundation
import Network
import RamaAppleNEFFI

/// Apple-framework-free home of the transparent-proxy per-flow state
/// machine, the engine handle ownership, and the session / context
/// registration maps.
///
/// `RamaTransparentProxyProvider` is the type the Apple system-extension
/// runtime instantiates and calls into; that subclass requirement is the
/// only reason it exists. The actual logic — receiving an intercepted
/// flow, wiring its read / write pumps to a Rust session, observing
/// `NWConnection` state transitions, cleaning up on terminal events —
/// has no reason to live in a `NETransparentProxyProvider` subclass and
/// historically just did so because it grew there.
///
/// Splitting that logic into this core type lets:
///
/// * unit tests drive the full per-flow lifecycle against a mock flow
///   (`MockTcpFlow` / `MockUdpFlow`) and a mock NWConnection
///   (`MockNwConnection`) without standing up a system extension or
///   real socket;
/// * end-to-end tests exercise the *real* Rust engine with mocked
///   Apple-framework surface, verifying byte flow + cleanup + memory
///   bounds under realistic scheduling;
/// * the provider become a thin (~150-line) adapter that delegates
///   every override to a method on the core, keeping the
///   Apple-specific boundary in one place.
///
/// The core has no `import NetworkExtension` dependency. Everything it
/// touches is either Rust-FFI (`Ram*Handle`), the `Network` framework
/// (which is testable), or its own protocols (`TcpFlowLike`,
/// `UdpFlowLike`, `NwConnectionLike`). The provider passes flow
/// metadata in via the `RamaTransparentProxyFlowMetaBridge` struct so
/// the core never has to access `NEFlowMetaData`.
final class TransparentProxyCore {
    // MARK: - Owned state

    private(set) var engine: RamaTransparentProxyEngineHandle?
    private let stateQueue = DispatchQueue(label: "rama.tproxy.core.state")
    private var tcpSessions: [ObjectIdentifier: RamaTcpSessionHandle] = [:]
    private var tcpContexts: [ObjectIdentifier: TcpFlowContext] = [:]
    private var udpSessions: [ObjectIdentifier: RamaUdpSessionHandle] = [:]
    private var udpContexts: [ObjectIdentifier: UdpFlowContext] = [:]

    /// Factory used to construct egress `NWConnection`s for intercepted
    /// flows. Production leaves this at the default (a real
    /// `NWConnection`); tests assign a mock factory so the per-flow
    /// state machine can be driven without a real socket.
    var nwConnectionFactory: NwConnectionFactoryFn = defaultNwConnectionFactory

    // MARK: - Engine lifecycle

    /// Hand a freshly-built engine to the core. The provider's
    /// `startProxy` override does the Apple-framework configuration
    /// dance (reading `protocolConfiguration`, building
    /// `NETransparentProxyNetworkSettings`, calling
    /// `setTunnelNetworkSettings`) and then publishes the resulting
    /// engine here. Per-flow handling becomes available only after
    /// this is called.
    func attachEngine(_ engine: RamaTransparentProxyEngineHandle) {
        self.engine = engine
    }

    /// Symmetric counterpart of `attachEngine` invoked from
    /// `stopProxy`. Stops the engine, clears all per-flow registrations.
    /// Idempotent — safe to call twice.
    func detachEngine(reason: Int32) {
        self.engine?.stop(reason: reason)
        self.engine = nil
        stateQueue.sync {
            self.tcpSessions.removeAll(keepingCapacity: false)
            self.tcpContexts.removeAll(keepingCapacity: false)
            self.udpSessions.removeAll(keepingCapacity: false)
            self.udpContexts.removeAll(keepingCapacity: false)
        }
    }

    // MARK: - App-message routing

    func handleAppMessage(_ messageData: Data) -> Data? {
        logDebug("handleAppMessage bytes=\(messageData.count)")
        guard let engine else {
            logDebug("handleAppMessage ignored because engine is unavailable")
            return nil
        }
        return engine.handleAppMessage(messageData)
    }

    // MARK: - Registration maps

    func registerTcpFlow(
        _ flowId: ObjectIdentifier,
        session: RamaTcpSessionHandle,
        context: TcpFlowContext
    ) {
        stateQueue.sync {
            self.tcpSessions[flowId] = session
            self.tcpContexts[flowId] = context
        }
    }

    func registerUdpFlow(
        _ flowId: ObjectIdentifier,
        session: RamaUdpSessionHandle,
        context: UdpFlowContext
    ) {
        stateQueue.sync {
            self.udpSessions[flowId] = session
            self.udpContexts[flowId] = context
        }
    }

    func removeTcpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync {
            self.tcpSessions.removeValue(forKey: flowId)
            self.tcpContexts.removeValue(forKey: flowId)
        }
    }

    func removeUdpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync {
            self.udpSessions.removeValue(forKey: flowId)
            self.udpContexts.removeValue(forKey: flowId)
        }
    }

    /// Count of currently-registered TCP flows. Test-only signal for
    /// leak / churn assertions.
    var tcpFlowCount: Int {
        stateQueue.sync { self.tcpContexts.count }
    }

    /// Count of currently-registered UDP flows. Test-only signal.
    var udpFlowCount: Int {
        stateQueue.sync { self.udpContexts.count }
    }

    // MARK: - Logging helpers

    // Identical to the helpers the provider used to expose; consolidated
    // here so closures that capture `self` (the core) from inside the
    // moved flow-handling methods still have the same surface available.

    func logTrace(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
            message: message
        )
    }

    func logDebug(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message: message
        )
    }

    func logInfo(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_INFO.rawValue),
            message: message
        )
    }

    func logError(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_ERROR.rawValue),
            message: message
        )
    }

    func logFlowMessage(_ message: FlowLogMessage) {
        switch message.level {
        case .trace: logTrace(message.text)
        case .debug: logDebug(message.text)
        case .error: logError(message.text)
        }
    }
}
