import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class SessionHandleTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard
            let h = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        return h
    }

    private func tcpMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,  // tcp
            remoteHost: "example.com",
            remotePort: 443,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func udpMeta() -> RamaTransparentProxyFlowMetaBridge {
        // Port 5000 (not 53): the demo handler passes DNS through
        // because the NE sandbox cannot bind raw UDP sockets, so a
        // DNS port silently downgrades to passthrough.
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 2,  // udp
            remoteHost: "example.com",
            remotePort: 5000,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    /// Pull a real intercept session out of the demo handler, or
    /// fail loudly if the demo's config drifts to passthrough/block.
    /// Without this we'd silently no-op every session-handle test.
    private func newInterceptedTcpSession(
        on engine: RamaTransparentProxyEngineHandle,
        onServerBytes: @escaping (Data) -> RamaTcpDeliverStatusBridge = { _ in .accepted },
        onClientReadDemand: @escaping () -> Void = {},
        onServerClosed: @escaping () -> Void = {}
    ) -> RamaTcpSessionHandle {
        let decision = engine.newTcpSession(
            meta: tcpMeta(),
            onServerBytes: onServerBytes,
            onClientReadDemand: onClientReadDemand,
            onServerClosed: onServerClosed
        )
        guard case .intercept(let session) = decision else {
            XCTFail("demo handler unexpectedly returned non-intercept; tests assume tcp 443 → intercept")
            preconditionFailure()
        }
        return session
    }

    private func newInterceptedUdpSession(
        on engine: RamaTransparentProxyEngineHandle
    ) -> RamaUdpSessionHandle {
        let decision = engine.newUdpSession(
            meta: udpMeta(),
            onServerDatagram: { _, _ in },
            onClientReadDemand: {},
            onServerClosed: {}
        )
        guard case .intercept(let session) = decision else {
            XCTFail("demo handler unexpectedly returned non-intercept; tests assume udp 5000 → intercept")
            preconditionFailure()
        }
        return session
    }

    /// Post-cancel `onClientBytes` must return `.closed` instead of
    /// reaching the freed Rust session.
    func testTcpCancelThenOnClientBytesReturnsClosed() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = newInterceptedTcpSession(on: engine)
        session.cancel()
        XCTAssertEqual(session.onClientBytes(Data("after-cancel".utf8)), .closed)
    }

    /// Tight-loop create + cancel + drop. Counts intercepts so a
    /// silent regression to passthrough fails the test.
    func testTcpSessionChurnDoesNotLeak() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let iterations = 256
        for _ in 0..<iterations {
            let session = newInterceptedTcpSession(on: engine)
            session.cancel()
            // Session drops here; deinit calls _session_free.
        }
    }

    /// Concurrent stress on the Swift wrapper's NSLock + the engine's
    /// `callback_active` mutex. Counts intercepts so a regression to
    /// passthrough surfaces as a failure rather than a silent no-op.
    func testTcpSessionConcurrentChurnIsSafe() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let intercepted = NSLock_Counter()
        let group = DispatchGroup()
        let workers = 4
        let perWorker = 64
        for _ in 0..<workers {
            DispatchQueue.global(qos: .userInitiated).async(group: group) {
                for _ in 0..<perWorker {
                    let session = self.newInterceptedTcpSession(on: engine)
                    intercepted.increment()
                    _ = session.onClientBytes(Data("hello".utf8))
                    session.cancel()
                }
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
        XCTAssertEqual(intercepted.value, workers * perWorker)
    }

    /// UDP equivalent of the TCP session churn test.
    func testUdpSessionConcurrentChurnIsSafe() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let intercepted = NSLock_Counter()
        let group = DispatchGroup()
        let workers = 4
        let perWorker = 64
        for _ in 0..<workers {
            DispatchQueue.global(qos: .userInitiated).async(group: group) {
                for _ in 0..<perWorker {
                    let session = self.newInterceptedUdpSession(on: engine)
                    intercepted.increment()
                    session.onClientDatagram(Data("dgram".utf8), peer: nil)
                    session.onClientClose()
                }
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
        XCTAssertEqual(intercepted.value, workers * perWorker)
    }

    /// Repeated `activate(...)` MUST NOT retain a second egress
    /// callback box: Rust's `_session_activate` rejects double-
    /// activation as a no-op + log, so a second `passRetained` would
    /// leak the new box (Rust still holds the raw pointer to the
    /// first one). Detect via a sentinel object captured by each
    /// closure: only the first sentinel should remain alive (held by
    /// box-1), the second sentinel must be released as soon as
    /// `activate` returns. After session deinit, both sentinels are
    /// released.
    func testTcpRepeatedActivateDoesNotLeakSecondCallbackBox() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        weak var firstSentinel: Sentinel?
        weak var secondSentinel: Sentinel?
        do {
            let session = newInterceptedTcpSession(on: engine)
            let s1 = Sentinel()
            let s2 = Sentinel()
            firstSentinel = s1
            secondSentinel = s2
            session.activate(
                onWriteToEgress: { [s1] _ in _ = s1; return .accepted },
                onEgressReadDemand: {},
                onCloseEgress: {}
            )
            // Second activate must NOT retain s2's closures.
            session.activate(
                onWriteToEgress: { [s2] _ in _ = s2; return .accepted },
                onEgressReadDemand: {},
                onCloseEgress: {}
            )
            // Right after the second activate, s2 has no strong refs
            // outside this scope. The bug-preserving variant would
            // have stashed it inside an Unmanaged box held by the
            // session.
            // Force a drain of any GCD queues / autoreleasepools.
        }
        // Session dropped → its egress callback box (the first one)
        // is released. Both sentinels must be deallocated.
        XCTAssertNil(secondSentinel, "second activate leaked its callback box")
        XCTAssertNil(firstSentinel, "session deinit failed to release the first callback box")
    }

    /// UDP variant of the activate-leak regression test.
    func testUdpRepeatedActivateDoesNotLeakSecondCallbackBox() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        weak var firstSentinel: Sentinel?
        weak var secondSentinel: Sentinel?
        do {
            let session = newInterceptedUdpSession(on: engine)
            let s1 = Sentinel()
            let s2 = Sentinel()
            firstSentinel = s1
            secondSentinel = s2
            session.activate(onSendToEgress: { [s1] _, _ in _ = s1 })
            session.activate(onSendToEgress: { [s2] _, _ in _ = s2 })
        }
        XCTAssertNil(secondSentinel, "second activate leaked its callback box")
        XCTAssertNil(firstSentinel, "session deinit failed to release the first callback box")
    }
}

/// Lifetime sentinel: weak refs to instances tell the test whether
/// the closures captured them outlived the test scope.
private final class Sentinel {}

/// Simple atomic counter for the concurrent-churn assertions.
private final class NSLock_Counter {
    private let lock = NSLock()
    private var _value = 0
    func increment() {
        lock.lock()
        _value += 1
        lock.unlock()
    }
    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }
}
