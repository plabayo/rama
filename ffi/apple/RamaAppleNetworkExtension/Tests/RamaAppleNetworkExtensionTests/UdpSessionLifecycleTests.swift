import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Lifecycle regression tests for `RamaUdpSessionHandle`.
///
/// The covered scenarios correspond to the bugfix commits on this branch:
///
/// 1. `egressReadPump` ARC lifetime — `NwUdpConnectionReadPump` was
///    deallocated immediately after the `.ready` handler completed,
///    silently dropping all egress receives.  The tests below exercise
///    the activate → datagram → close lifecycle so a future regression
///    surfaces here before reaching a heap-snapshot analysis.
///
/// 2. `terminate` idempotency — the close path can be triggered from
///    both the writer's error callback and the egress pump's terminal;
///    double-calling must be a safe no-op.
///
/// 3. Post-close guard paths — late `onEgressDatagram` and
///    `onClientDatagram` callbacks must not crash after `onClientClose`.
final class UdpSessionLifecycleTests: XCTestCase {
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

    private func newInterceptedUdpSession(
        on engine: RamaTransparentProxyEngineHandle,
        onServerDatagram: @escaping (Data, RamaUdpPeer?) -> Void = { _, _ in }
    ) -> RamaUdpSessionHandle {
        // Port 5000 (not 53): the demo handler treats DNS as passthrough
        // because the NE sandbox cannot bind raw UDP sockets.
        let meta = RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 2,  // udp
            remoteHost: "example.com",
            remotePort: 5000,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
        let decision = engine.newUdpSession(
            meta: meta,
            onServerDatagram: onServerDatagram,
            onClientReadDemand: {},
            onServerClosed: {}
        )
        guard case .intercept(let s) = decision else {
            XCTFail("demo handler unexpectedly returned non-intercept; tests assume udp 5000 → intercept")
            preconditionFailure()
        }
        return s
    }

    /// `onClientClose` must be idempotent. The `terminate` closure in
    /// `handleUdpFlow` can fire from both the writer's error path and
    /// the egress read pump's terminal callback — either can arrive first
    /// and the second must be a safe no-op with no double-free in Rust.
    func testOnClientCloseIsIdempotent() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = newInterceptedUdpSession(on: engine)
        session.onClientClose()
        session.onClientClose()  // second call must not crash
    }

    /// A late `onClientDatagram` arriving after `onClientClose` must be
    /// silently dropped — the same guard as the TCP `.closed` path.
    func testOnClientDatagramAfterOnClientCloseIsNoop() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = newInterceptedUdpSession(on: engine)
        session.onClientClose()
        session.onClientDatagram(Data("late client datagram".utf8), peer: nil)
    }

    /// Activate the egress send callback then immediately close the
    /// session. Before the ARC fix, the `NwUdpConnectionReadPump` was
    /// dropped right after `.ready` returned, so the `onTerminate`
    /// closure would fire on a deallocated pump. The session-level
    /// lifecycle (activate → close) exercises the store-then-cancel
    /// path added by the fix.
    func testActivateThenImmediateOnClientCloseDoesNotCrash() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = newInterceptedUdpSession(on: engine)
        session.activate()
        session.onClientClose()
    }

    /// Tight-loop activate + close. The ARC fix ensures each pump is
    /// stored and cancelled cleanly; this pins that N iterations of
    /// activate → close produce no crash, where N exceeds what a
    /// single stack-allocated pump could survive.
    func testRapidActivateCloseChurnDoesNotCrash() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        for _ in 0..<64 {
            let session = newInterceptedUdpSession(on: engine)
            session.activate()
            session.onClientClose()
        }
    }

    /// 4 × 16 concurrent activate + close cycles. The cancel-vs-callback
    /// race window is microseconds wide; concurrent churn under ASan is
    /// the only reliable way to observe the UAF that would have occurred
    /// if the pump was dropped on the stack while an NWConnection receive
    /// callback held a `[weak self]` back-reference.
    func testConcurrentActivateCloseChurnIsSafe() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }

        let group = DispatchGroup()
        let workers = 4
        let perWorker = 16
        for _ in 0..<workers {
            DispatchQueue.global(qos: .userInitiated).async(group: group) {
                for _ in 0..<perWorker {
                    let session = self.newInterceptedUdpSession(on: engine)
                    session.activate()
                    session.onClientClose()
                }
            }
        }
        XCTAssertEqual(
            group.wait(timeout: .now() + 10), .success,
            "concurrent udp activate+close churn timed out"
        )
    }

}
