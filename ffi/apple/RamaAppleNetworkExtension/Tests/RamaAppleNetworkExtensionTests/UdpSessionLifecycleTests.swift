import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Lifecycle regression tests for `RamaUdpSessionHandle`.
///
/// The Swift side no longer owns UDP egress (the Rust engine hands
/// the ingress flow to the service, which opens its own egress
/// socket); these tests cover the remaining Swift-side lifecycle
/// invariants:
///
/// 1. `onClientClose` idempotency — the close path can be triggered
///    from both the writer's error callback and the engine's terminal
///    callback; double-calling must be a safe no-op.
///
/// 2. Post-close guard paths — late `onClientDatagram` callbacks must
///    not crash after `onClientClose`.
///
/// 3. Activate → close tight loops — many short-lived flows must not
///    leak or crash.
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
        // to avoid a circular dependency with the system resolver.
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

    /// Activate then immediately close the session — covers the
    /// minimal lifecycle a real flow goes through when the originating
    /// app drops it before any datagram is exchanged.
    func testActivateThenImmediateOnClientCloseDoesNotCrash() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = newInterceptedUdpSession(on: engine)
        session.activate()
        session.onClientClose()
    }

    /// Tight-loop activate + close. Pins that N iterations of
    /// activate → close produce no crash and no per-flow leak.
    func testRapidActivateCloseChurnDoesNotCrash() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        for _ in 0..<64 {
            let session = newInterceptedUdpSession(on: engine)
            session.activate()
            session.onClientClose()
        }
    }

    /// 4 × 16 concurrent activate + close cycles. Concurrent churn
    /// under ASan flushes out any cancel-vs-callback race in the
    /// per-flow Swift-side lifecycle.
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
