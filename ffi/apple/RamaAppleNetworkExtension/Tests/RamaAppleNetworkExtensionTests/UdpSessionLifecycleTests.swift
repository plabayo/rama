import Foundation
import RamaAppleNEFFI
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
        onServerDatagram: @escaping (RamaBytesView, RamaUdpPeerView) -> Void = { _, _ in },
        onClientReadDemand: @escaping (UInt64) -> Void = { _ in }
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
            onClientReadDemand: onClientReadDemand,
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

    #if DEBUG || RAMA_TESTING
        /// Rust holds its demand gate across the synchronous probe callback. Close
        /// must publish cancellation and release the Swift handle lock before it
        /// asks Rust to drain that gate, or a callback-triggered ACK forms the
        /// inverse lock order and deadlocks.
        func testCloseReleasesHandleLockBeforeDrainingInflightProbeDemand() {
            let engine = makeEngine()
            defer { engine.stop(reason: 0) }

            let sessionRef = TestValue<RamaUdpSessionHandle?>(nil)
            defer { sessionRef.set(nil) }
            let probeId = TestValue<UInt64?>(nil)
            let callbackAckCompleted = TestValue(false)
            let ackCallReturned = TestValue(false)

            let ackWorkerReady = DispatchSemaphore(value: 0)
            let startAck = DispatchSemaphore(value: 0)
            let demandEntered = DispatchSemaphore(value: 0)
            let callbackReturned = DispatchSemaphore(value: 0)
            let closeReachedSeam = DispatchSemaphore(value: 0)
            let continueClose = DispatchSemaphore(value: 0)
            let closeReturned = DispatchSemaphore(value: 0)
            let ackWork = DispatchGroup()
            ackWork.enter()

            // Prestart the ACK worker so the liveness assertion does not depend
            // on creating or scheduling a worker after the lock cycle is armed.
            let ackQueue = DispatchQueue(label: "rama.tests.udp-close-demand-ack")
            ackQueue.async {
                ackWorkerReady.signal()
                startAck.wait()
                if let session = sessionRef.get(), let probeId = probeId.get() {
                    session.completeClientRead(probeId: probeId)
                    ackCallReturned.set(true)
                }
                ackWork.leave()
            }

            // Rescue every deliberately parked participant if an earlier wiring
            // assertion fails. Extra semaphore signals are harmless.
            defer {
                continueClose.signal()
                startAck.signal()
            }

            let session = newInterceptedUdpSession(
                on: engine,
                onClientReadDemand: { callbackProbeId in
                    probeId.set(callbackProbeId)
                    demandEntered.signal()
                    // This is a liveness-only rescue for a bug-preserving build:
                    // after 30 seconds the callback returns, releases Rust's
                    // demand gate, and lets close plus the ACK worker unwind.
                    callbackAckCompleted.set(
                        ackWork.wait(timeout: .now() + 30) == .success)
                    callbackReturned.signal()
                })
            sessionRef.set(session)
            session.testSetAfterCancelledBeforeRustClose {
                closeReachedSeam.signal()
                continueClose.wait()
            }
            defer { session.testSetAfterCancelledBeforeRustClose(nil) }

            XCTAssertEqual(
                ackWorkerReady.wait(timeout: .now() + 30), .success,
                "prestarted ACK worker did not become ready")

            session.activate()
            XCTAssertEqual(
                demandEntered.wait(timeout: .now() + 30), .success,
                "real UDP demand callback was not entered")
            XCTAssertEqual(probeId.get(), 0, "initial ordinary demand must use probe ID zero")

            DispatchQueue.global(qos: .userInitiated).async {
                session.onClientClose()
                closeReturned.signal()
            }
            XCTAssertEqual(
                closeReachedSeam.wait(timeout: .now() + 30), .success,
                "close did not publish cancellation at the DEBUG seam")

            // At this instant the demand callback owns Rust's demand gate and
            // close has published `cancelled`. Releasing both workers forces the
            // exact former inversion without relying on sleeps or scheduler luck.
            continueClose.signal()
            startAck.signal()

            XCTAssertEqual(
                callbackReturned.wait(timeout: .now() + 35), .success,
                "probe demand callback did not leave after its liveness rescue")
            XCTAssertTrue(
                callbackAckCompleted.get(),
                "callback-triggered ACK could not acquire the Swift handle lock before close drained Rust's demand gate")
            XCTAssertEqual(
                closeReturned.wait(timeout: .now() + 30), .success,
                "UDP close did not return after the demand callback left")
            XCTAssertEqual(
                ackWork.wait(timeout: .now() + 30), .success,
                "ACK worker remained blocked after close returned")
            XCTAssertTrue(ackCallReturned.get(), "ACK worker did not call completeClientRead")
        }
    #endif

}
