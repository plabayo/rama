import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Cross-pump interaction tests for the egress side of a TCP session.
///
/// The linger-cancel watchdog and the EOF backstop in the read pump are
/// each tested in isolation by their own suites. The bugs that
/// actually shipped in 1.4.0, though, came from the *interaction*
/// between the two pumps and the NWConnection state machine — a
/// connection that lingered after FIN AND then peer-EOFed mid-linger,
/// for example, has to leave nothing leaked regardless of which
/// backstop fires first.
///
/// Each test below exercises one such interaction sequence end-to-end:
/// pumps constructed, the appropriate timeline driven, then the
/// invariants checked.
///
/// Invariant under test (in plain words): no matter the order in
/// which the natural close paths and the watchdogs converge,
/// `connection.cancel()` is called at least once and at most once in
/// excess of what `cancel()`'s idempotency contract allows (i.e. the
/// system never *fails* to cancel; it may cancel twice but never
/// zero times).
final class TcpEgressPumpInteractionTests: XCTestCase {

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

    private func makeQueue(_ tag: String) -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.pump-interaction.\(tag)", qos: .utility)
    }

    private func makeInterceptedSession(
        _ engine: RamaTransparentProxyEngineHandle
    ) -> RamaTcpSessionHandle {
        let meta = RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,
            remoteHost: "example.com",
            remotePort: 443,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
        let decision = engine.newTcpSession(
            meta: meta,
            onServerBytes: { _ in .accepted },
            onClientReadDemand: {},
            onServerClosed: {}
        )
        guard case .intercept(let s) = decision else {
            XCTFail("session intercept expected")
            preconditionFailure()
        }
        return s
    }

    private func waitForQueueDrain(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
        let exp = expectation(description: "queue drained")
        queue.async { exp.fulfill() }
        wait(for: [exp], timeout: timeout)
    }

    // MARK: - Drain + peer EOF interaction

    /// Local FIN sent, then peer EOF arrives before the linger
    /// watchdog fires. The expected end state: connection cancelled
    /// (by one of the backstops), pumps both off, no orphan timer
    /// outstanding. Pump cancel must invalidate both watchdogs.
    func testDrainThenPeerEofBeforeLinger() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue("drain-then-eof")
        let mock = MockNwConnection()
        mock.transition(to: .ready)

        let writePump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(600),
            onDrained: {}
        )
        let readPump = NwTcpConnectionReadPump(
            connection: mock,
            session: session,
            queue: queue,
            eofGraceDeadline: .milliseconds(600)
        )

        readPump.start()
        writePump.closeWhenDrained()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.sentChunks.count, 1, "FIN should have been sent")
        XCTAssertEqual(mock.cancelCount, 0, "no watchdog should have fired yet")

        // Simulate peer EOF on the read side. The read pump will fire
        // session.onEgressEof() and schedule the EOF backstop. Both
        // backstops (linger from the write side, EOF from the read
        // side) are now armed.
        mock.completePendingReceive(isComplete: true)
        waitForQueueDrain(queue)

        // External cancel (the path the per-flow context's terminal
        // teardown closures take) before any backstop fires. Must
        // invalidate both watchdogs cleanly.
        writePump.cancel()
        readPump.cancel()
        waitForQueueDrain(queue)

        Thread.sleep(forTimeInterval: 0.90)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 0,
            "external cancel before any backstop fires must invalidate both watchdogs"
        )
    }

    /// Local FIN sent, neither pump externally cancelled, linger
    /// watchdog and EOF backstop both armed but they race. At least
    /// one must fire and at most two cancels are expected (one per
    /// backstop — both call `cancel()` which is idempotent on a
    /// real NWConnection, but the mock counts every call).
    func testRacingBackstopsBothCancel() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue("racing-backstops")
        let mock = MockNwConnection()
        mock.transition(to: .ready)

        let writePump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            lingerCloseDeadline: .milliseconds(200),
            onDrained: {}
        )
        let readPump = NwTcpConnectionReadPump(
            connection: mock,
            session: session,
            queue: queue,
            eofGraceDeadline: .milliseconds(200)
        )

        readPump.start()
        writePump.closeWhenDrained()
        mock.completePendingReceive(isComplete: true)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0)

        // Both watchdogs are armed at ~200 ms. Wait long enough that
        // both have fired (1 second is well past both deadlines plus
        // any CI jitter).
        Thread.sleep(forTimeInterval: 1.0)
        waitForQueueDrain(queue)

        XCTAssertGreaterThanOrEqual(
            mock.cancelCount, 1,
            "at least one backstop must have force-cancelled the connection"
        )
        XCTAssertLessThanOrEqual(
            mock.cancelCount, 2,
            "no more than two cancels expected — one per armed backstop"
        )
    }

    // MARK: - Resource lifetime invariants

    /// Both pumps must deallocate within a short window once the
    /// connection is gone and external cancel has run. Catches
    /// retain-cycle regressions that would let a pump (and through
    /// it the session) survive teardown.
    func testPumpsDeallocateAfterCancel() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue("pump-dealloc")
        let mock = MockNwConnection()
        mock.transition(to: .ready)

        weak var weakWritePump: NwTcpConnectionWritePump?
        weak var weakReadPump: NwTcpConnectionReadPump?

        autoreleasepool {
            let writePump = NwTcpConnectionWritePump(
                connection: mock,
                queue: queue,
                lingerCloseDeadline: .milliseconds(50),
                onDrained: {}
            )
            let readPump = NwTcpConnectionReadPump(
                connection: mock,
                session: session,
                queue: queue,
                eofGraceDeadline: .milliseconds(50)
            )
            weakWritePump = writePump
            weakReadPump = readPump

            readPump.start()
            writePump.cancel()
            readPump.cancel()
            waitForQueueDrain(queue)
        }

        // Give GCD a chance to drop the work-item retains held by
        // any cancelled-but-not-yet-deallocated DispatchWorkItem.
        let deadline = Date().addingTimeInterval(2.0)
        while (weakWritePump != nil || weakReadPump != nil) && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }

        XCTAssertNil(weakWritePump, "write pump retained beyond cancel — likely a closure-capture cycle")
        XCTAssertNil(weakReadPump, "read pump retained beyond cancel — likely a closure-capture cycle")
    }

    /// When both backstops fire (no external cancel), the work items
    /// themselves clear the pump's `lingerWork` / `eofWork` slot so
    /// the pump itself can deallocate once external code drops its
    /// reference. Regression guard against the watchdog DispatchWork
    /// item keeping the pump alive forever via the captured
    /// `[weak self]` retain ladder.
    func testPumpsDeallocateAfterBackstopsFire() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue("pump-dealloc-after-backstop")
        let mock = MockNwConnection()
        mock.transition(to: .ready)

        weak var weakWritePump: NwTcpConnectionWritePump?
        weak var weakReadPump: NwTcpConnectionReadPump?

        autoreleasepool {
            let writePump = NwTcpConnectionWritePump(
                connection: mock,
                queue: queue,
                lingerCloseDeadline: .milliseconds(100),
                onDrained: {}
            )
            let readPump = NwTcpConnectionReadPump(
                connection: mock,
                session: session,
                queue: queue,
                eofGraceDeadline: .milliseconds(100)
            )
            weakWritePump = writePump
            weakReadPump = readPump

            readPump.start()
            writePump.closeWhenDrained()
            mock.completePendingReceive(isComplete: true)
            waitForQueueDrain(queue)

            // Wait past both deadlines so both watchdogs fire.
            Thread.sleep(forTimeInterval: 0.50)
            waitForQueueDrain(queue)
        }

        let deadline = Date().addingTimeInterval(2.0)
        while (weakWritePump != nil || weakReadPump != nil) && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }

        XCTAssertNil(weakWritePump, "write pump retained past watchdog fire — watchdog work item leak")
        XCTAssertNil(weakReadPump, "read pump retained past watchdog fire — watchdog work item leak")
    }
}
