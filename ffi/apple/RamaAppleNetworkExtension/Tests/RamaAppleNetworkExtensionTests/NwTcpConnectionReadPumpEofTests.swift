import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for the EOF / read-error backstop in `NwTcpConnectionReadPump`.
///
/// Under normal operation, the clean teardown path on upstream EOF is:
///   1. `connection.receive` completes with `isComplete = true`
///   2. pump fires `session.onEgressEof()`
///   3. Rust bridge exits and fires `on_server_closed`
///   4. Swift routes through `onServerClosed` → `closeWhenDrained` →
///      `connection.cancel()`
///
/// Step 4 depends on the originating app being able to drain its
/// `NEAppProxyFlow.writeData` queue. When the app stops reading (process
/// exit, browser tab closed, NEAppProxyFlow already cancelled by the
/// kernel for other reasons) the drain never completes and the clean
/// path stalls indefinitely. The backstop schedules an unconditional
/// `connection.cancel()` after `eofGraceDeadline` so the NWConnection
/// registration is released in bounded time regardless.
final class NwTcpConnectionReadPumpEofTests: XCTestCase {

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

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.tcp.read-pump.eof", qos: .utility)
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
            XCTFail("demo handler unexpectedly returned non-intercept")
            preconditionFailure()
        }
        return s
    }

    /// Drains the test's serial queue. The pump schedules its
    /// EOF-cancel work item asynchronously; awaiting a no-op block on
    /// the same queue forces the test to observe the post-EOF state.
    private func waitForQueueDrain(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
        let exp = expectation(description: "queue drained")
        queue.async { exp.fulfill() }
        wait(for: [exp], timeout: timeout)
    }

    func testIsCompleteSchedulesCancelWithinGrace() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue()
        let mock = MockNwConnection()
        let pump = NwTcpConnectionReadPump(
            connection: mock,
            session: session,
            queue: queue,
            eofGraceDeadline: .milliseconds(300)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1, "pump should have issued one receive on start")

        // Upstream peer EOF.
        mock.completePendingReceive(isComplete: true)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0, "EOF backstop must not fire before its deadline")

        // Past the grace deadline + slack.
        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "EOF backstop should have force-cancelled the connection exactly once"
        )
    }

    func testReadErrorSchedulesCancelWithinGrace() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue()
        let mock = MockNwConnection()
        let pump = NwTcpConnectionReadPump(
            connection: mock,
            session: session,
            queue: queue,
            eofGraceDeadline: .milliseconds(300)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1)

        // Read error path — same backstop applies.
        let err = NWError.posix(.ECONNRESET)
        mock.completePendingReceive(isComplete: false, error: err)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0)

        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "EOF backstop should fire on the read-error branch as well"
        )
    }

    func testExternalPumpCancelInvalidatesEofBackstop() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue()
        let mock = MockNwConnection()
        let pump = NwTcpConnectionReadPump(
            connection: mock,
            session: session,
            queue: queue,
            eofGraceDeadline: .milliseconds(600)
        )

        pump.start()
        waitForQueueDrain(queue)
        mock.completePendingReceive(isComplete: true)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0)

        // The clean teardown path reaches pump.cancel() before the
        // backstop deadline. The backstop must NOT then fire — it
        // would call cancel() on a connection some other path has
        // already taken responsibility for, which is harmless on the
        // wire but masks accounting bugs in tests.
        pump.cancel()
        waitForQueueDrain(queue)

        Thread.sleep(forTimeInterval: 0.90)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 0,
            "external pump.cancel() must invalidate the EOF backstop"
        )
    }

    /// Regression: the EOF backstop must fire even after the pump
    /// itself is deallocated. A promote teardown drops the per-flow
    /// ctx — and the read pump along with it — once the cutover
    /// completes; without a strong capture of the connection, the
    /// backstop's `[weak self]` no-ops and the NWConnection
    /// registration leaks until the OS reaps it.
    ///
    /// Mirrors `testLingerCancelsConnectionEvenAfterPumpDeallocated`
    /// in the writer-pump linger suite.
    func testCancelStillFiresAfterPumpDeallocated() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue()
        let mock = MockNwConnection()

        // Use a generous deadline so the "backstop not yet fired"
        // pre-assertion has comfortable slack even on a heavily
        // contended CI runner: `waitForQueueDrain` itself goes
        // through a serial queue and an `XCTestExpectation`, and a
        // 150 ms window proved tight enough to be flaky there.
        // Siblings in this file already use ≥300 ms for the same
        // reason.
        do {
            let pump = NwTcpConnectionReadPump(
                connection: mock,
                session: session,
                queue: queue,
                eofGraceDeadline: .milliseconds(500)
            )
            pump.start()
            waitForQueueDrain(queue)
            XCTAssertEqual(mock.pendingReceiveCount, 1)

            mock.completePendingReceive(isComplete: true)
            waitForQueueDrain(queue)
            XCTAssertEqual(mock.cancelCount, 0, "backstop not yet fired")
            // `pump` goes out of scope → deallocated.
        }

        // Past the grace deadline + slack.
        Thread.sleep(forTimeInterval: 0.70)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "EOF backstop must cancel the connection even after the pump is deallocated"
        )
    }

    /// Regression (audit "Medium": egress `.closed` asymmetry). When the
    /// Rust egress consumer is dropped, `session.onEgressBytes(_:)` returns
    /// `.closed`. The pump must treat this as a terminal reason and arm the
    /// same bounded-release backstop as EOF/error — otherwise the pump
    /// silently stops reading while the NWConnection (and its NECP
    /// registration) lingers until the OS reaps it. The sibling
    /// `TcpClientReadPump` already routes `.closed` through `terminate(...)`;
    /// this test pins the symmetric behaviour here.
    ///
    /// `session.cancel()` flips the handle's `cancelled` flag, after which
    /// `onEgressBytes(_:)` returns `.closed` deterministically without
    /// depending on Rust bridge state.
    func testEgressClosedSchedulesCancelWithinGrace() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue()
        let mock = MockNwConnection()
        let pump = NwTcpConnectionReadPump(
            connection: mock,
            session: session,
            queue: queue,
            eofGraceDeadline: .milliseconds(300)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1)

        // Rust dropped the egress consumer: subsequent `onEgressBytes`
        // returns `.closed`.
        session.cancel()

        // A receive carrying bytes now routes through the data branch,
        // where `onEgressBytes` returns `.closed`.
        mock.completePendingReceive(data: Data([0x1, 0x2, 0x3]), isComplete: false)
        waitForQueueDrain(queue)
        XCTAssertEqual(
            mock.cancelCount, 0,
            "bounded release must not fire before its deadline"
        )
        XCTAssertEqual(
            mock.pendingReceiveCount, 0,
            "pump must stop reading once the egress consumer is closed"
        )

        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "egress `.closed` must arm the same bounded release as EOF/error"
        )
    }

    /// Regression (same audit finding, session-gone branch). If the per-flow
    /// session is torn down while a receive is in flight, the pump's `weak`
    /// session reference nils out. The data branch's `guard let session`
    /// bail must also drive the bounded release — re-issuing a receive would
    /// keep draining bytes that have nowhere to go, and doing nothing would
    /// leak the NWConnection.
    func testSessionGoneMidReceiveSchedulesCancelWithinGrace() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        var session: RamaTcpSessionHandle? = makeInterceptedSession(engine)
        let queue = makeQueue()
        let mock = MockNwConnection()
        let pump = NwTcpConnectionReadPump(
            connection: mock,
            session: session!,
            queue: queue,
            eofGraceDeadline: .milliseconds(300)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1)

        // Drop the only strong reference: the pump holds the session
        // `weak`, so it nils out here.
        session = nil

        // A receive carrying bytes now hits the `guard let session` bail.
        mock.completePendingReceive(data: Data([0x1, 0x2, 0x3]), isComplete: false)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0, "bounded release must not fire before its deadline")
        XCTAssertEqual(
            mock.pendingReceiveCount, 0,
            "pump must stop reading once the session is gone"
        )

        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "a session that vanishes mid-receive must arm the bounded release"
        )
    }

    func testNonTerminalReceiveDoesNotScheduleBackstop() {
        let engine = makeEngine()
        defer { engine.stop(reason: 0) }
        let session = makeInterceptedSession(engine)
        let queue = makeQueue()
        let mock = MockNwConnection()
        let pump = NwTcpConnectionReadPump(
            connection: mock,
            session: session,
            queue: queue,
            eofGraceDeadline: .milliseconds(300)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1)

        // Empty completion (nil data, isComplete = false, no error)
        // — the pump loops back to `scheduleReadLocked` without
        // touching the session, so this path tests "non-terminal
        // receive" without depending on the unactivated-session's
        // `onEgressBytes` return value.
        mock.completePendingReceive(isComplete: false)
        waitForQueueDrain(queue)

        Thread.sleep(forTimeInterval: 0.45)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 0,
            "no backstop should fire while the connection is still being read normally"
        )
    }
}
