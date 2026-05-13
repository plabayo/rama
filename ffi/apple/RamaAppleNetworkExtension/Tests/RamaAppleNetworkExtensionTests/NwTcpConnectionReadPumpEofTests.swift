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
            eofGraceDeadline: .milliseconds(60)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1, "pump should have issued one receive on start")

        // Upstream peer EOF.
        mock.completePendingReceive(isComplete: true)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0, "EOF backstop must not fire before its deadline")

        // Past the grace deadline + slack.
        Thread.sleep(forTimeInterval: 0.15)
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
            eofGraceDeadline: .milliseconds(60)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1)

        // Read error path — same backstop applies.
        let err = NWError.posix(.ECONNRESET)
        mock.completePendingReceive(error: err)
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0)

        Thread.sleep(forTimeInterval: 0.15)
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
            eofGraceDeadline: .milliseconds(200)
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

        Thread.sleep(forTimeInterval: 0.30)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 0,
            "external pump.cancel() must invalidate the EOF backstop"
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
            eofGraceDeadline: .milliseconds(60)
        )

        pump.start()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.pendingReceiveCount, 1)

        // Empty completion (nil data, isComplete = false, no error)
        // — the pump loops back to `scheduleReadLocked` without
        // touching the session, so this path tests "non-terminal
        // receive" without depending on the unactivated-session's
        // `onEgressBytes` return value.
        mock.completePendingReceive()
        waitForQueueDrain(queue)

        Thread.sleep(forTimeInterval: 0.15)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 0,
            "no backstop should fire while the connection is still being read normally"
        )
    }
}
