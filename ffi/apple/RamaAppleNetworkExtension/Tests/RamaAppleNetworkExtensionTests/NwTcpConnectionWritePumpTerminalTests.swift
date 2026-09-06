import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Local FIN preserves the response half; two-sided terminal releases the connection.
final class NwTcpConnectionWritePumpTerminalTests: XCTestCase {

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.tcp.write-pump.terminal", qos: .utility)
    }

    private func waitForQueueDrain(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
        let exp = expectation(description: "queue drained")
        queue.async { exp.fulfill() }
        wait(for: [exp], timeout: timeout)
    }

    func testTerminalReleaseCancelsAndRefundsImmediately() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let core = TransparentProxyCore()
        let pump = NwTcpConnectionWritePump(connection: mock, queue: queue, onDrained: {})
        let drained = expectation(description: "FIN completed")
        pump.closeWhenDrained { drained.fulfill() }
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0)
        XCTAssertTrue(mock.completePendingSend())
        wait(for: [drained], timeout: 1)
        queue.sync {
            pump.installTerminalResourceRelease(core.beginResourceRetirement())
            pump.releaseTerminalConnection()
            XCTAssertEqual(mock.cancelCount, 1)
            XCTAssertEqual(core.testRetiringResourceCount, 0)
            pump.releaseTerminalConnection()
        }
        XCTAssertEqual(mock.cancelCount, 1)
    }

    func testDrainSendsFinWithoutStartingResponseDeadline() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: {}
        )

        pump.closeWhenDrained()
        waitForQueueDrain(queue)

        // Drain with no pending bytes emits exactly one FIN. A successful
        // local half-close must not start whole-connection cancellation.
        XCTAssertEqual(mock.sentChunks.count, 1, "expected exactly one send (the FIN)")
        XCTAssertNil(mock.sentChunks.first?.content, "FIN send should have nil content")
        XCTAssertEqual(mock.sentChunks.first?.isComplete, true, "FIN send should have isComplete=true")
        XCTAssertEqual(
            mock.cancelCount, 0,
            "a quiet response half must survive beyond the terminal grace")
    }

    func testTerminalWriteErrorDuringDrainFiresCallbackAndForceCancels() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let drained = expectation(description: "closeWhenDrained callback fired")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: {}
        )

        // Queue a chunk so the drain has an in-flight send to fail.
        // With no pending bytes, `closeWhenDrained` would send the FIN
        // immediately and never reach the terminate path.
        pump.enqueue(Data([0x01, 0x02, 0x03]))
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.sentChunks.count, 1, "the data chunk was sent")
        XCTAssertEqual(
            mock.pendingSendCount, 1, "its send completion is still outstanding")

        pump.closeWhenDrained { drained.fulfill() }
        waitForQueueDrain(queue)
        // Still draining — the in-flight send hasn't completed, so no
        // FIN and no terminal yet.
        XCTAssertEqual(mock.cancelCount, 0)

        // Fail the in-flight send with a NON-transient error
        // (ECONNRESET is not in the {ENOBUFS, EAGAIN} retry set) → the
        // core terminates instead of finishing the drain.
        mock.completePendingSend(error: .posix(.ECONNRESET))

        wait(for: [drained], timeout: 2.0)
        waitForQueueDrain(queue)
        XCTAssertEqual(
            mock.cancelCount, 1,
            "terminal write error must force-cancel the connection so it can't leak"
        )
        // No FIN was ever sent — the drain terminated on error before
        // the FIN send (a FIN is a send with nil content).
        XCTAssertNil(
            mock.sentChunks.first(where: { $0.content == nil }),
            "no FIN on the terminal-error path"
        )
    }

    func testCloseWhenDrainedOnAlreadyClosedCoreForceCancels() {
        let mock = MockNwConnection()
        mock.transition(to: .ready)
        let queue = makeQueue()
        let drained = expectation(description: "closeWhenDrained callback fired")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: {}
        )

        // Close the core WITHOUT cancelling the connection — exactly what
        // `pump.cancel()` does (the connection cancel is normally the
        // teardown caller's responsibility, but promoted teardown
        // delegates it to this pump).
        pump.cancel()
        waitForQueueDrain(queue)
        XCTAssertEqual(
            mock.cancelCount, 0,
            "precondition: pump.cancel() alone does not cancel the connection"
        )

        // The graceful close now arrives on an already-closed core → the
        // `isClosed()` fast path. It must force-cancel the connection AND
        // fire the callback.
        pump.closeWhenDrained { drained.fulfill() }
        wait(for: [drained], timeout: 2.0)
        waitForQueueDrain(queue)

        XCTAssertEqual(
            mock.cancelCount, 1,
            "closeWhenDrained on an already-closed core must force-cancel the connection so the promoted-teardown path can't leak it"
        )
        XCTAssertEqual(
            mock.sentChunks.count, 0,
            "no FIN is possible on an already-closed core"
        )
    }

    func testDrainOnNonReadyConnectionForceCancelsInsteadOfLeaking() {
        let mock = MockNwConnection()
        mock.transition(to: .preparing)
        let queue = makeQueue()
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: {}
        )

        pump.closeWhenDrained()
        waitForQueueDrain(queue)

        // No FIN can be sent on a non-`.ready` connection...
        XCTAssertEqual(
            mock.sentChunks.count, 0,
            "FIN must not be sent when the connection is not in .ready state"
        )
        // ...but the connection MUST be force-cancelled right away —
        // not left for a watchdog this branch never arms. The promoted
        // terminal path delegates connection cancel to this pump, so
        // bailing without cancelling leaks the NWConnection + its NECP
        // entry. Immediate, not deadline-gated.
        XCTAssertEqual(
            mock.cancelCount, 1,
            "non-ready drain must force-cancel the connection so it can't leak"
        )
    }

    func testDrainWhileWaitingDefersFinUntilReadyRecovery() {
        let mock = MockNwConnection()
        mock.transition(to: .waiting(.posix(.ENETDOWN)))
        let queue = makeQueue()
        let drained = expectation(description: "FIN completion drains")
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: {}
        )

        pump.closeWhenDrained { drained.fulfill() }
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0)
        XCTAssertEqual(mock.sentChunks.count, 0)

        mock.transition(to: .ready)
        pump.connectionBecameReady()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 0)
        XCTAssertEqual(mock.sentChunks.count, 1)
        XCTAssertTrue(
            mock.sentChunks[0].contentContext
                === NWConnection.ContentContext.finalMessage)
        XCTAssertTrue(mock.completePendingSend(error: nil))
        wait(for: [drained], timeout: 1.0)
    }

    func testRetirementInstalledAfterEarlierForceCancelReleasesImmediately() {
        let core = TransparentProxyCore()
        let mock = MockNwConnection()
        mock.transition(to: .preparing)
        let queue = makeQueue()
        let pump = NwTcpConnectionWritePump(
            connection: mock,
            queue: queue,
            onDrained: {})

        pump.closeWhenDrained()
        waitForQueueDrain(queue)
        XCTAssertEqual(mock.cancelCount, 1)

        let release = core.beginResourceRetirement()
        XCTAssertEqual(core.testRetiringResourceCount, 1)
        queue.sync { pump.installTerminalResourceRelease(release) }
        XCTAssertEqual(
            core.testRetiringResourceCount, 0,
            "an already-issued cancel must not retain new retirement accounting")
    }

}
