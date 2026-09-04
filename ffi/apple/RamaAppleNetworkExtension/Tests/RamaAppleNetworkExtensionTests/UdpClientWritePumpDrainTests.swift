import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Drives `UdpClientWritePump`'s `flow.writeDatagrams` completion path —
/// the success-drain (write done → flush the next queued reply) and the
/// write-error terminate (close + onTerminalError) — plus the drop-on-full
/// lossy bound. `MockUdpFlow.completePendingWrite` exists but had no callers,
/// so these branches were entirely uncovered.
final class UdpClientWritePumpDrainTests: XCTestCase {

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.udp.write.drain.test", qos: .utility)
    }
    private func ep(_ port: UInt16 = 5353) -> NWHostEndpoint {
        NWHostEndpoint(hostname: "127.0.0.1", port: "\(port)")
    }
    private func tag(_ n: Int) -> Data { Data([UInt8(n >> 8), UInt8(n & 0xff)]) }
    private func tagOf(_ d: Data) -> Int { Int(d[0]) << 8 | Int(d[1]) }

    // MARK: - success drain

    /// `writeDatagrams` is caller-serial: the pump holds one batch in flight
    /// and queues the rest. When the in-flight write completes successfully,
    /// the pump must flush the NEXT queued reply (phase .writing → .idle →
    /// flush). The completion success path had zero coverage.
    func testSuccessfulWriteDrainsNextQueued() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        let pump = UdpClientWritePump(flow: flow, queue: queue, logger: { _ in }, onTerminalError: { _ in })
        pump.markOpened()

        pump.enqueue(tag(1), sentBy: ep())
        pump.enqueue(tag(2), sentBy: ep())
        queue.sync {}
        XCTAssertEqual(flow.writtenBatches.count, 1, "only the first write is in flight")
        XCTAssertEqual(flow.writtenBatches.first.map { tagOf($0.datagrams[0]) }, 1)

        XCTAssertTrue(flow.completePendingWrite(error: nil), "complete the in-flight write")
        queue.sync {}
        XCTAssertEqual(flow.writtenBatches.count, 1, "second reply now flushed after the first drained")
        XCTAssertEqual(flow.writtenBatches.first.map { tagOf($0.datagrams[0]) }, 2)
    }

    // MARK: - write-error terminate

    /// A non-nil `writeDatagrams` completion error must terminate the pump:
    /// close it, clear the queue, and fire `onTerminalError`. Further
    /// enqueues are then dropped (no new writes).
    func testWriteErrorTerminatesPumpAndFiresCallback() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        var terminalError: Error?
        let pump = UdpClientWritePump(
            flow: flow, queue: queue, logger: { _ in }, onTerminalError: { terminalError = $0 })
        pump.markOpened()

        pump.enqueue(tag(1), sentBy: ep())
        pump.enqueue(tag(2), sentBy: ep())  // queued behind the in-flight one
        queue.sync {}

        XCTAssertTrue(
            flow.completePendingWrite(error: NSError(domain: NSPOSIXErrorDomain, code: Int(EPIPE))))
        queue.sync {}

        XCTAssertEqual(
            (terminalError as NSError?)?.code, Int(EPIPE), "write error must fire onTerminalError")

        // Pump is closed: the queued reply was dropped and further enqueues
        // produce no writes.
        pump.enqueue(tag(3), sentBy: ep())
        queue.sync {}
        XCTAssertTrue(
            flow.writtenBatches.isEmpty, "a terminated pump must not issue further writes")
    }

    func testCloseWhileWritingIgnoresLateCompletion() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        var terminalCount = 0
        let pump = UdpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in terminalCount += 1 })
        pump.markOpened()
        pump.enqueue(tag(1), sentBy: ep())
        pump.enqueue(tag(2), sentBy: ep())
        queue.sync {}

        pump.close()
        queue.sync {}
        XCTAssertTrue(flow.completePendingWrite(error: nil))
        queue.sync {}

        pump.enqueue(tag(3), sentBy: ep())
        queue.sync {}
        XCTAssertTrue(flow.writtenBatches.isEmpty)
        XCTAssertEqual(terminalCount, 0)
    }

    func testOnQueueClosePrecedesAlreadyQueuedWriteCompletion() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        let pump = UdpClientWritePump(
            flow: flow, queue: queue, logger: { _ in }, onTerminalError: { _ in })
        pump.markOpened()
        pump.enqueue(tag(1), sentBy: ep())
        pump.enqueue(tag(2), sentBy: ep())
        queue.sync {}

        let blockerStarted = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerStarted.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 1), .success)

        // Termination is ahead of the in-flight completion on the same queue.
        // Closing the pump must be immediate in that block; otherwise the
        // completion flushes tag 2 after the kernel write half is closed.
        queue.async {
            pump.close()
            flow.closeWriteWithError(nil)
        }
        XCTAssertTrue(flow.completePendingWrite(error: nil))
        releaseBlocker.signal()
        queue.sync {}

        XCTAssertTrue(flow.writtenBatches.isEmpty)
        XCTAssertEqual(flow.writeAfterCloseCount, 0)
    }

    // MARK: - drop-on-full lossy bound

    /// UDP is lossy: once `pending.count >= udpWritePumpMaxPending` (256) the
    /// pump drops the NEWEST datagram rather than buffer without bound. With
    /// one batch in flight + 256 queued, enqueueing past that drops the
    /// latest arrivals; the older 257 (1 in flight + 256 queued) are retained
    /// in FIFO order.
    func testDropsNewestWhenQueueFull() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        var activityCount = 0
        let pump = UdpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in },
            onActivity: { activityCount += 1 }
        )
        pump.markOpened()

        // 260 attributed datagrams; never complete the in-flight write so the
        // queue backs up to the cap. Retained = 1 in-flight + 256 queued =
        // tags 0...256; tags 257,258,259 are dropped (newest-first).
        let total = 260
        for n in 0..<total { pump.enqueue(tag(n), sentBy: ep()) }
        queue.sync {}
        XCTAssertEqual(
            activityCount, total,
            "received datagrams remain activity even when the lossy queue drops them"
        )

        var drained: [Int] = []
        while let batch = flow.writtenBatches.first {
            drained.append(tagOf(batch.datagrams[0]))
            XCTAssertTrue(flow.completePendingWrite(error: nil))
            queue.sync {}
        }

        XCTAssertEqual(
            drained, Array(0...256),
            "the oldest 257 datagrams are retained in FIFO order; the newest are dropped on overflow")
    }

    func testDispatchBacklogIsBoundedBeforeFlowQueueRuns() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        var activityCount = 0
        let pump = UdpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in },
            onActivity: { activityCount += 1 }
        )
        pump.markOpened()
        pump.enqueue(tag(0), sentBy: ep())
        queue.sync {}

        let blockerStarted = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerStarted.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 1), .success)

        for n in 1...10_000 { pump.enqueue(tag(n), sentBy: ep()) }
        let saturated = pump.testAdmissionSnapshot
        XCTAssertEqual(saturated.waiting, udpWritePumpMaxPending)
        XCTAssertEqual(saturated.acceptedDispatches, 257)
        XCTAssertEqual(saturated.droppedFull, 9_744)
        XCTAssertEqual(saturated.fullLogCount, 1)
        XCTAssertEqual(activityCount, 10_001)

        pump.close()
        for n in 10_001...10_100 { pump.enqueue(tag(n), sentBy: ep()) }
        XCTAssertEqual(pump.testAdmissionSnapshot.acceptedDispatches, 257)
        XCTAssertEqual(activityCount, 10_001)

        releaseBlocker.signal()
        queue.sync {}
        let closed = pump.testAdmissionSnapshot
        XCTAssertTrue(closed.closed)
        XCTAssertEqual(closed.waiting, 0)
    }

    func testInlineEndpointUpdatesAreCapturedInOrder() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        let pump = UdpClientWritePump(
            flow: flow, queue: queue, logger: { _ in }, onTerminalError: { _ in })
        pump.markOpened()
        queue.sync {}

        let first = ep(5353)
        let second = ep(5354)
        queue.sync {
            pump.setSentByEndpoint(first)
            XCTAssertEqual(pump.testSentByEndpointSetCount, 1)
            pump.enqueue(tag(1))
            pump.setSentByEndpoint(second)
            XCTAssertEqual(pump.testSentByEndpointSetCount, 2)
            pump.enqueue(tag(2))
        }
        queue.sync {}

        XCTAssertEqual(String(describing: flow.writtenBatches[0].sentBy[0]), String(describing: first))
        XCTAssertTrue(flow.completePendingWrite(error: nil))
        queue.sync {}
        XCTAssertEqual(String(describing: flow.writtenBatches[0].sentBy[0]), String(describing: second))
    }
}
