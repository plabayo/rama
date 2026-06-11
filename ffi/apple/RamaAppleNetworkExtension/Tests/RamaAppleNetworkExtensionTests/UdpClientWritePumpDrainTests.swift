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

    // MARK: - drop-on-full lossy bound

    /// UDP is lossy: once `pending.count >= udpWritePumpMaxPending` (256) the
    /// pump drops the NEWEST datagram rather than buffer without bound. With
    /// one batch in flight + 256 queued, enqueueing past that drops the
    /// latest arrivals; the older 257 (1 in flight + 256 queued) are retained
    /// in FIFO order.
    func testDropsNewestWhenQueueFull() {
        let flow = MockUdpFlow()
        let queue = makeQueue()
        let pump = UdpClientWritePump(flow: flow, queue: queue, logger: { _ in }, onTerminalError: { _ in })
        pump.markOpened()

        // 260 attributed datagrams; never complete the in-flight write so the
        // queue backs up to the cap. Retained = 1 in-flight + 256 queued =
        // tags 0...256; tags 257,258,259 are dropped (newest-first).
        let total = 260
        for n in 0..<total { pump.enqueue(tag(n), sentBy: ep()) }
        queue.sync {}

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
}
