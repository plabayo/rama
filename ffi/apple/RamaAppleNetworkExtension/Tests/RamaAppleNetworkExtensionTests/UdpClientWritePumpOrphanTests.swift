import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Pins the head-of-line-block fix on `UdpClientWritePump.flushLocked`.
///
/// **The bug.** A native enqueue can capture `sentBy ?? sentByEndpoint` at
/// admission, while borrowed Rust replies deliberately bypass the fallback.
/// If the eligible endpoint resolution is nil, the pump previously returned
/// WITHOUT popping — meaning a later attributed
/// datagram appended to the back of the queue was held behind an
/// orphan head forever (an attributed enqueue does not retroactively
/// fix the head's missing peer). Real flows could wedge on a single
/// peerless reply until the idle watchdog (or an explicitly configured Rust
/// max-flow-lifetime backstop) closed it.
///
/// **The fix.** When the head is unresolvable, *drop* it (UDP is
/// lossy by design); log once per flow; continue to the
/// next item.
final class UdpClientWritePumpOrphanTests: XCTestCase {

    private static let queue = DispatchQueue(label: "rama.tproxy.udp.write.pump.test")

    private func makePump(flow: MockUdpFlow) -> UdpClientWritePump {
        UdpClientWritePump(
            flow: flow,
            queue: Self.queue,
            logger: { _ in },
            onTerminalError: { _ in }
        )
    }

    /// `lo0` endpoint useful as a real `NWHostEndpoint`. Construction
    /// is cheap; we never actually send.
    private func attributedEndpoint(port: UInt16 = 5353) -> NWHostEndpoint {
        NWHostEndpoint(hostname: "127.0.0.1", port: "\(port)")
    }

    /// Block until the test queue drains. The pump dispatches all
    /// state mutations + flushLocked invocations onto `Self.queue`,
    /// so a `queue.sync {}` is a deterministic flush.
    private func sync() {
        Self.queue.sync {}
    }

    /// Orphan reply (sentBy = nil) followed by an attributed reply
    /// (sentBy = some peer). Without the fix, the attributed reply
    /// is stuck behind the orphan and the kernel sees NO writes.
    /// With the fix, the orphan is dropped and the attributed reply
    /// is written promptly.
    func testOrphanHeadDoesNotBlockAttributedTail() {
        let flow = MockUdpFlow()
        let pump = makePump(flow: flow)
        pump.markOpened()
        sync()

        pump.enqueue(Data("orphan".utf8), sentBy: nil)
        pump.enqueue(Data("attributed".utf8), sentBy: attributedEndpoint())
        sync()

        let batches = flow.writtenBatches
        XCTAssertEqual(
            batches.count, 1,
            "exactly the attributed reply must be written; orphan must be dropped, not held"
        )
        XCTAssertEqual(batches.first?.datagrams.first.map { String(decoding: $0, as: UTF8.self) }, "attributed")
        XCTAssertEqual(
            (batches.first?.sentBy.first as? NWHostEndpoint)?.hostname, "127.0.0.1"
        )
    }

    /// Three orphans in a row, then an attributed one. All three
    /// orphans must drop; the attributed one must write.
    func testManyConsecutiveOrphansAllDropAttributedSurvives() {
        let flow = MockUdpFlow()
        let pump = makePump(flow: flow)
        pump.markOpened()
        sync()

        pump.enqueue(Data("orphan1".utf8), sentBy: nil)
        pump.enqueue(Data("orphan2".utf8), sentBy: nil)
        pump.enqueue(Data("orphan3".utf8), sentBy: nil)
        pump.enqueue(Data("survivor".utf8), sentBy: attributedEndpoint())
        sync()

        let batches = flow.writtenBatches
        XCTAssertEqual(batches.count, 1, "all orphans must be dropped")
        XCTAssertEqual(
            batches.first?.datagrams.first.map { String(decoding: $0, as: UTF8.self) },
            "survivor"
        )
    }

    /// An orphan that arrives AFTER `setSentByEndpoint` populates
    /// the cache is rescued by the fallback — the cache fills in.
    /// Pin that this still works (the orphan-drain must not over-
    /// trigger).
    func testOrphanRescuedByCachedSentByEndpoint() {
        let flow = MockUdpFlow()
        let pump = makePump(flow: flow)
        pump.markOpened()
        pump.setSentByEndpoint(attributedEndpoint())
        sync()

        pump.enqueue(Data("rescued".utf8), sentBy: nil)
        sync()

        let batches = flow.writtenBatches
        XCTAssertEqual(batches.count, 1, "cache rescue must write the orphan")
        XCTAssertEqual(
            batches.first?.datagrams.first.map { String(decoding: $0, as: UTF8.self) },
            "rescued"
        )
        XCTAssertEqual(
            (batches.first?.sentBy.first as? NWHostEndpoint)?.hostname, "127.0.0.1"
        )
    }

    /// An orphan first, NO cache populated, then a cache populated
    /// AFTER. With the drop-on-flush fix, the orphan is gone by the
    /// time the cache is set — so the cache only helps future
    /// enqueues. Pin the contract: setSentByEndpoint AFTER drop is
    /// not a time-machine; it does not resurrect dropped datagrams.
    func testLateCachePopulationDoesNotResurrectDroppedOrphan() {
        let flow = MockUdpFlow()
        let pump = makePump(flow: flow)
        pump.markOpened()
        sync()

        pump.enqueue(Data("doomed".utf8), sentBy: nil)
        sync()
        // Now the queue is empty: orphan was dropped.
        pump.setSentByEndpoint(attributedEndpoint())
        sync()

        XCTAssertEqual(
            flow.writtenBatches.count, 0,
            "dropped orphan must not be resurrected by a later cache update"
        )
    }

    /// Native work admitted before activation may still be waiting when its
    /// explicit fallback arrives. Unlike a borrowed missing peer, it remains
    /// fallback-eligible and is rescued when the pump opens.
    func testQueuedNativeNilIsRescuedByFallbackUpdateBeforeActivation() {
        let flow = MockUdpFlow()
        let pump = makePump(flow: flow)

        pump.enqueue(Data("queued-native".utf8), sentBy: nil)
        sync()
        XCTAssertTrue(flow.writtenBatches.isEmpty)

        pump.setSentByEndpoint(attributedEndpoint())
        pump.markOpened()
        sync()

        XCTAssertEqual(
            flow.writtenBatches.first?.datagrams,
            [Data("queued-native".utf8)])
        XCTAssertEqual(
            (flow.writtenBatches.first?.sentBy.first as? NWHostEndpoint)?.hostname,
            "127.0.0.1")
    }

    /// A valid write between orphan drops must not re-arm the diagnostic.
    /// Otherwise an alternating peerless/attributed stream emits and allocates
    /// one log record every other datagram on the packet path.
    func testOrphanDiagnosticIsLifetimeStickyAcrossSuccessfulWrites() {
        let flow = MockUdpFlow()
        let logs = TestValue<[FlowLogMessage]>([])
        let pump = UdpClientWritePump(
            flow: flow,
            queue: Self.queue,
            logger: { message in logs.update { $0.append(message) } },
            onTerminalError: { _ in }
        )
        pump.markOpened()
        sync()

        for index in 0..<3 {
            pump.enqueue(Data("orphan-\(index)".utf8), sentBy: nil)
            pump.enqueue(
                Data("valid-\(index)".utf8),
                sentBy: attributedEndpoint(port: UInt16(5_353 + index)))
            sync()
            XCTAssertTrue(flow.completePendingWrite(error: nil))
            sync()
        }

        let orphanLogs = logs.get().filter {
            $0.text.contains("udp write pump dropped")
        }
        XCTAssertEqual(orphanLogs.count, 1)
        XCTAssertEqual(
            orphanLogs.first?.text,
            "udp write pump dropped 1 orphan datagram(s): no usable sentBy endpoint (borrowed peer absent or invalid, or native fallback unavailable). Further orphan-drop diagnostics are suppressed for this pump.")
        XCTAssertFalse(orphanLogs.first?.text.contains("no cached endpoint") == true)
    }
}
