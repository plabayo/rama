import CryptoKit
import Foundation
import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Virtual monotonic time, including retry and stall callbacks. No test sleeps.
/// Callbacks deliberately run off the flow queue, matching NE's contract.
private final class BulkClock: @unchecked Sendable {
    struct Event {
        let at: UInt64
        let work: @Sendable () -> Void
    }
    let time = TestValue<UInt64>(1)
    let events = TestValue<[Event]>([])
    func now() -> DispatchTime { DispatchTime(uptimeNanoseconds: time.get() * 1_000_000) }
    func schedule(_ ms: Int, _ work: @escaping @Sendable () -> Void) {
        events.update { $0.append(Event(at: time.get() + UInt64(ms), work: work)) }
    }
    func advance(_ ms: UInt64, drain: () -> Void) {
        let target = time.get() + ms
        while let next = events.get().map(\.at).min(), next <= target {
            time.set(next)
            let due = events.update { events -> [Event] in
                let due = events.filter { $0.at <= next }
                events.removeAll { $0.at <= next }
                return due
            }
            for event in due { event.work() }
            drain()
        }
        time.set(target)
        drain()
    }
}

/// Keeps failed attempts out of the delivered stream; holds one actual payload
/// and completion until explicitly completed or retired. It can deliberately
/// keep a callback after close to verify physical-charge lifetime honestly.
private final class BulkFlow: TcpFlowLike, @unchecked Sendable {
    struct Write {
        let data: Data
        let completion: @Sendable (Error?) -> Void
    }
    let base = MockTcpFlow()
    let pending = TestValue<Write?>(nil)
    let delivered = TestValue(Data())
    let deliveredCount = TestValue(0)
    let deliveredDigest = TestValue(SHA256())
    let retainDelivered = TestValue(true)
    func write(_ data: Data, withCompletionHandler completion: @escaping @Sendable (Error?) -> Void) {
        XCTAssertNil(pending.get(), "NE writes must remain serial")
        pending.set(Write(data: data, completion: completion))
    }
    @discardableResult
    func complete(_ error: Error? = nil) -> Bool {
        guard let write = pending.update({ p -> Write? in defer { p = nil }; return p }) else {
            return false
        }
        if error == nil {
            deliveredCount.update { $0 += write.data.count }
            deliveredDigest.update { $0.update(data: write.data) }
            if retainDelivered.get() { delivered.update { $0.append(write.data) } }
        }
        write.completion(error)
        return true
    }
    func readData(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        base.readData(completionHandler: completionHandler)
    }
    func open(withLocalEndpoint localEndpoint: NWHostEndpoint?,
              completionHandler: @escaping @Sendable (Error?) -> Void) { completionHandler(nil) }
    func closeReadWithError(_ error: Error?) { base.closeReadWithError(error) }
    func closeWriteWithError(_ error: Error?) { base.closeWriteWithError(error) }
    func applyMetadata(to params: NWParameters) {}
}

private final class BulkForwarderRef: @unchecked Sendable {
    weak var value: TcpDirectForwarder?
}

final class PromotedBulkTransferTests: XCTestCase {
    private final class Harness {
        let queue = DispatchQueue(label: "rama.test.bulk")
        let clock = BulkClock()
        let flow = BulkFlow()
        let connection = MockNwConnection()
        let ctx = TcpFlowContext()
        let budget: WriterMemoryBudget
        let writer: TcpClientWritePump
        let egress: NwTcpConnectionWritePump
        let forwarder: TcpDirectForwarder
        let terminals = TestValue(0)
        let droppedEdges = TestValue(0)
        let cap = 64 * 1024

        init(timeout: Int = 360_000, dropEdges: Int = 0,
             budget: WriterMemoryBudget = WriterMemoryBudget(),
             productionCore: TransparentProxyCore? = nil) {
            self.budget = budget
            let ctx = ctx, clock = clock, terminals = terminals, edges = droppedEdges
            edges.set(dropEdges)
            let forwarderRef = BulkForwarderRef()
            let policy = TcpWritePumpPolicy(maxPendingBytes: cap, stallTimeoutMs: timeout)
            writer = TcpClientWritePump(
                flow: flow, queue: queue, logger: { _ in },
                onTerminalError: { [weak ctx] error in
                    terminals.update { $0 += 1 }
                    ctx?.applyWriterTerminal(error)
                },
                onDrained: {
                    let dropped = edges.update { n -> Bool in
                        if n > 0 { n -= 1; return true }; return false
                    }
                    if !dropped { forwarderRef.value?.onClientPumpDrained() }
                },
                onActivity: { [weak ctx] in ctx?.recordActivityUnlessPressureEvicted() ?? false },
                retryScheduler: { clock.schedule($0, $1) },
                stallScheduler: { clock.schedule($0, $1) },
                now: { clock.now() }, writerMemoryBudget: budget, writePolicy: policy)
            egress = NwTcpConnectionWritePump(
                connection: connection, queue: queue,
                onDrained: { forwarderRef.value?.onEgressPumpDrained() },
                onTerminal: { [weak ctx] error in ctx?.applyWriterTerminal(error) },
                retryScheduler: { clock.schedule($0, $1) },
                stallScheduler: { clock.schedule($0, $1) },
                now: { clock.now() }, writerMemoryBudget: budget, writePolicy: policy)
            if let core = productionCore {
                let queue = queue, flow = flow, connection = connection
                let writer = writer, egress = egress
                forwarder = queue.sync {
                    core.makePromotedForwarder(
                        ctx: ctx, flow: flow, connection: connection,
                        clientWritePump: writer, egressWritePump: egress, flowQueue: queue)
                }
            } else {
                forwarder = TcpDirectForwarder(
                    flow: flow, connection: connection, clientWritePump: writer,
                    egressWritePump: egress, writerMemoryBudget: budget, queue: queue,
                    logger: { _ in }, drainStallDeadline: .never,
                    onReadError: { [weak ctx] error in ctx?.applyReadHardError(error) },
                    writeChunkLimit: cap,
                    closeClientWrite: { [weak ctx] error in ctx?.closeClientWriteOnce(error) },
                    pauseScheduler: { clock.schedule($0, $1) }, onTerminal: {})
            }
            forwarderRef.value = forwarder
            ctx.flow = flow
            ctx.flowQueue = queue
            ctx.connection = connection
            ctx.clientWritePump = writer
            ctx.egressWritePump = egress
            ctx.directForwarder = forwarder
            ctx.mode = .promoted
            ctx.egressReady = true
            if let core = productionCore {
                ctx.core = core
                ctx.flowId = ObjectIdentifier(flow)
                core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
            }
            connection.transition(to: .ready)
            writer.markOpened()
            forwarder.markClientReadDrained()
            forwarder.markEgressReadDrained()
            forwarder.markRustC2SDone()
            forwarder.markRustS2CDone()
            drain()
        }
        func drain() { for _ in 0..<8 { queue.sync {} } }
        func advance(_ ms: UInt64) { clock.advance(ms, drain: drain) }
        func receive(_ data: Data, eof: Bool = false, error: NWError? = nil) {
            XCTAssertTrue(connection.completePendingReceive(data: data, isComplete: eof, error: error))
            drain()
        }
        func complete(_ error: Error? = nil) {
            XCTAssertTrue(flow.complete(error))
            drain()
        }
        var done: Bool { queue.sync { ctx.isDone } }
        func assertError(_ code: Int? = nil, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertTrue(done, file: file, line: line)
            XCTAssertEqual(flow.base.closeReadCallCount, 1, file: file, line: line)
            XCTAssertEqual(flow.base.closeWriteCallCount, 1, file: file, line: line)
            XCTAssertNotNil(flow.base.lastCloseReadError, file: file, line: line)
            XCTAssertNotNil(flow.base.lastCloseWriteError, file: file, line: line)
            if let code {
                XCTAssertEqual((flow.base.lastCloseWriteError as NSError?)?.code, code, file: file, line: line)
            }
            XCTAssertNil(queue.sync { ctx.connection }, file: file, line: line)
            XCTAssertGreaterThan(connection.cancelCount, 0, file: file, line: line)
        }
        deinit {
            queue.sync { ctx.applyEngineDetached() }
            _ = flow.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
            drain()
        }
    }

    private func pattern(_ count: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ ($0 >> 8)) })
    }

    func testSlowReaderPausesThroughFiveMinutesPreserveStreamAndEOF() {
        for pause: UInt64 in [1_000, 6_000, 30_000, 300_000] {
            let h = Harness()
            let payload = pattern(h.cap * 3 + 24)
            // Carryover can exceed one write chunk and can already include EOF.
            h.forwarder.acceptEgressCarryover(payload)
            h.forwarder.acceptEgressCarryover(nil)
            h.drain()
            h.advance(pause)
            XCTAssertFalse(h.done)
            XCTAssertEqual(h.flow.base.closeWriteCallCount, 0)
            while h.flow.pending.get() != nil { h.complete() }
            XCTAssertEqual(h.flow.delivered.get(), payload)
            XCTAssertEqual(h.flow.base.closeWriteCallCount, 1)
            XCTAssertNil(h.flow.base.lastCloseWriteError)
            XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
        }
    }

    func testWithheldCallbackTimesOutExactlyOnceAndLateCallbackReleasesCharge() {
        let h = Harness(timeout: 30_000)
        h.receive(pattern(h.cap))
        h.receive(pattern(h.cap)) // pause with a second source root
        h.advance(29_999)
        XCTAssertFalse(h.done)
        h.advance(1)
        h.assertError(Int(ETIMEDOUT))
        XCTAssertEqual(h.terminals.get(), 1)
        // Transport still owns a real Data/callback: do not falsely refund it.
        XCTAssertEqual(h.budget.snapshot().retainedBytes, h.cap)
        h.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ENOBUFS)))
        h.advance(90_000)
        h.assertError(Int(ETIMEDOUT))
        XCTAssertEqual(h.terminals.get(), 1)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(h.budget.snapshot().retainedItems, 0)
    }

    func testLostDrainEdgesRecoverWithoutReorderingOrDuplicateBytes() {
        let h = Harness(dropEdges: 4)
        let payload = pattern(h.cap * 5 + 24)
        h.forwarder.acceptEgressCarryover(payload)
        h.forwarder.acceptEgressCarryover(nil)
        h.drain()
        for _ in 0..<6 {
            h.complete()
            h.advance(1_000)
        }
        XCTAssertEqual(h.droppedEdges.get(), 0)
        XCTAssertEqual(h.flow.delivered.get(), payload)
        XCTAssertEqual(h.flow.base.closeWriteCallCount, 1)
        XCTAssertNil(h.flow.base.lastCloseWriteError)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testBackpressureWithProgressLastsFarLongerThanOldDeadline() {
        let h = Harness(timeout: 30_000)
        let payload = pattern(h.cap)
        let noBuffers = NSError(domain: NSPOSIXErrorDomain, code: Int(ENOBUFS))
        for _ in 0..<12 {
            h.receive(payload)
            h.complete(noBuffers)
            h.advance(10_000)
            h.complete()
            XCTAssertFalse(h.done)
        }
        XCTAssertEqual(h.flow.delivered.get(), Data((0..<12).flatMap { _ in payload }))
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testOnlyBackpressureTimesOutWithOriginalPOSIXError() {
        let h = Harness(timeout: 30_000)
        h.receive(pattern(h.cap))
        let error = NSError(domain: NSPOSIXErrorDomain, code: Int(ENOBUFS))
        for _ in 0..<149 { h.complete(error); h.advance(200) }
        XCTAssertFalse(h.done)
        h.complete(error)
        h.advance(200)
        h.assertError(Int(ENOBUFS))
        XCTAssertEqual(h.terminals.get(), 1)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testEOFWhileWedgedNeverClosesCleanly() {
        let h = Harness(timeout: 30_000)
        h.receive(pattern(h.cap), eof: true)
        h.advance(29_999)
        XCTAssertEqual(h.flow.base.closeWriteCallCount, 0)
        h.advance(1)
        h.assertError(Int(ETIMEDOUT))
        h.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testSuccessfulCompletionRefreshesIdleEvenWithoutNewAdmission() {
        let h = Harness()
        let core = TransparentProxyCore()
        let id = ObjectIdentifier(h.flow)
        core.testInsertTcpContext(id, h.ctx)
        h.receive(pattern(h.cap))
        // More than the production promoted-idle window has elapsed since any
        // enqueue. Only the successful write completion can revive this clock.
        let nowNs = DispatchTime.now().uptimeNanoseconds
        let old = nowNs > 2_000_000_000_000 ? nowNs - 2_000_000_000_000 : 1
        h.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: old)
        h.complete()
        // Also prove the edge directly when a freshly booted CI host has not
        // been up long enough to backdate beyond the full idle timeout.
        XCTAssertGreaterThan(h.ctx.lastActivityAt.uptimeNanoseconds, old)
        core.testRunPeriodicMaintenance()
        h.drain()
        XCTAssertFalse(h.done)
        XCTAssertEqual(h.flow.base.closeWriteCallCount, 0)
    }

    func testEveryForcedTeardownCarriesErrorWithUnwrittenBytes() {
        let actions: [(TcpFlowContext) -> Void] = [
            { $0.applyWriterTerminal(NSError(domain: NSPOSIXErrorDomain, code: Int(EPIPE))) },
            { $0.applyDrainBackstop() }, { $0.applyIdleTimeout() },
            { $0.applyPressureEvicted() }, { $0.applyEngineDetached() },
        ]
        for action in actions {
            let h = Harness()
            h.receive(pattern(h.cap))
            h.receive(pattern(h.cap))
            h.queue.sync { action(h.ctx); action(h.ctx) }
            h.drain()
            h.assertError()
            h.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
            XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
            XCTAssertEqual(h.budget.snapshot().retainedItems, 0)
        }
    }

    func testActiveUploadCannotMaskWedgedDownload() {
        let h = Harness(timeout: 30_000)
        h.receive(pattern(h.cap))
        for _ in 0..<29 {
            h.flow.base.completeReadSynchronously(data: Data([1, 2, 3]), error: nil)
            h.drain()
            XCTAssertTrue(h.connection.completePendingSend())
            h.drain()
            h.advance(1_000)
            XCTAssertFalse(h.done)
        }
        XCTAssertEqual(h.connection.sentChunks.compactMap(\.content).reduce(0) { $0 + $1.count }, 87)
        h.advance(1_000)
        h.assertError(Int(ETIMEDOUT))
        h.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
    }

    func testThreeBulkFlowsOneWedgedDoNotStarveOtherFlows() {
        let budget = WriterMemoryBudget()
        let flows = (0..<3).map { _ in Harness(timeout: 30_000, budget: budget) }
        let payload = pattern(64 * 1024)
        for h in flows { h.receive(payload) }
        for tick in 0..<40 {
            for (i, h) in flows.enumerated() {
                if i > 0 && tick % (i + 1) == 0 {
                    h.complete()
                    h.receive(payload)
                }
                h.advance(1_000)
            }
            XCTAssertLessThanOrEqual(budget.snapshot().retainedBytes, 3 * payload.count)
        }
        flows[0].assertError(Int(ETIMEDOUT))
        for h in flows.dropFirst() {
            h.complete()
            XCTAssertFalse(h.done)
            XCTAssertGreaterThan(h.flow.deliveredCount.get(), payload.count)
        }
        flows[0].complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
    }

    func testSeededFaultInterleavingsPreservePrefixAndBoundTimers() {
        for seed: UInt64 in [1, 7, 42, 0xdeadbeef] {
            let h = Harness(dropEdges: Int.max)
            var rng = seed
            var source = Data()
            for index in 0..<200 {
                rng = rng &* 6364136223846793005 &+ 1
                // Two distinct chunks force a real pause, rather than merely
                // configuring dropped notifications that can never be emitted.
                let head = Data(repeating: UInt8(truncatingIfNeeded: index), count: h.cap)
                var payload = Data(repeating: UInt8(truncatingIfNeeded: rng >> 32),
                                   count: Int(rng % UInt64(h.cap - 4)) + 4)
                payload[0] = UInt8(truncatingIfNeeded: index)
                payload[1] = UInt8(truncatingIfNeeded: index >> 8)
                source.append(head)
                source.append(payload)
                h.receive(head)
                h.receive(payload, eof: index == 199)
                XCTAssertGreaterThan(h.queue.sync { h.forwarder.testBufferedChunkCount }, 0)
                XCTAssertEqual(h.connection.pendingReceiveCount, 0)
                if rng % 3 == 0 {
                    h.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(EAGAIN)))
                    h.advance(1_000)
                }
                h.advance(rng % 20_000)
                XCTAssertFalse(h.done)
                h.complete()
                let prefix = h.flow.delivered.get()
                XCTAssertEqual(prefix, Data(source.prefix(prefix.count)), "seed=\(seed)")
                XCTAssertNil(h.flow.pending.get(), "dropped drain edge must leave the tail parked")
                XCTAssertGreaterThan(h.queue.sync { h.forwarder.testBufferedChunkCount }, 0)
                h.advance(1_000)
                h.complete()
                XCTAssertEqual(h.flow.delivered.get(), source, "seed=\(seed)")
                XCTAssertLessThanOrEqual(h.clock.events.get().count, 2,
                    "short bursts must not accumulate long-lived watchdog closures")
                XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
            }
            XCTAssertEqual(h.flow.delivered.get(), source)
            XCTAssertEqual(h.flow.base.closeWriteCallCount, 1)
            XCTAssertNil(h.flow.base.lastCloseWriteError)
        }
    }

    func testAggregateWaitWithoutAnyInflightWriteIsStillBounded() {
        let budget = WriterMemoryBudget(policy: WriterMemoryPolicy(
            maxBytes: 128 * 1024, maxItems: 16, tcpWaiterMaxBytes: 64 * 1024,
            udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        XCTAssertTrue(budget.tryReserve(bytes: 128 * 1024))
        let h = Harness(timeout: 30_000, budget: budget)
        XCTAssertEqual(h.writer.enqueue(Data([1])), .paused)
        h.drain()
        XCTAssertNil(h.flow.pending.get())
        h.advance(29_999)
        XCTAssertFalse(h.done)
        h.advance(1)
        h.assertError(Int(ETIMEDOUT))
        budget.release(bytes: 128 * 1024)
        h.drain()
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testEmptyWritesDoNotCreateProgressOrStallTimers() {
        let h = Harness(timeout: 1_000)
        for _ in 0..<100 { XCTAssertEqual(h.writer.enqueue(Data()), .accepted) }
        h.drain()
        h.advance(2_000)
        XCTAssertFalse(h.done)
        XCTAssertNil(h.flow.pending.get())
        XCTAssertTrue(h.clock.events.get().isEmpty)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testNativeNetworkBackpressureRetriesWithoutDroppingUpload() {
        XCTAssertTrue(isTransientWriteBackpressure(NWError.posix(.ENOBUFS)))
        XCTAssertTrue(isTransientWriteBackpressure(NWError.posix(.EAGAIN)))
        XCTAssertFalse(isTransientWriteBackpressure(NWError.dns(ENOBUFS)))
        XCTAssertFalse(isTransientWriteBackpressure(NWError.posix(.EPIPE)))
        let h = Harness()
        let payload = pattern(1_024)
        h.flow.base.completeReadSynchronously(data: payload, error: nil)
        h.drain()
        XCTAssertTrue(h.connection.completePendingSend(error: .posix(.ENOBUFS)))
        h.drain()
        h.advance(10_000)
        XCTAssertFalse(h.done)
        XCTAssertEqual(h.connection.sentChunks.compactMap(\.content), [payload, payload])
        XCTAssertTrue(h.connection.completePendingSend())
        h.drain()
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testBusyDownloadCannotMaskWedgedUpload() {
        let h = Harness(timeout: 30_000)
        h.flow.base.completeReadSynchronously(data: Data([1, 2, 3]), error: nil)
        h.drain()
        for _ in 0..<29 {
            h.receive(Data([4, 5, 6]))
            h.complete()
            h.advance(1_000)
            XCTAssertFalse(h.done)
        }
        h.advance(1_000)
        h.assertError(Int(ETIMEDOUT))
        XCTAssertTrue(h.connection.completePendingSend(error: .posix(.ECANCELED)))
        h.drain()
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testProductionEOFWiringSurvivesFiveMinutePausedDrain() {
        let core = TransparentProxyCore()
        let h = Harness(productionCore: core)
        let payload = pattern(h.cap)
        h.receive(payload)
        h.receive(Data([0xff]), eof: true)
        XCTAssertEqual(h.ctx.lingerCloseMs, 360_000)
        XCTAssertTrue(h.ctx.terminalSignalled, "actual EOF must publish closing state")
        XCTAssertTrue(h.ctx.drainClosePending, "retained EOF tail must protect the drain")
        // Pump time is virtual; production maintenance has its real monotonic
        // clock. Age its observed activity explicitly without sleeping.
        h.advance(300_000)
        let nowNs = DispatchTime.now().uptimeNanoseconds
        h.ctx.lastActivityAt = DispatchTime(
            uptimeNanoseconds: nowNs > 300_000_000_000 ? nowNs - 300_000_000_000 : 1)
        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()
        h.drain()
        XCTAssertFalse(h.done)
        XCTAssertEqual(h.flow.base.closeWriteCallCount, 0)
        h.complete()
        h.complete()
        XCTAssertEqual(h.flow.delivered.get(), payload + Data([0xff]))
        XCTAssertEqual(h.flow.base.closeWriteCallCount, 1)
        XCTAssertNil(h.flow.base.lastCloseWriteError)
        XCTAssertFalse(h.ctx.drainClosePending)
    }

    func testWriterStallPreservesEarlierServerReset() {
        let h = Harness(timeout: 30_000)
        h.receive(pattern(h.cap))
        h.advance(1_000)
        h.receive(Data([0xff]), eof: true, error: .posix(.ECONNRESET))
        h.advance(29_000)
        h.assertError(Int(ECONNRESET))
        h.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testProductionNaturalTerminalClosesAndReleasesBeforeHarnessCleanup() {
        let core = TransparentProxyCore()
        let h = Harness(productionCore: core)
        h.receive(Data([1, 2, 3]), eof: true)
        h.complete()
        h.flow.base.completeReadSynchronously(data: nil, error: nil)
        h.drain()
        XCTAssertEqual(h.connection.pendingSendCount, 1, "final FIN awaits completion")
        XCTAssertFalse(h.done)
        XCTAssertTrue(h.connection.completePendingSend())
        h.drain()
        XCTAssertTrue(h.done, "production onTerminal must run without deinit assistance")
        XCTAssertEqual(h.flow.base.closeReadCallCount, 1)
        XCTAssertEqual(h.flow.base.closeWriteCallCount, 1)
        XCTAssertNil(h.flow.base.lastCloseReadError)
        XCTAssertNil(h.flow.base.lastCloseWriteError)
        XCTAssertGreaterThan(h.connection.cancelCount, 0)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testTerminalGraphDeallocatesAfterTransportRetiresLateCallbacks() {
        weak var flow: BulkFlow?
        weak var connection: MockNwConnection?
        weak var writer: TcpClientWritePump?
        weak var egress: NwTcpConnectionWritePump?
        weak var forwarder: TcpDirectForwarder?
        let budget = WriterMemoryBudget()
        do {
            let h = Harness(timeout: 1_000, budget: budget)
            flow = h.flow
            connection = h.connection
            writer = h.writer
            egress = h.egress
            forwarder = h.forwarder
            h.receive(pattern(h.cap))
            h.advance(1_000)
            h.complete(NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
            h.drain()
        }
        XCTAssertNil(flow)
        XCTAssertNil(connection)
        XCTAssertNil(writer)
        XCTAssertNil(egress)
        XCTAssertNil(forwarder)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testOneGiBHasBoundedSwiftPayloadRetention() {
        let h = Harness()
        h.flow.retainDelivered.set(false)
        let payload = pattern(h.cap)
        let chunks = 1024 * 1024 * 1024 / payload.count
        var produced = 0
        var expectedDigest = SHA256()
        for completed in 0..<chunks {
            // Saturate every available source receive before allowing one
            // destination completion. Each chunk has distinct backing and an
            // index marker, making reordering/duplication visible to the hash.
            while h.connection.pendingReceiveCount > 0 && produced < chunks {
                var chunk = payload
                for byte in 0..<4 {
                    chunk[byte] = UInt8(truncatingIfNeeded: produced >> (byte * 8))
                }
                expectedDigest.update(data: chunk)
                h.receive(chunk, eof: produced == chunks - 1)
                produced += 1
                XCTAssertLessThanOrEqual(h.budget.snapshot().retainedBytes, 2 * h.cap)
            }
            h.advance(completed % 37 == 0 ? 30_000 : 10)
            h.complete()
        }
        XCTAssertEqual(produced, chunks)
        XCTAssertEqual(Data(h.flow.deliveredDigest.get().finalize()), Data(expectedDigest.finalize()))
        XCTAssertEqual(h.flow.deliveredCount.get(), 1024 * 1024 * 1024)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(h.flow.base.closeWriteCallCount, 1)
        XCTAssertNil(h.flow.base.lastCloseWriteError)
    }
}
