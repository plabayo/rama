import Foundation
import Network
import RamaAppleNEFFI
import XCTest

@testable import RamaAppleNetworkExtension

private final class RustDrainClock: @unchecked Sendable {
    struct Event {
        let at: UInt64
        let run: () -> Void
    }
    let milliseconds = TestValue<UInt64>(1)
    private let events = TestValue<[Event]>([])
    let reverseDueEvents = TestValue(false)
    func now() -> DispatchTime {
        DispatchTime(uptimeNanoseconds: milliseconds.get() * 1_000_000)
    }
    func schedule(_ ms: Int, _ run: @escaping () -> Void) {
        events.update { $0.append(Event(at: milliseconds.get() + UInt64(ms), run: run)) }
    }
    func advance(_ ms: UInt64, drain: () -> Void) {
        let target = milliseconds.get() + ms
        while let next = events.get().map(\.at).min(), next <= target {
            milliseconds.set(next)
            let due = events.update { events -> [Event] in
                let due = events.filter { $0.at <= next }
                events.removeAll { $0.at <= next }
                return due
            }
            let ordered = reverseDueEvents.get() ? Array(due.reversed()) : due
            for event in ordered { event.run() }
            drain()
        }
        milliseconds.set(target)
        drain()
    }
}

private final class RustDrainSink: NwEgressBytesSink {
    var onError: () -> Void = {}
    func onEgressBytes(_ data: Data) -> RamaTcpDeliverStatusBridge { .accepted }
    func onEgressEof() {}
    func onEgressError() { onError() }
}

/// Exercises the real Rust-mediated Swift drain owner, without a promoted
/// forwarder. Rust bridge timeout/delivery semantics are independently driven
/// under Tokio virtual time in ffi_stream.rs; these tests protect the other
/// half of that boundary and the production session's EOF/backstop wiring.
final class ViaRustBulkTransferTests: XCTestCase {
    private final class Harness {
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let connection = MockNwConnection()
        let clock = RustDrainClock()
        let budget = WriterMemoryBudget()
        let session: TcpFlowSession<MockTcpFlow>
        let writer: TcpClientWritePump

        init() {
            let clock = clock
            session = TcpFlowSession(
                core: core, flow: flow,
                meta: RamaTransparentProxyFlowMetaBridge(
                    protocolRaw: 1, remoteHost: "example.com", remotePort: 443,
                    localHost: nil, localPort: 0, sourceAppSigningIdentifier: nil,
                    sourceAppBundleIdentifier: nil, sourceAppAuditToken: nil, sourceAppPid: 42),
                now: { clock.now() },
                drainBackstopScheduler: { queue, ms, work in
                    clock.schedule(ms) { queue.sync { work.perform() } }
                })
            let ctx = session.ctx
            writer = TcpClientWritePump(
                flow: flow, queue: session.flowQueue, logger: { _ in },
                onTerminalError: { [weak ctx] in ctx?.applyWriterTerminal($0) },
                onDrained: {},
                onActivity: { [weak ctx] in
                    ctx?.lastActivityAt = clock.now()
                    return ctx?.isDone == false
                },
                retryScheduler: { clock.schedule($0, $1) },
                stallScheduler: { clock.schedule($0, $1) },
                now: { clock.now() }, writerMemoryBudget: budget,
                writePolicy: TcpWritePumpPolicy(maxPendingBytes: 256 * 1024))
            flow.captureWriteCompletions = true
            session.flowQueue.sync {
                ctx.connection = connection
                ctx.clientWritePump = writer
                ctx.lastActivityAt = clock.now()
                ctx.egressReady = true
                session.egressReady = true
                session.configureDrainPolicy(nil)
            }
            writer.markOpened()
            drain()
        }
        func drain() { for _ in 0..<8 { session.flowQueue.sync {} } }
        func advance(_ ms: UInt64) { clock.advance(ms, drain: drain) }
        func complete() {
            XCTAssertTrue(flow.completeNextWrite())
            drain()
        }
        deinit {
            session.flowQueue.sync { session.ctx.applyEngineDetached() }
            while flow.completeNextWrite() {}
            drain()
        }
    }

    func testDefaultAndExplicitLingerCannotPreemptWriterAllowance() {
        let h = Harness()
        for requested: UInt32 in [0, 5_000, 60_000, 360_000, 600_000] {
            var opts = RamaTcpEgressConnectOptions()
            opts.has_linger_close_ms = true
            opts.linger_close_ms = requested
            h.session.flowQueue.sync { h.session.configureDrainPolicy(opts) }
            XCTAssertEqual(h.session.lingerCloseMs, max(requested, 360_000))
            XCTAssertEqual(h.session.ctx.lingerCloseMs, h.session.lingerCloseMs,
                           "maintenance and the session must use the same grace")
        }
    }

    func testRustEOFTailSurvivesPausesAndClosesOnlyAfterEveryByteCompletes() {
        for pause: UInt64 in [1_000, 6_000, 30_000, 300_000] {
            let h = Harness()
            let chunks = (0..<4).map { Data(repeating: UInt8($0), count: 64 * 1024) }
            for chunk in chunks { XCTAssertEqual(h.writer.enqueue(chunk), .accepted) }
            h.drain()
            h.session.flowQueue.sync { h.session.closeClientAfterRustDrain() }
            h.drain()
            XCTAssertEqual(h.session.ctx.mode, .viaRust)
            XCTAssertEqual(h.session.lingerCloseMs, 360_000)
            h.advance(pause)
            XCTAssertEqual(h.flow.closeWriteCallCount, 0)
            XCTAssertEqual(h.connection.cancelCount, 0)
            for index in chunks.indices {
                XCTAssertEqual(h.flow.closeWriteCallCount, 0)
                XCTAssertEqual(h.flow.writes, Array(chunks.prefix(index + 1)))
                h.complete()
            }
            XCTAssertEqual(h.flow.writes, chunks)
            XCTAssertEqual(h.flow.closeWriteCallCount, 1)
            XCTAssertNil(h.flow.lastCloseWriteError)
            XCTAssertEqual(h.connection.cancelCount, 0, "independent upload stays open")
            XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
            h.advance(720_000)
            XCTAssertEqual(h.flow.closeWriteCallCount, 1, "cancelled backstops cannot close again")
            XCTAssertFalse(h.session.ctx.isDone)
        }
    }

    func testSlowRustEOFTailProgressOutlivesSeveralStallWindows() {
        let h = Harness()
        let chunks = (0..<4).map { Data(repeating: UInt8($0 + 1), count: 32_768) }
        for chunk in chunks { XCTAssertEqual(h.writer.enqueue(chunk), .accepted) }
        h.drain()
        h.session.flowQueue.sync { h.session.closeClientAfterRustDrain() }
        h.drain()
        for _ in chunks {
            h.advance(300_000)
            XCTAssertFalse(h.session.ctx.isDone)
            XCTAssertEqual(h.flow.closeWriteCallCount, 0)
            h.complete()
        }
        XCTAssertEqual(h.flow.writes, chunks)
        XCTAssertEqual(h.flow.closeWriteCallCount, 1)
        XCTAssertNil(h.flow.lastCloseWriteError)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
    }

    func testRustEOFWithheldWriteFailsAtWindowDespiteOppositeActivity() {
        let h = Harness()
        XCTAssertEqual(h.writer.enqueue(Data(repeating: 9, count: 65_536)), .accepted)
        h.drain()
        h.session.flowQueue.sync { h.session.closeClientAfterRustDrain() }
        h.drain()
        h.advance(300_000)
        h.session.flowQueue.sync { h.session.ctx.lastActivityAt = h.clock.now() }
        h.advance(59_999)
        XCTAssertEqual(h.flow.closeWriteCallCount, 0)
        h.advance(1)
        XCTAssertTrue(h.session.ctx.isDone)
        XCTAssertEqual(h.flow.closeReadCallCount, 1)
        XCTAssertEqual(h.flow.closeWriteCallCount, 1)
        XCTAssertEqual((h.flow.lastCloseReadError as NSError?)?.code, Int(ETIMEDOUT))
        XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, Int(ETIMEDOUT))
        XCTAssertEqual(h.connection.cancelCount, 1)
        XCTAssertNil(h.session.ctx.connection)
        h.complete()
        h.advance(720_000)
        XCTAssertEqual(h.flow.closeWriteCallCount, 1)
        XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(h.budget.snapshot().retainedItems, 0)
    }
    func testReadErrorGraceDefersWhileTailProgressesAndPreservesOriginalError() {
        for withholdForever in [false, true] {
            let h = Harness()
            let sink = RustDrainSink()
            let error = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET))
            let ctx = h.session.ctx, clock = h.clock
            let reader = NwTcpConnectionReadPump(
                connection: h.connection, session: sink, queue: h.session.flowQueue,
                eofGraceDeadline: .milliseconds(withholdForever ? 0 : 2_000),
                onReadError: { [weak ctx] in ctx?.egressReadError = $0 },
                onAbnormalStop: { [weak ctx] in ctx?.applyReadHardError($0) },
                shouldDeferAbnormalStop: { [weak ctx] in ctx?.clientWritePump?.hasOutstandingWork == true },
                abnormalStopScheduler: { queue, delay, work in
                    guard case .milliseconds(let ms) = delay else {
                        XCTFail("unexpected grace units"); return
                    }
                    clock.schedule(ms) { queue.sync { work.perform() } }
                })
            sink.onError = { h.session.closeClientAfterRustDrain() }
            let chunks = (0..<4).map { Data(repeating: UInt8($0 + 1), count: 32_768) }
            for chunk in chunks { XCTAssertEqual(h.writer.enqueue(chunk), .accepted) }
            h.drain()
            h.session.flowQueue.sync { ctx.egressReadPump = reader }
            reader.start()
            h.drain()
            XCTAssertTrue(h.connection.completePendingReceive(isComplete: true, error: .posix(.ECONNRESET)))
            h.drain()
            XCTAssertEqual((ctx.egressReadError as NSError?)?.code, error.code)
            h.advance(300_000)
            XCTAssertEqual(h.flow.closeWriteCallCount, 0, "short orphan grace must not truncate a tail")
            if withholdForever {
                h.advance(60_000)
                XCTAssertEqual(h.flow.closeWriteCallCount, 1)
                XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, error.code,
                               "the source reset must survive the writer timeout")
                h.complete()
            } else {
                for index in chunks.indices {
                    if index > 0 { h.advance(300_000) }
                    XCTAssertEqual(h.flow.closeWriteCallCount, 0)
                    h.complete()
                }
                XCTAssertEqual(h.flow.writes, chunks)
                XCTAssertEqual(h.flow.closeWriteCallCount, 1)
                XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, error.code)
            }
            h.advance(720_000)
            XCTAssertEqual(h.flow.closeReadCallCount, 1)
            XCTAssertEqual(h.flow.closeWriteCallCount, 1)
            XCTAssertEqual(h.connection.cancelCount, 1)
            XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
        }
    }

    func testSourceErrorSurvivesEitherTimeoutWinningTheQueueRace() {
        for backstopFirst in [false, true] {
            let h = Harness()
            let error = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET))
            XCTAssertEqual(h.writer.enqueue(Data([1, 2, 3])), .accepted)
            h.drain()
            h.session.flowQueue.sync {
                h.session.ctx.egressReadError = error
                h.session.closeClientAfterRustDrain()
            }
            h.drain()
            h.clock.reverseDueEvents.set(backstopFirst)
            h.advance(360_000)
            XCTAssertEqual((h.flow.lastCloseReadError as NSError?)?.code, error.code)
            XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, error.code)
            XCTAssertEqual(h.flow.closeWriteCallCount, 1)
            h.complete()
            h.advance(720_000)
            XCTAssertEqual(h.flow.closeWriteCallCount, 1)
            XCTAssertEqual(h.connection.cancelCount, 1)
            XCTAssertEqual(h.budget.snapshot().retainedBytes, 0)
        }
    }

}
