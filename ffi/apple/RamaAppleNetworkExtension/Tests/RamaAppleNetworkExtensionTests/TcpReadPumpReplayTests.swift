import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Drives the read pumps' `.paused` → `pendingData` replay-buffer →
/// `resume()` state machine, and the `.paused`-replay carryover hand-off,
/// with a SCRIPTED sink.
final class TcpReadPumpReplayTests: XCTestCase {

    private final class NoCopyLifetimeProbe: @unchecked Sendable {
        private let lock = NSLock()
        private var _released = false

        var released: Bool {
            lock.lock(); defer { lock.unlock() }
            return _released
        }

        func markReleased() {
            lock.lock(); _released = true; lock.unlock()
        }
    }

    private final class OwnedSliceSink: TcpClientBytesSink, @unchecked Sendable {
        private let lock = NSLock()
        private var statuses: [RamaTcpDeliverStatusBridge]
        private var retained: TcpPayloadSlice?
        private weak var observedRoot: TcpRetainedBuffer?
        private var _received: [Data] = []
        private var _accepted: [Data] = []
        private let retainAccepted: Bool
        private let beforeRead: (() -> Void)?

        init(
            _ statuses: [RamaTcpDeliverStatusBridge],
            retainAccepted: Bool = false,
            beforeRead: (() -> Void)? = nil
        ) {
            self.statuses = statuses
            self.retainAccepted = retainAccepted
            self.beforeRead = beforeRead
        }

        func onClientBytes(_ data: Data) -> RamaTcpDeliverStatusBridge {
            XCTFail("physical read path must use TcpPayloadSlice")
            return .closed
        }

        func onClientPayload(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge {
            lock.lock()
            defer { lock.unlock() }
            observedRoot = payload.root
            beforeRead?()
            let data = payload.copiedData
            _received.append(data)
            let status = statuses.isEmpty ? .accepted : statuses.removeFirst()
            if status == .accepted { _accepted.append(data) }
            if status == .accepted, retainAccepted { retained = payload }
            return status
        }

        var received: [Data] {
            lock.lock(); defer { lock.unlock() }
            return _received
        }

        var accepted: [Data] {
            lock.lock(); defer { lock.unlock() }
            return _accepted
        }

        var observedRootIsAlive: Bool {
            lock.lock(); defer { lock.unlock() }
            return observedRoot != nil
        }

        func takeRetained() -> TcpPayloadSlice? {
            lock.lock(); defer { lock.unlock() }
            let value = retained
            retained = nil
            return value
        }
    }

    private func makeNoCopyData(
        _ bytes: [UInt8]
    ) -> (data: Data, pointer: UnsafeMutableRawPointer, probe: NoCopyLifetimeProbe) {
        // Foundation may inline very small Data values even when initialized
        // with bytesNoCopy. Stay above that threshold so pointer mutation
        // distinguishes a retained backing allocation from an accidental copy.
        let byteCount = max(96, bytes.count)
        let pointer = UnsafeMutableRawPointer.allocate(
            byteCount: byteCount,
            alignment: MemoryLayout<UInt8>.alignment)
        pointer.initializeMemory(as: UInt8.self, repeating: 0, count: byteCount)
        bytes.withUnsafeBytes { source in
            pointer.copyMemory(from: source.baseAddress!, byteCount: bytes.count)
        }
        let probe = NoCopyLifetimeProbe()
        let data = Data(
            bytesNoCopy: pointer,
            count: byteCount,
            deallocator: .custom { pointer, _ in
                probe.markReleased()
                pointer.deallocate()
            })
        return (data, pointer, probe)
    }

    private func makePhysicalBudget() -> WriterMemoryBudget {
        WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 256,
                maxItems: 16,
                tcpWaiterMaxBytes: 128,
                udpPressureReserveBytes: 0,
                udpPressureReserveItems: 0))
    }

    /// Sink whose `onClientBytes` / `onEgressBytes` return a scripted
    /// status sequence (one per call; defaults to `.accepted` once
    /// exhausted) and records every chunk it was handed, in order.
    private final class ScriptedBytesSink:
        TcpClientBytesSink, NwEgressBytesSink, @unchecked Sendable
    {
        private let lock = NSLock()
        private var statuses: [RamaTcpDeliverStatusBridge]
        private var _received: [Data] = []
        private var _eofCount = 0
        private var _errorCount = 0

        init(_ statuses: [RamaTcpDeliverStatusBridge]) { self.statuses = statuses }

        private func next(_ data: Data) -> RamaTcpDeliverStatusBridge {
            lock.lock()
            defer { lock.unlock() }
            _received.append(data)
            return statuses.isEmpty ? .accepted : statuses.removeFirst()
        }
        func onClientBytes(_ data: Data) -> RamaTcpDeliverStatusBridge { next(data) }
        func onEgressBytes(_ data: Data) -> RamaTcpDeliverStatusBridge { next(data) }
        func onEgressEof() {
            lock.lock()
            _eofCount += 1
            lock.unlock()
        }
        func onEgressError() {
            lock.lock()
            _errorCount += 1
            lock.unlock()
        }

        var received: [Data] {
            lock.lock()
            defer { lock.unlock() }
            return _received
        }
        var eofCount: Int {
            lock.lock()
            defer { lock.unlock() }
            return _eofCount
        }
        var errorCount: Int {
            lock.lock()
            defer { lock.unlock() }
            return _errorCount
        }
    }

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.replay", qos: .utility)
    }

    func testAcceptedOwnedSliceKeepsNoCopyRootAndChargeUntilConsumerDrops() {
        let sink = OwnedSliceSink([.accepted], retainAccepted: true)
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let budget = makePhysicalBudget()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in },
            onTerminal: { _ in }, writerMemoryBudget: budget)
        pump.requestRead()
        pollUntil("accepted lifetime read pending") { flow.pendingReadCount == 1 }

        let source = autoreleasepool {
            var value = makeNoCopyData([0x11, 0x22, 0x33, 0x44])
            flow.completeReadSynchronously(data: value.data, error: nil)
            value.data = Data()
            return (pointer: value.pointer, probe: value.probe)
        }
        pollUntil("accepted slice retained") { sink.received.count == 1 }
        XCTAssertEqual(budget.snapshot().retainedBytes, 96)
        XCTAssertFalse(source.probe.released)
        XCTAssertTrue(sink.observedRootIsAlive)

        source.pointer.storeBytes(of: UInt8(0xA5), as: UInt8.self)
        var retained = sink.takeRetained()
        XCTAssertEqual(retained?.copiedData.first, 0xA5, "accepted view must share the root")
        retained = nil
        pollUntil("accepted root released") { budget.snapshot().retainedBytes == 0 }
        XCTAssertFalse(sink.observedRootIsAlive)
        withExtendedLifetime(pump) {}
    }

    func testClientReadSplitsOnePhysicalRootIntoBoundedFfiViews() {
        let sink = OwnedSliceSink([.accepted, .accepted, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 256, maxItems: 16, tcpWaiterMaxBytes: 32,
                udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in },
            onTerminal: { _ in }, writerMemoryBudget: budget)
        pump.requestRead()
        pollUntil("bounded view read pending") { flow.pendingReadCount == 1 }
        flow.completeRead(data: Data(repeating: 0x6A, count: 80), error: nil)
        pollUntil("all bounded views delivered") { sink.received.count == 3 }
        XCTAssertEqual(sink.received.map(\.count), [32, 32, 16])
        XCTAssertEqual(Data(sink.received.joined()), Data(repeating: 0x6A, count: 80))
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        withExtendedLifetime(pump) {}
    }

    func testClientReplayLogsOnlyInitialPausePerPhysicalCallback() {
        let repeatedPauses = 8
        let sink = OwnedSliceSink(
            [.accepted, .paused]
                + Array(repeating: .paused, count: repeatedPauses)
                + [.accepted, .paused, .accepted]
                + [.paused, .paused, .accepted, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 256, maxItems: 16, tcpWaiterMaxBytes: 32,
                udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        let diagnostics = TestValue<[String]>([])
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue,
            logger: { message in
                if message.level == .trace, message.text.contains("replay cursor occupied") {
                    diagnostics.update { $0.append(message.text) }
                }
            },
            onTerminal: { _ in }, writerMemoryBudget: budget)

        queue.sync { pump.requestRead() }
        XCTAssertEqual(flow.pendingReadCount, 1)
        let first = Data((0..<80).map(UInt8.init))
        flow.completeReadSynchronously(data: first, error: nil)
        queue.sync {}
        XCTAssertEqual(sink.received, [Data(first.prefix(32)), Data(first[32..<64])])
        XCTAssertEqual(diagnostics.get().count, 1)
        XCTAssertEqual(flow.pendingReadCount, 0)
        XCTAssertEqual(budget.snapshot().retainedBytes, first.count)

        for _ in 0..<repeatedPauses {
            queue.sync { pump.resume() }
            XCTAssertEqual(sink.received.last, Data(first[32..<64]))
            XCTAssertEqual(sink.accepted, [Data(first.prefix(32))])
            XCTAssertEqual(diagnostics.get().count, 1, "resumed pauses must not log")
            XCTAssertEqual(flow.pendingReadCount, 0)
            XCTAssertEqual(budget.snapshot().retainedBytes, first.count)
        }

        // Accept the middle view, then pause on the final view of the same root.
        queue.sync { pump.resume() }
        XCTAssertEqual(sink.received.last, Data(first.suffix(16)))
        XCTAssertEqual(Data(sink.accepted.joined()), Data(first.prefix(64)))
        XCTAssertEqual(diagnostics.get().count, 1, "later slices are still replay")
        XCTAssertEqual(flow.pendingReadCount, 0)
        XCTAssertEqual(budget.snapshot().retainedBytes, first.count)

        queue.sync { pump.resume() }
        XCTAssertEqual(Data(sink.accepted.joined()), first)
        XCTAssertEqual(sink.received.count, repeatedPauses + 5)
        XCTAssertEqual(flow.pendingReadCount, 1)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertFalse(sink.observedRootIsAlive)

        // A new physical callback may emit its own initial pause diagnostic.
        let second = Data((80..<128).map(UInt8.init))
        flow.completeReadSynchronously(data: second, error: nil)
        queue.sync {}
        XCTAssertEqual(sink.received.last, Data(second.prefix(32)))
        XCTAssertEqual(diagnostics.get().count, 2)
        XCTAssertEqual(flow.pendingReadCount, 0)
        XCTAssertEqual(budget.snapshot().retainedBytes, second.count)

        queue.sync { pump.resume() }
        XCTAssertEqual(sink.received.last, Data(second.prefix(32)))
        XCTAssertEqual(diagnostics.get().count, 2)
        XCTAssertEqual(flow.pendingReadCount, 0)
        XCTAssertEqual(budget.snapshot().retainedBytes, second.count)

        queue.sync { pump.resume() }
        XCTAssertEqual(Data(sink.accepted.joined()), first + second)
        XCTAssertEqual(sink.accepted.map(\.count), [32, 32, 16, 32, 16])
        XCTAssertEqual(diagnostics.get().count, 2)
        XCTAssertEqual(flow.pendingReadCount, 1)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertFalse(sink.observedRootIsAlive)
        withExtendedLifetime(pump) {}
    }

    func testPausedOwnedSliceRetainsNoCopyRootUntilReplayAccepts() {
        let sink = OwnedSliceSink([.paused, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let budget = makePhysicalBudget()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in },
            onTerminal: { _ in }, writerMemoryBudget: budget)
        pump.requestRead()
        pollUntil("paused lifetime read pending") { flow.pendingReadCount == 1 }

        let source = autoreleasepool {
            var value = makeNoCopyData([0x01, 0x02, 0x03])
            flow.completeReadSynchronously(data: value.data, error: nil)
            value.data = Data()
            return (pointer: value.pointer, probe: value.probe)
        }
        pollUntil("paused root retained") { sink.received.count == 1 }
        XCTAssertEqual(budget.snapshot().retainedBytes, 96)
        XCTAssertFalse(source.probe.released)
        XCTAssertTrue(sink.observedRootIsAlive)

        source.pointer.storeBytes(of: UInt8(0xFE), as: UInt8.self)
        pump.resume()
        pollUntil("paused root replayed") { sink.received.count == 2 }
        XCTAssertEqual(sink.received[1].first, 0xFE)
        pollUntil("replayed root released") { budget.snapshot().retainedBytes == 0 }
        XCTAssertFalse(sink.observedRootIsAlive)
        withExtendedLifetime(pump) {}
    }

    func testClosedOwnedSliceDropsNoCopyRootAndCharge() {
        var source = makeNoCopyData([0x71, 0x72])
        let sink = OwnedSliceSink(
            [.closed],
            beforeRead: {
                source.pointer.storeBytes(of: UInt8(0xE2), as: UInt8.self)
            })
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let budget = makePhysicalBudget()
        let terminal = TestValue(0)
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in },
            onTerminal: { _ in terminal.update { $0 += 1 } },
            writerMemoryBudget: budget)
        pump.requestRead()
        pollUntil("closed lifetime read pending") { flow.pendingReadCount == 1 }

        flow.completeReadSynchronously(data: source.data, error: nil)
        source.data = Data()
        pollUntil("closed root retired") { terminal.get() == 1 }
        XCTAssertEqual(sink.received.first?.first, 0xE2)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertFalse(sink.observedRootIsAlive)
        withExtendedLifetime(pump) {}
    }

    func testPromotionTransfersPausedNoCopyCursorWithoutRefundOrCopy() {
        let sink = OwnedSliceSink([.paused])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let budget = makePhysicalBudget()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in },
            onTerminal: { _ in }, writerMemoryBudget: budget)
        pump.requestRead()
        pollUntil("promotion lifetime read pending") { flow.pendingReadCount == 1 }

        let source = autoreleasepool {
            var value = makeNoCopyData([0x31, 0x32, 0x33])
            flow.completeReadSynchronously(data: value.data, error: nil)
            value.data = Data()
            return (pointer: value.pointer, probe: value.probe)
        }
        pollUntil("promotion source paused") { sink.received.count == 1 }

        let cursor = TestValue<TcpPayloadCursor?>(nil)
        let complete = expectation(description: "physical promotion barrier")
        pump.cancelForPromoteWithReservations(
            onCarryover: { cursor.set($0) },
            onComplete: { complete.fulfill() })
        wait(for: [complete], timeout: 2)
        XCTAssertEqual(budget.snapshot().retainedBytes, 96)
        XCTAssertFalse(source.probe.released)
        XCTAssertTrue(sink.observedRootIsAlive)

        source.pointer.storeBytes(of: UInt8(0xE1), as: UInt8.self)
        XCTAssertEqual(cursor.get()?.prefix(maxBytes: 64).copiedData.first, 0xE1)
        cursor.set(nil)
        pollUntil("promoted cursor root released") { budget.snapshot().retainedBytes == 0 }
        XCTAssertFalse(sink.observedRootIsAlive)
        withExtendedLifetime(pump) {}
    }

    // MARK: - Client read pump (ingress) replay

    /// On a `.paused` from the session the pump holds the chunk and stops
    /// issuing reads; `resume()` replays the SAME bytes BEFORE issuing the
    /// next read. A regression that dropped/duplicated/reordered the held
    /// bytes — or failed to gate the next read behind `resume()` — fails here.
    func testClientReadPumpPausedHoldsThenResumeReplaysInOrder() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let activityCount = TestValue(0)
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in },
            onTerminal: { _ in },
            onActivity: { activityCount.update { $0 += 1 } })

        pump.requestRead()
        pollUntil("pump issued first readData") { !flow.pendingReadCompletions.isEmpty }

        let chunk = Data([0x01, 0x02, 0x03, 0x04])
        flow.completeRead(data: chunk, error: nil)

        // Session returned .paused → pump holds the chunk and does NOT read again.
        pollUntil("chunk delivered to sink") { sink.received.count == 1 }
        queue.sync {}
        XCTAssertEqual(sink.received, [chunk])
        XCTAssertEqual(activityCount.get(), 1, "newly read chunk records one activity edge")
        XCTAssertTrue(
            flow.pendingReadCompletions.isEmpty,
            "a paused pump must NOT issue another readData until resume()")

        // resume() replays the held chunk first, then reads afresh.
        pump.resume()
        pollUntil("held chunk replayed on resume") { sink.received.count == 2 }
        XCTAssertEqual(
            sink.received, [chunk, chunk],
            "resume() must replay the exact held bytes before reading more")
        XCTAssertEqual(activityCount.get(), 1, "replay must not duplicate the activity edge")
        pollUntil("fresh readData issued after successful replay") {
            !flow.pendingReadCompletions.isEmpty
        }
        let nextChunk = Data([0x05])
        flow.completeRead(data: nextChunk, error: nil)
        pollUntil("next new chunk delivered") { sink.received.count == 3 }
        XCTAssertEqual(sink.received, [chunk, chunk, nextChunk])
        XCTAssertEqual(activityCount.get(), 2, "each new read records one activity edge")
    }

    func testClientReadPumpResumeRunsInlineWhenAlreadyOnFlowQueue() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in }, onTerminal: { _ in })

        pump.requestRead()
        pollUntil("client read is pending") { flow.pendingReadCount == 1 }
        let chunk = Data([0x31, 0x32])
        flow.completeRead(data: chunk, error: nil)
        pollUntil("client chunk is held") { sink.received.count == 1 }
        queue.sync {}

        queue.sync {
            pump.resume()
            XCTAssertEqual(
                sink.received, [chunk, chunk],
                "queue-local demand must replay before resume() returns")
            XCTAssertEqual(
                flow.pendingReadCount, 1,
                "a successful queue-local replay must synchronously request the next read")
        }
    }

    func testClientReadPumpResumeDispatchesWhenCalledOffFlowQueue() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in }, onTerminal: { _ in })

        pump.requestRead()
        pollUntil("client read is pending") { flow.pendingReadCount == 1 }
        let chunk = Data([0x33, 0x34])
        flow.completeRead(data: chunk, error: nil)
        pollUntil("client chunk is held") { sink.received.count == 1 }
        queue.sync {}

        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)

        pump.resume()
        XCTAssertEqual(
            sink.received, [chunk],
            "off-queue resume must not mutate queue-confined replay state inline")
        XCTAssertEqual(flow.pendingReadCount, 0)

        releaseBlocker.signal()
        pollUntil("off-queue resume replays and reads") {
            sink.received.count == 2 && flow.pendingReadCount == 1
        }
    }

    func testClientReadPublishesActivityBeforeItsQueueHop() {
        let sink = ScriptedBytesSink([.accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let activityCount = TestValue(0)
        let pump = TcpClientReadPump(
            flow: flow,
            session: sink,
            queue: queue,
            logger: { _ in },
            onTerminal: { _ in },
            onActivity: { activityCount.update { $0 += 1 } })
        pump.requestRead()
        pollUntil("client read is pending") { !flow.pendingReadCompletions.isEmpty }
        let gate = DispatchSemaphore(value: 0)
        queue.async { gate.wait() }

        flow.completeRead(data: Data([0x01]), error: nil)
        pollUntil("activity published before delivery") { activityCount.get() == 1 }
        XCTAssertTrue(sink.received.isEmpty, "delivery remains parked behind the queue gate")

        gate.signal()
        pollUntil("delivery resumes") { sink.received.count == 1 }
    }

    /// A `.paused` AGAIN on the replay attempt re-holds the same bytes (no
    /// duplication, no loss, no extra read) until the next resume.
    func testClientReadPumpRepausedReplayDoesNotDuplicateOrRead() {
        let sink = ScriptedBytesSink([.paused, .paused, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in }, onTerminal: { _ in })

        pump.requestRead()
        pollUntil("first readData") { !flow.pendingReadCompletions.isEmpty }
        let chunk = Data([0xAA, 0xBB])
        flow.completeRead(data: chunk, error: nil)
        pollUntil("delivered once") { sink.received.count == 1 }

        pump.resume()  // replay → .paused again → re-hold
        pollUntil("replayed once (still paused)") { sink.received.count == 2 }
        queue.sync {}
        XCTAssertEqual(sink.received, [chunk, chunk])
        XCTAssertTrue(
            flow.pendingReadCompletions.isEmpty, "still paused → no fresh read")

        pump.resume()  // replay → .accepted → read afresh
        pollUntil("replayed again, now accepted") { sink.received.count == 3 }
        XCTAssertEqual(sink.received, [chunk, chunk, chunk], "same bytes, never dropped or doubled")
        pollUntil("fresh read after accept") { !flow.pendingReadCompletions.isEmpty }
    }

    // MARK: - Egress read pump replay

    /// Egress (NWConnection-receive) counterpart of the client-pump replay.
    func testEgressReadPumpPausedHoldsThenResumeReplaysInOrder() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let activityCount = TestValue(0)
        let pump = NwTcpConnectionReadPump(
            connection: conn, session: sink, queue: queue,
            eofGraceDeadline: .seconds(60),
            onActivity: { activityCount.update { $0 += 1 } })

        pump.start()
        pollUntil("pump issued first receive") { conn.pendingReceiveCount == 1 }

        let chunk = Data([0x09, 0x08, 0x07])
        _ = conn.completePendingReceive(data: chunk, isComplete: false, error: nil)

        pollUntil("chunk delivered to sink") { sink.received.count == 1 }
        queue.sync {}
        XCTAssertEqual(sink.received, [chunk])
        XCTAssertEqual(activityCount.get(), 1, "new receive records one activity edge")
        XCTAssertEqual(
            conn.pendingReceiveCount, 0, "a paused egress pump must NOT issue another receive")

        pump.resume()
        pollUntil("held chunk replayed on resume") { sink.received.count == 2 }
        XCTAssertEqual(sink.received, [chunk, chunk], "replay the exact held bytes first")
        XCTAssertEqual(activityCount.get(), 1, "replay must not duplicate the activity edge")
        pollUntil("fresh receive after replay") { conn.pendingReceiveCount == 1 }
        let nextChunk = Data([0x06])
        _ = conn.completePendingReceive(data: nextChunk, isComplete: false, error: nil)
        pollUntil("next new chunk delivered") { sink.received.count == 3 }
        XCTAssertEqual(sink.received, [chunk, chunk, nextChunk])
        XCTAssertEqual(activityCount.get(), 2, "each new receive records one activity edge")
    }

    func testEgressReadPumpResumeRunsInlineWhenAlreadyOnFlowQueue() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionReadPump(
            connection: conn,
            session: sink,
            queue: queue,
            eofGraceDeadline: .seconds(60))

        pump.start()
        pollUntil("egress receive is pending") { conn.pendingReceiveCount == 1 }
        let chunk = Data([0x41, 0x42])
        XCTAssertTrue(
            conn.completePendingReceive(data: chunk, isComplete: false, error: nil))
        pollUntil("egress chunk is held") { sink.received.count == 1 }
        queue.sync {}

        queue.sync {
            pump.resume()
            XCTAssertEqual(
                sink.received, [chunk, chunk],
                "queue-local demand must replay before resume() returns")
            XCTAssertEqual(
                conn.pendingReceiveCount, 1,
                "a successful queue-local replay must synchronously issue the next receive")
        }
    }

    func testEgressReadPumpResumeDispatchesWhenCalledOffFlowQueue() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionReadPump(
            connection: conn,
            session: sink,
            queue: queue,
            eofGraceDeadline: .seconds(60))

        pump.start()
        pollUntil("egress receive is pending") { conn.pendingReceiveCount == 1 }
        let chunk = Data([0x43, 0x44])
        XCTAssertTrue(
            conn.completePendingReceive(data: chunk, isComplete: false, error: nil))
        pollUntil("egress chunk is held") { sink.received.count == 1 }
        queue.sync {}

        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)

        pump.resume()
        XCTAssertEqual(
            sink.received, [chunk],
            "off-queue resume must not mutate queue-confined replay state inline")
        XCTAssertEqual(conn.pendingReceiveCount, 0)

        releaseBlocker.signal()
        pollUntil("off-queue resume replays and receives") {
            sink.received.count == 2 && conn.pendingReceiveCount == 1
        }
    }

    func testEgressReceiveOnFlowQueueProcessesInlineAndRearmsInOrder() {
        let sink = ScriptedBytesSink([.accepted])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionReadPump(
            connection: conn,
            session: sink,
            queue: queue,
            eofGraceDeadline: .seconds(60))

        pump.start()
        pollUntil("egress receive is pending") { conn.pendingReceiveCount == 1 }
        let chunk = Data([0x51, 0x52])

        queue.sync {
            XCTAssertTrue(
                conn.completePendingReceive(data: chunk, isComplete: false, error: nil))
            XCTAssertEqual(
                sink.received, [chunk],
                "a Network.framework callback on the start queue must be consumed inline")
            XCTAssertEqual(
                conn.pendingReceiveCount, 1,
                "the next receive must be armed before the inline callback returns")
        }
    }

    func testEgressReceivePublishesActivityBeforeItsQueueHop() {
        let sink = ScriptedBytesSink([.accepted])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let activityCount = TestValue(0)
        let pump = NwTcpConnectionReadPump(
            connection: conn,
            session: sink,
            queue: queue,
            eofGraceDeadline: .seconds(60),
            onActivity: { activityCount.update { $0 += 1 } })
        pump.start()
        pollUntil("egress receive is pending") { conn.pendingReceiveCount == 1 }
        let gate = DispatchSemaphore(value: 0)
        queue.async { gate.wait() }

        XCTAssertTrue(
            conn.completePendingReceive(
                data: Data([0x02]),
                isComplete: false,
                error: nil))
        pollUntil("activity published before delivery") { activityCount.get() == 1 }
        XCTAssertTrue(sink.received.isEmpty, "delivery remains parked behind the queue gate")
        XCTAssertEqual(
            conn.pendingReceiveCount, 0,
            "an off-queue mock completion must dispatch before delivering or rearming")

        gate.signal()
        pollUntil("delivery resumes") { sink.received.count == 1 }
        XCTAssertEqual(conn.pendingReceiveCount, 1)
    }

    func testClientReadTransitAcrossBlockedRetiringQueuesSharesOneEnvelope() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 8, maxItems: 2, tcpWaiterMaxBytes: 4,
                udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        let firstSink = ScriptedBytesSink([.accepted])
        let secondSink = ScriptedBytesSink([.accepted])
        let firstFlow = MockTcpFlow()
        let secondFlow = MockTcpFlow()
        let firstQueue = DispatchQueue(label: "rama.tproxy.read-transit.retired.first")
        let secondQueue = DispatchQueue(label: "rama.tproxy.read-transit.retired.second")
        let secondTerminated = expectation(description: "second transit denied")
        let first = TcpClientReadPump(
            flow: firstFlow, session: firstSink, queue: firstQueue,
            logger: { _ in }, onTerminal: { _ in },
            writerMemoryBudget: budget)
        let second = TcpClientReadPump(
            flow: secondFlow, session: secondSink, queue: secondQueue,
            logger: { _ in }, onTerminal: { error in
                XCTAssertNotNil(error)
                secondTerminated.fulfill()
            }, writerMemoryBudget: budget)
        first.requestRead()
        second.requestRead()
        pollUntil("both generations issued reads") {
            firstFlow.pendingReadCount == 1 && secondFlow.pendingReadCount == 1
        }

        let firstGate = DispatchSemaphore(value: 0)
        let secondGate = DispatchSemaphore(value: 0)
        let gatesEntered = expectation(description: "both flow queues blocked")
        gatesEntered.expectedFulfillmentCount = 2
        firstQueue.async { gatesEntered.fulfill(); firstGate.wait() }
        secondQueue.async { gatesEntered.fulfill(); secondGate.wait() }
        wait(for: [gatesEntered], timeout: 3)

        firstFlow.completeRead(data: Data(repeating: 1, count: 4), error: nil)
        pollUntil("first callback transit charged") {
            budget.snapshot().retainedBytes == 4
        }
        secondFlow.completeRead(data: Data(repeating: 2, count: 4), error: nil)
        Thread.sleep(forTimeInterval: 0.02)
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        XCTAssertTrue(secondSink.received.isEmpty)

        firstGate.signal()
        secondGate.signal()
        wait(for: [secondTerminated], timeout: 3)
        pollUntil("first transit consumed and released") {
            firstSink.received.count == 1 && budget.snapshot().retainedBytes == 0
        }
        withExtendedLifetime((first, second)) {}
    }

    func testOffQueueEgressTransitIsChargedUntilQueuedDeliveryConsumesIt() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 8, maxItems: 2, tcpWaiterMaxBytes: 4,
                udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        let sink = ScriptedBytesSink([.accepted])
        let connection = MockNwConnection()
        let queue = DispatchQueue(label: "rama.tproxy.egress-transit")
        let pump = NwTcpConnectionReadPump(
            connection: connection,
            session: sink,
            queue: queue,
            eofGraceDeadline: .seconds(60),
            writerMemoryBudget: budget)
        pump.start()
        pollUntil("egress receive issued") { connection.pendingReceiveCount == 1 }

        let entered = expectation(description: "egress queue blocked")
        let gate = DispatchSemaphore(value: 0)
        queue.async { entered.fulfill(); gate.wait() }
        wait(for: [entered], timeout: 3)
        XCTAssertTrue(connection.completePendingReceive(
            data: Data(repeating: 3, count: 4), isComplete: false))
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        gate.signal()
        pollUntil("off-queue transit consumed") {
            sink.received.count == 1 && budget.snapshot().retainedBytes == 0
        }
        withExtendedLifetime(pump) {}
    }

    func testClientPromotionCompletesWhenTransitAdmissionFails() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        XCTAssertTrue(budget.tryReserve(bytes: 4))
        let sink = ScriptedBytesSink([.accepted])
        let flow = MockTcpFlow()
        let queue = DispatchQueue(label: "rama.tproxy.client-promote-pressure")
        let terminalCount = TestValue(0)
        let errorCount = TestValue(0)
        let carryoverCount = TestValue(0)
        let completeCount = TestValue(0)
        let pump = TcpClientReadPump(
            flow: flow,
            session: sink,
            queue: queue,
            logger: { _ in },
            onTerminal: { _ in terminalCount.update { $0 += 1 } },
            writerMemoryBudget: budget)
        pump.requestRead()
        pollUntil("client read is pending before promotion") {
            flow.pendingReadCount == 1
        }

        queue.sync {
            pump.cancelForPromote(
                onCarryover: { _ in carryoverCount.update { $0 += 1 } },
                onError: { _ in errorCount.update { $0 += 1 } },
                onComplete: { completeCount.update { $0 += 1 } })
        }
        XCTAssertEqual(completeCount.get(), 0)

        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 3), .success)
        flow.completeRead(data: Data([0xA1]), error: nil)
        XCTAssertEqual(completeCount.get(), 0)

        releaseBlocker.signal()
        pollUntil("client promotion pressure result completes") {
            completeCount.get() == 1
        }
        queue.sync {}
        XCTAssertEqual(errorCount.get(), 1)
        XCTAssertEqual(carryoverCount.get(), 0)
        XCTAssertEqual(terminalCount.get(), 0)
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        budget.release(bytes: 4)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        withExtendedLifetime(pump) {}
    }

    func testEgressPromotionCompletesWhenOffQueueTransitAdmissionFails() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        XCTAssertTrue(budget.tryReserve(bytes: 4))
        let sink = ScriptedBytesSink([.accepted])
        let connection = MockNwConnection()
        connection.transition(to: .ready)
        let queue = DispatchQueue(label: "rama.tproxy.egress-promote-pressure")
        let abnormalStopCount = TestValue(0)
        let errorCount = TestValue(0)
        let eofCount = TestValue(0)
        let completeCount = TestValue(0)
        let pump = NwTcpConnectionReadPump(
            connection: connection,
            session: sink,
            queue: queue,
            eofGraceDeadline: .seconds(60),
            onAbnormalStop: { _ in abnormalStopCount.update { $0 += 1 } },
            writerMemoryBudget: budget)
        pump.start()
        pollUntil("egress receive is pending before promotion") {
            connection.pendingReceiveCount == 1
        }

        queue.sync {
            pump.cancelForPromote(
                onCarryover: { payload in
                    if payload == nil { eofCount.update { $0 += 1 } }
                },
                onError: { _ in errorCount.update { $0 += 1 } },
                onComplete: { completeCount.update { $0 += 1 } })
        }
        XCTAssertEqual(completeCount.get(), 0)

        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 3), .success)
        XCTAssertTrue(connection.completePendingReceive(
            data: Data([0xB1]), isComplete: false, error: nil))
        XCTAssertEqual(completeCount.get(), 0)

        releaseBlocker.signal()
        pollUntil("egress promotion pressure result completes") {
            completeCount.get() == 1
        }
        queue.sync {}
        XCTAssertEqual(errorCount.get(), 1)
        XCTAssertEqual(eofCount.get(), 1)
        XCTAssertEqual(abnormalStopCount.get(), 0)
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        budget.release(bytes: 4)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        withExtendedLifetime(pump) {}
    }

    func testEgressPromotionPreservesTransitFailureObservedBeforeCutover() {
        assertEgressPromotionPreservesAbnormalStop(exhaustTransitBudget: true)
    }

    func testEgressPromotionPreservesClosedConsumerFailureObservedBeforeCutover() {
        assertEgressPromotionPreservesAbnormalStop(exhaustTransitBudget: false)
    }

    /// The inverse of the in-flight promotion race above: the read pump has
    /// already discarded a payload and armed its failure backstop when cutover
    /// arrives. That stop must be visible to the core and replay its error if a
    /// defensive caller nevertheless takes the pump's promotion handoff.
    private func assertEgressPromotionPreservesAbnormalStop(
        exhaustTransitBudget: Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let budget = makePhysicalBudget()
        if exhaustTransitBudget { XCTAssertTrue(budget.tryReserve(bytes: 256)) }
        defer {
            if exhaustTransitBudget { budget.release(bytes: 256) }
        }
        let sink = ScriptedBytesSink(exhaustTransitBudget ? [.accepted] : [.closed])
        let connection = MockNwConnection()
        connection.transition(to: .ready)
        let queue = DispatchQueue(label: "rama.tproxy.egress-promote-after-abnormal-stop")
        let ctx = TcpFlowContext()
        let events = TestValue<[String]>([])
        let carryoverError = TestValue<NSError?>(nil)
        let pump = NwTcpConnectionReadPump(
            connection: connection,
            session: sink,
            queue: queue,
            eofGraceDeadline: .seconds(60),
            onTerminalObserved: {
                ctx.terminalSignalled = true
                events.update { $0.append("observed") }
            },
            onReadError: { _ in events.update { $0.append("read-error") } },
            onAbnormalStop: { _ in events.update { $0.append("backstop") } },
            writerMemoryBudget: budget)
        pump.start()
        pollUntil("egress receive is pending before abnormal stop") {
            connection.pendingReceiveCount == 1
        }
        XCTAssertTrue(connection.completePendingReceive(
            data: Data([0xC1, 0xC2]), isComplete: false))
        queue.sync {
            XCTAssertTrue(pump.isEofBackstopArmed, file: file, line: line)
            XCTAssertTrue(
                ctx.terminalSignalled,
                "the core must reject promotion after a payload was discarded",
                file: file, line: line)
            pump.cancelForPromote(
                onCarryover: { payload in
                    events.update { $0.append(payload == nil ? "eof" : "data") }
                },
                onError: { error in
                    carryoverError.set(error as NSError)
                    events.update { $0.append("error") }
                },
                onComplete: { events.update { $0.append("complete") } })
            XCTAssertFalse(pump.isEofBackstopArmed, file: file, line: line)
            pump.cancelForPromote(
                onCarryover: { _ in events.update { $0.append("duplicate-eof") } },
                onError: { _ in events.update { $0.append("duplicate-error") } },
                onComplete: { events.update { $0.append("complete-again") } })
        }
        XCTAssertEqual(
            events.get(),
            ["observed", "read-error", "error", "eof", "complete", "complete-again"],
            file: file, line: line)
        XCTAssertEqual(
            carryoverError.get()?.domain,
            exhaustTransitBudget ? "rama.tproxy.writer-memory" : "rama.tproxy.egress-read",
            file: file, line: line)
        XCTAssertEqual(connection.pendingReceiveCount, 0, file: file, line: line)
        XCTAssertEqual(sink.errorCount, 1, file: file, line: line)
        withExtendedLifetime((pump, sink)) {}
    }

    // MARK: - cancelForPromote hands the held replay buffer to carryover

    /// When a promote cutover hits a pump that is holding a `.paused` chunk,
    /// `cancelForPromote` MUST hand that chunk to `onCarryover` before the
    /// barrier fires — otherwise the buffered bytes are lost across the
    /// cutover (the gap the degenerate carryover test couldn't reach).
    func testClientReadPumpCancelForPromoteFlushesHeldReplayBuffer() {
        let sink = ScriptedBytesSink([.paused])  // first delivery pauses → held
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in }, onTerminal: { _ in })

        pump.requestRead()
        pollUntil("first readData") { !flow.pendingReadCompletions.isEmpty }
        let held = Data([0x11, 0x22, 0x33])
        flow.completeRead(data: held, error: nil)
        pollUntil("chunk held as pendingData") { sink.received.count == 1 }
        queue.sync {}

        let result = TestValue((carryover: [Data](), sawNoneSentinel: false))
        let completeFired = expectation(description: "onComplete barrier fires")
        pump.cancelForPromote(
            onCarryover: { payload in
                result.update {
                    if let payload { $0.carryover.append(payload) } else { $0.sawNoneSentinel = true }
                }
            },
            onComplete: { completeFired.fulfill() })
        wait(for: [completeFired], timeout: 2.0)
        queue.sync {}

        XCTAssertEqual(
            result.get().carryover, [held],
            "the held .paused replay buffer must be handed to carryover, intact and in order")
        XCTAssertFalse(result.get().sawNoneSentinel, "no EOF sentinel — the pump was paused, not at EOF")
    }

    /// Egress counterpart of the carryover-flush test.
    func testEgressReadPumpCancelForPromoteFlushesHeldReplayBuffer() {
        let sink = ScriptedBytesSink([.paused])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionReadPump(
            connection: conn, session: sink, queue: queue, eofGraceDeadline: .seconds(60))

        pump.start()
        pollUntil("first receive") { conn.pendingReceiveCount == 1 }
        let held = Data([0x44, 0x55])
        _ = conn.completePendingReceive(data: held, isComplete: false, error: nil)
        pollUntil("chunk held as pendingData") { sink.received.count == 1 }
        queue.sync {}

        let carryover = TestValue<[Data]>([])
        let completeFired = expectation(description: "onComplete barrier fires")
        pump.cancelForPromote(
            onCarryover: { payload in
                if let payload { carryover.update { $0.append(payload) } }
            },
            onComplete: { completeFired.fulfill() })
        wait(for: [completeFired], timeout: 2.0)
        queue.sync {}

        XCTAssertEqual(carryover.get(), [held], "egress held replay buffer handed to carryover intact")
    }
}
