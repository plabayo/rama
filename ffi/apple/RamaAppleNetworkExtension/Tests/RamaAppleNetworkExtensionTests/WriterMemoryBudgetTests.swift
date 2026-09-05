import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

final class WriterMemoryBudgetTests: XCTestCase {
    private final class RetainingReadSink: TcpClientBytesSink {
        let payload = TestValue<TcpPayloadSlice?>(nil)

        func onClientBytes(_ data: Data) -> RamaTcpDeliverStatusBridge {
            XCTFail("the read pump must transfer its physical payload owner")
            return .closed
        }

        func onClientPayload(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge {
            self.payload.set(payload)
            return .accepted
        }
    }

    private func observedNoCopyPayload(count: Int, events: TestValue<[String]>) -> Data {
        let pointer = UnsafeMutableRawPointer.allocate(
            byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        pointer.initializeMemory(as: UInt8.self, repeating: 0xA7, count: count)
        return Data(
            bytesNoCopy: pointer,
            count: count,
            deallocator: .custom { pointer, _ in
                pointer.deallocate()
                events.update { $0.append("payload destroyed") }
            })
    }

    func testWriterRootDestroysPhysicalPayloadBeforeBudgetRefund() {
        let byteCount = 96 // Keep Data out of its inline representation.
        let budget = WriterMemoryBudget()
        let events = TestValue<[String]>([])
        budget.testAfterReleaseBeforeCoordinatorKick = { [weak budget] in
            XCTAssertEqual(events.get(), ["payload destroyed"])
            XCTAssertEqual(budget?.snapshot().retainedBytes, 0)
            XCTAssertEqual(budget?.snapshot().retainedItems, 0)
            events.update { $0.append("budget refunded") }
        }
        defer { budget.testAfterReleaseBeforeCoordinatorKick = nil }

        // End the source Data and bridging temporaries' lifetimes before
        // checking the root. The final release below happens outside this
        // pool, so pool drainage cannot conceal an early budget refund.
        var payload: TcpPayloadSlice? = autoreleasepool {
            let data = observedNoCopyPayload(count: byteCount, events: events)
            XCTAssertTrue(budget.tryReserve(bytes: byteCount))
            return budget.makePregrantedWriterPayload(data)
        }
        var clone = payload
        withExtendedLifetime(clone) {
            payload = nil
            XCTAssertEqual(events.get(), [], "a cloned slice must retain the no-copy storage")
            XCTAssertEqual(budget.snapshot().retainedBytes, byteCount)
            XCTAssertEqual(budget.snapshot().retainedItems, 1)
        }

        clone = nil
        XCTAssertEqual(events.get(), ["payload destroyed", "budget refunded"])
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testTcpTransitRootDestroysPhysicalPayloadBeforeBudgetRefund() {
        let byteCount = 96
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 256, maxItems: 4, tcpWaiterMaxBytes: 32,
                udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        let events = TestValue<[String]>([])
        budget.testAfterReleaseBeforeCoordinatorKick = { [weak budget] in
            XCTAssertEqual(events.get(), ["payload destroyed"])
            XCTAssertEqual(budget?.testTcpTransitSnapshot.retainedBytes, 0)
            XCTAssertEqual(budget?.testTcpTransitSnapshot.retainedItems, 0)
            XCTAssertEqual(budget?.snapshot().retainedBytes, 0)
            XCTAssertEqual(budget?.snapshot().retainedItems, 0)
            events.update { $0.append("budget refunded") }
        }
        defer { budget.testAfterReleaseBeforeCoordinatorKick = nil }

        var cursor: TcpPayloadCursor? = autoreleasepool {
            budget.makeTcpTransitCursor(observedNoCopyPayload(count: byteCount, events: events))
        }
        XCTAssertNotNil(cursor)
        var clonedCursor = cursor
        var slice = cursor?.prefix(maxBytes: 32)
        cursor = nil
        withExtendedLifetime(clonedCursor) {
            slice = nil
            XCTAssertEqual(events.get(), [], "the cursor clone must retain the complete root")
            XCTAssertEqual(budget.snapshot().retainedBytes, byteCount)
            XCTAssertEqual(budget.testTcpTransitSnapshot.retainedBytes, byteCount)
        }

        slice = clonedCursor?.prefix(maxBytes: 32)
        withExtendedLifetime(slice) {
            clonedCursor = nil
            XCTAssertEqual(slice?.count, 32)
            XCTAssertEqual(events.get(), [], "a partial view must retain the complete backing allocation")
            XCTAssertEqual(budget.snapshot().retainedBytes, byteCount)
            XCTAssertEqual(budget.snapshot().retainedItems, 1)
            XCTAssertEqual(budget.testTcpTransitSnapshot.retainedBytes, byteCount)
            XCTAssertEqual(budget.testTcpTransitSnapshot.retainedItems, 1)
        }

        slice = nil
        XCTAssertEqual(events.get(), ["payload destroyed", "budget refunded"])
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
        XCTAssertEqual(budget.testTcpTransitSnapshot.retainedBytes, 0)
        XCTAssertEqual(budget.testTcpTransitSnapshot.retainedItems, 0)
    }

    func testMinimumByteBudgetDeliversTcpWhileMaximumWriterAndUdpProgress() {
        assertMinimumTransportCapacity(maxBytes: 8 * 1024 * 1024 + 128 * 1024)
    }

    func testMinimumItemBudgetDeliversTcpWhileMaximumWriterAndUdpProgress() {
        assertMinimumTransportCapacity(maxItems: 256)
    }

    func testCombinedMinimumBudgetDeliversTcpWhileMaximumWriterAndUdpProgress() {
        assertMinimumTransportCapacity(
            maxBytes: 8 * 1024 * 1024 + 128 * 1024, maxItems: 256)
    }

    func testReconfiguredMinimumBudgetDeliversTcpWhileMaximumWriterAndUdpProgress() {
        assertMinimumTransportCapacity(
            maxBytes: 8 * 1024 * 1024 + 128 * 1024,
            maxItems: 256,
            reconfigure: true)
    }

    private func assertMinimumTransportCapacity(
        maxBytes: Int = WriterMemoryPolicy.default.maxBytes,
        maxItems: Int = WriterMemoryPolicy.default.maxItems,
        reconfigure: Bool = false
    ) {
        // These are the public Rust configuration bounds, not a reduced
        // test-only reserve. Exercise the production policy constructor and
        // actual read pump before checking the pressure coordinator.
        let maximumWriterBytes = 8 * 1024 * 1024
        let policy = TransparentProxyRuntimePolicy(
            tcpWritePumpMaxPendingBytes: maximumWriterBytes,
            flowPressureSoftCap: 450,
            flowPressureLowWater: 350,
            flowPressureIdleFloorMs: 120_000,
            liveFlowHardCap: 500,
            udpIdleTimeoutMs: 30_000,
            tcpStartInFlightHardCap: 128,
            tcpStartInFlightSoftCap: 64,
            tcpStartLatencyBreakerP95Ms: 0,
            tcpStartLatencyBreakerCloseP95Ms: 0,
            tcpPressureConnectTimeoutMs: 0,
            tcpBreakerConnectTimeoutMs: 0,
            flowRefusalPassthrough: true,
            writerMemoryMaxBytes: maxBytes,
            writerMemoryMaxItems: maxItems)
        XCTAssertEqual(policy.tcpWritePump.maxPendingBytes, maximumWriterBytes)
        let budget = WriterMemoryBudget(policy: reconfigure ? .default : policy.writerMemory)
        if reconfigure { budget.reconfigure(policy: policy.writerMemory) }

        let queue = DispatchQueue(label: "rama.writer-budget.minimum.read")
        let flow = MockTcpFlow()
        let sink = RetainingReadSink()
        let terminalCount = TestValue(0)
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in },
            onTerminal: { _ in terminalCount.update { $0 += 1 } },
            writerMemoryBudget: budget)
        queue.sync { pump.requestRead() }
        let readData = Data(repeating: 0xA7, count: 64 * 1024)
        flow.completeReadSynchronously(data: readData, error: nil)
        queue.sync {}
        XCTAssertEqual(terminalCount.get(), 0, "an empty budget must accept a normal TCP read")
        XCTAssertEqual(sink.payload.get()?.copiedData, readData)
        guard sink.payload.get() != nil else { return }
        XCTAssertEqual(budget.snapshot().retainedBytes, readData.count)

        // Keep that real read root live while a maximum TCP retry waits. The
        // UDP charge represents one maximum-size datagram and zero-length
        // datagrams filling the remaining service item reserve.
        let fillerBytes = maxBytes - readData.count - policy.writerMemory.udpPressureReserveBytes
        XCTAssertTrue(budget.tryReserve(bytes: fillerBytes))
        let granted = expectation(description: "maximum TCP retry progresses beside retained read")
        let grantBox = TestValue<WriterMemoryGrant?>(nil)
        let waiter = budget.waitForTcpCapacity(bytes: maximumWriterBytes) { grant in
            grantBox.set(grant)
            granted.fulfill()
        }
        defer { waiter.cancel() }
        let udpBytes = Int(UInt16.max)
        let udpItems = policy.writerMemory.udpPressureReserveItems
        guard case .pressureUdp? = budget.tryReserveUdp(bytes: udpBytes, items: udpItems) else {
            budget.release(bytes: fillerBytes)
            sink.payload.set(nil)
            return XCTFail("maximum UDP datagram must fit while the TCP retry is waiting")
        }
        budget.release(bytes: fillerBytes)
        wait(for: [granted], timeout: 3)
        XCTAssertEqual(budget.snapshot().retainedBytes, readData.count + maximumWriterBytes + udpBytes)
        XCTAssertEqual(budget.snapshot().retainedItems, udpItems + 2)
        if maxItems == 256 {
            XCTAssertEqual(budget.snapshot().retainedItems, maxItems)
            XCTAssertNil(budget.tryReserveUdp(bytes: 0), "the aggregate item bound still holds")
        }
        XCTAssertEqual(sink.payload.get()?.copiedData, readData)

        grantBox.update { grant in
            grant?.release()
            grant = nil
        }
        budget.releaseUdp(
            bytes: udpBytes, items: udpItems, pressureBytes: udpBytes, pressureItems: udpItems)
        sink.payload.set(nil)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testCanceledHeadMiddleAndTailPreserveFifoAcrossGrantBatches() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 100,
                maxItems: 100,
                tcpWaiterMaxBytes: 1,
                udpPressureReserveBytes: 0,
                udpPressureReserveItems: 0))
        XCTAssertTrue(budget.tryReserve(bytes: 100))
        let order = Locked<[Int]>([])
        let delivered = expectation(description: "surviving FIFO waiters")
        delivered.expectedFulfillmentCount = 9
        var waiters: [WriterMemoryWaiter] = []
        for index in 0..<12 {
            waiters.append(budget.waitForTcpCapacity(bytes: 1) { grant in
                order.withLock { $0.append(index) }
                grant.release()
                delivered.fulfill()
            })
        }
        for index in [0, 5, 11, 9] { waiters[index].cancel() }
        waiters.append(budget.waitForTcpCapacity(bytes: 1) { grant in
            order.withLock { $0.append(12) }
            grant.release()
            delivered.fulfill()
        })
        budget.release(bytes: 100)
        wait(for: [delivered], timeout: 3)
        withExtendedLifetime(waiters) {
            XCTAssertEqual(order.withLock { $0 }, [1, 2, 3, 4, 6, 7, 8, 10, 12])
            XCTAssertEqual(budget.testWaiterCount, 0)
            XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        }
    }

    func testCanceledTailWaitersKeepCoordinatorStorageBoundedBehindBlockedHead() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 4_096,
                maxItems: 4_096,
                tcpWaiterMaxBytes: 1_024,
                udpPressureReserveBytes: 0,
                udpPressureReserveItems: 0))
        XCTAssertTrue(budget.tryReserve(bytes: 4_096))
        let oldest = budget.waitForTcpCapacity(bytes: 1_024) { _ in
            XCTFail("the oldest waiter cannot fit while the holder owns the budget")
        }
        defer {
            oldest.cancel()
            budget.release(bytes: 4_096)
        }

        // Connection churn can retire arbitrarily many later pumps while the
        // same oldest retry remains blocked. The live-flow cap bounds the
        // dictionary, so queue metadata must follow the live population too.
        for _ in 0..<32_768 {
            let canceled = budget.waitForTcpCapacity(bytes: 1_024) { _ in
                XCTFail("a canceled waiter must never receive a grant")
            }
            canceled.cancel()
        }
        XCTAssertEqual(budget.testWaiterCount, 1)
        XCTAssertLessThanOrEqual(
            budget.testCoordinatorNodeCount,
            64 + 2 * budget.testWaiterCount,
            "canceled waiter IDs must not accumulate behind a blocked live head")
    }

    func testHealthyAdmissionAtomicIsLockFreeAndHasNoPressureSideEffects() {
        let pressureEvents = Locked(0)
        let budget = WriterMemoryBudget(
            onPressureEvent: { _ in pressureEvents.withLock { $0 += 1 } })
        XCTAssertTrue(
            budget.testCapacityAtomicIsLockFree,
            "the packed capacity CAS must be lock-free on the Apple target")

        let iterations = 200_000
        let started = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<iterations {
            XCTAssertTrue(budget.tryReserve(bytes: 1))
            budget.release(bytes: 1)
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds - started
        let nanosPerReserveRelease = Double(elapsed) / Double(iterations)
        print(
            "writer-memory healthy reserve+release mean_ns=\(nanosPerReserveRelease) iterations=\(iterations)")
        XCTAssertEqual(budget.testWaiterCount, 0)
        XCTAssertEqual(pressureEvents.withLock { $0 }, 0)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
    }

    func testReportTokenizedTcpAdmissionCostAgainstHistoricalQueueShape() {
        let batches = 100
        let samples = batches * tcpWritePumpMaxPendingItems
        let payload = Data([0xA5])
        let currentQueue = DispatchQueue(label: "rama.writer-budget.perf.current")
        let currentGate = DispatchSemaphore(value: 0)
        currentQueue.async { currentGate.wait() }
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: samples + 1,
                maxItems: samples + 1,
                tcpWaiterMaxBytes: 1,
                udpPressureReserveBytes: 0,
                udpPressureReserveItems: 0))
        var cores: [TcpWritePumpCore] = []
        cores.reserveCapacity(batches)
        var correctedNanos: UInt64 = 0
        for _ in 0..<batches {
            let core = TcpWritePumpCore(
                queue: currentQueue,
                initialLifecycle: .pending,
                onDrained: {},
                doWrite: { _, _ in XCTFail("pending benchmark core must not write") },
                logHwm: { _ in },
                writerMemoryBudget: budget,
                writePolicy: TcpWritePumpPolicy(maxPendingBytes: tcpWritePumpMaxPendingItems))
            let start = DispatchTime.now().uptimeNanoseconds
            for _ in 0..<tcpWritePumpMaxPendingItems {
                XCTAssertEqual(core.enqueue(payload), .accepted)
            }
            correctedNanos += DispatchTime.now().uptimeNanoseconds - start
            cores.append(core)
        }

        // Historical shape: the existing per-pump lock/accounting plus one
        // dispatch capture, without the new aggregate CAS + ARC owner.
        let legacyQueue = DispatchQueue(label: "rama.writer-budget.perf.legacy")
        let legacyGate = DispatchSemaphore(value: 0)
        legacyQueue.async { legacyGate.wait() }
        let legacyState = Locked((bytes: 0, items: 0))
        let legacyStart = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<samples {
            legacyState.withLock {
                $0.bytes += payload.count
                $0.items += 1
            }
            legacyQueue.async { _ = payload }
        }
        let legacyNanos = DispatchTime.now().uptimeNanoseconds - legacyStart
        let correctedMean = Double(correctedNanos) / Double(samples)
        let legacyMean = Double(legacyNanos) / Double(samples)
        print(
            "writer-memory enqueue mean_ns corrected=\(correctedMean) historical_shape=\(legacyMean) samples=\(samples)")
        XCTAssertLessThan(correctedMean, 100_000)

        currentGate.signal()
        legacyGate.signal()
        currentQueue.sync {}
        legacyQueue.sync {}
        for core in cores {
            currentQueue.sync(execute: core.prepareCancel())
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
    }

    func testWriterEnvelopeRemainsBoundedWhenLiveFlowHardCapIsDisabled() {
        let policy = TransparentProxyRuntimePolicy(
            tcpWritePumpMaxPendingBytes: 1_024,
            flowPressureSoftCap: 0,
            flowPressureLowWater: 0,
            flowPressureIdleFloorMs: 1_000,
            liveFlowHardCap: 0,
            udpIdleTimeoutMs: 0,
            tcpStartInFlightHardCap: 0,
            tcpStartInFlightSoftCap: 0,
            tcpStartLatencyBreakerP95Ms: 0,
            tcpStartLatencyBreakerCloseP95Ms: 0,
            tcpPressureConnectTimeoutMs: 0,
            tcpBreakerConnectTimeoutMs: 0,
            flowRefusalPassthrough: true,
            writerMemoryMaxBytes: 8 * 1024 * 1024,
            writerMemoryMaxItems: 4_096)

        XCTAssertEqual(policy.writerMemory.maxBytes, 8 * 1024 * 1024)
        XCTAssertEqual(policy.writerMemory.maxItems, 4_096)
    }

    func testConcurrentReservationsNeverCrossPackedByteOrItemLimits() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4_096, maxItems: 128))
        let successes = Locked(0)
        let group = DispatchGroup()

        for worker in 0..<16 {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                _ = worker
                while budget.tryReserve(bytes: 32) {
                    successes.withLock { $0 += 1 }
                }
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 3), .success)

        let count = successes.withLock { $0 }
        XCTAssertEqual(count, 128)
        XCTAssertEqual(
            budget.snapshot(),
            WriterMemorySnapshot(
                retainedBytes: 4_096,
                retainedItems: 128,
                tcpWaiterGate: false))

        for _ in 0..<count { budget.release(bytes: 32) }
        XCTAssertEqual(
            budget.snapshot(),
            WriterMemorySnapshot(
                retainedBytes: 0,
                retainedItems: 0,
                tcpWaiterGate: false))
    }

    func testUdpUsesSpareHeadroomWhileTcpWaitsAndTcpStillProgresses() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 1_280,
                maxItems: 256,
                tcpWaiterMaxBytes: 512,
                udpPressureReserveBytes: 256,
                udpPressureReserveItems: 255))
        XCTAssertTrue(budget.tryReserve(bytes: 512, items: 1))
        XCTAssertTrue(budget.tryReserve(bytes: 384, items: 1))

        let tcpGranted = expectation(description: "TCP head receives pregrant")
        let grantBox = Locked<WriterMemoryGrant?>(nil)
        let waiter = budget.waitForTcpCapacity(bytes: 512) { grant in
            grantBox.withLock { $0 = grant }
            tcpGranted.fulfill()
        }
        XCTAssertTrue(budget.snapshot().tcpWaiterGate)

        let udpAdmission = budget.tryReserveUdp(bytes: 64, items: 1)
        guard case .pressureUdp? = udpAdmission else {
            return XCTFail("a TCP waiter must not black-hole fitting UDP/QUIC service")
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 960)

        budget.release(bytes: 384, items: 1)
        budget.release(bytes: 512, items: 1)
        wait(for: [tcpGranted], timeout: 3)
        withExtendedLifetime(waiter) {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 576)
        XCTAssertEqual(budget.snapshot().retainedItems, 2)

        let grant = grantBox.withLock { value -> WriterMemoryGrant? in
            defer { value = nil }
            return value
        }
        XCTAssertTrue(grant?.consume() == true)
        budget.release(bytes: 512, items: 1)
        budget.releaseUdp(
            bytes: 64, items: 1, pressureBytes: 64, pressureItems: 1)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testSaturatedUdpItemReserveDoesNotDoubleCountAgainstTcpGrant() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 192 * 1024,
                maxItems: 257,
                tcpWaiterMaxBytes: 64 * 1024,
                udpPressureReserveBytes: 64 * 1024,
                udpPressureReserveItems: 255))
        XCTAssertTrue(budget.tryReserve(bytes: 1, items: 1))
        let tcpGranted = expectation(description: "TCP item progresses")
        let grantBox = Locked<WriterMemoryGrant?>(nil)
        let waiter = budget.waitForTcpCapacity(bytes: 1, items: 1) { grant in
            grantBox.withLock { $0 = grant }
            tcpGranted.fulfill()
        }
        guard case .pressureUdp? = budget.tryReserveUdp(bytes: 0, items: 255) else {
            return XCTFail("UDP service reserve should accept its exact item cap")
        }
        budget.release(bytes: 1, items: 1)
        wait(for: [tcpGranted], timeout: 3)
        withExtendedLifetime(waiter) {}
        XCTAssertEqual(budget.snapshot().retainedItems, 256)

        let grant = grantBox.withLock { value -> WriterMemoryGrant? in
            defer { value = nil }
            return value
        }
        XCTAssertTrue(grant?.consume() == true)
        budget.release(bytes: 1, items: 1)
        budget.releaseUdp(
            bytes: 0, items: 255, pressureBytes: 0, pressureItems: 255)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testPressureUdpSubchargeCannotBeConsumedByRacingTcpGrant() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 1_024,
                maxItems: 8,
                tcpWaiterMaxBytes: 256,
                udpPressureReserveBytes: 256,
                udpPressureReserveItems: 2))
        XCTAssertTrue(budget.tryReserve(bytes: 768, items: 1))
        XCTAssertTrue(budget.tryReserve(bytes: 1, items: 1))
        let tcpGranted = expectation(description: "TCP eventually granted")
        let grantBox = Locked<WriterMemoryGrant?>(nil)
        let waiter = budget.waitForTcpCapacity(bytes: 256) { grant in
            grantBox.withLock { $0 = grant }
            tcpGranted.fulfill()
        }

        let subcharged = DispatchSemaphore(value: 0)
        let allowAggregate = DispatchSemaphore(value: 0)
        budget.testAfterPressureUdpSubcharge = {
            subcharged.signal()
            XCTAssertEqual(allowAggregate.wait(timeout: .now() + 3), .success)
        }
        let fillerReleased = DispatchSemaphore(value: 0)
        budget.testAfterReleaseBeforeCoordinatorKick = {
            fillerReleased.signal()
        }
        let udpResult = Locked<WriterMemoryAdmission?>(nil)
        let udpDone = expectation(description: "UDP aggregate reservation")
        DispatchQueue.global(qos: .userInitiated).async {
            let admission = budget.tryReserveUdp(bytes: 256, items: 1)
            udpResult.withLock { $0 = admission }
            udpDone.fulfill()
        }
        XCTAssertEqual(subcharged.wait(timeout: .now() + 3), .success)

        // Make the TCP head appear eligible if it incorrectly treats UDP's
        // unpublished subcharge as already present in aggregate usage.
        let releaseDone = expectation(description: "release completes after coordinator lock")
        DispatchQueue.global(qos: .userInitiated).async {
            budget.release(bytes: 1, items: 1)
            releaseDone.fulfill()
        }
        XCTAssertEqual(fillerReleased.wait(timeout: .now() + 3), .success)
        allowAggregate.signal()
        wait(for: [udpDone, releaseDone], timeout: 3)
        guard case .pressureUdp? = udpResult.withLock({ $0 }) else {
            return XCTFail("UDP must retain its reserved pressure slot")
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 1_024)

        budget.release(bytes: 768, items: 1)
        wait(for: [tcpGranted], timeout: 3)
        withExtendedLifetime(waiter) {}
        let grant = grantBox.withLock { value -> WriterMemoryGrant? in
            defer { value = nil }
            return value
        }
        XCTAssertTrue(grant?.consume() == true)
        budget.release(bytes: 256, items: 1)
        budget.releaseUdp(
            bytes: 256, items: 1, pressureBytes: 256, pressureItems: 1)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
    }

    func testLoweredReconfigurationBlocksUntilOldUsageFalls() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 16,
                maxItems: 8,
                tcpWaiterMaxBytes: 4,
                udpPressureReserveBytes: 4,
                udpPressureReserveItems: 2))
        XCTAssertTrue(budget.tryReserve(bytes: 12, items: 3))
        budget.reconfigure(
            policy: WriterMemoryPolicy(
                maxBytes: 8,
                maxItems: 4,
                tcpWaiterMaxBytes: 4,
                udpPressureReserveBytes: 2,
                udpPressureReserveItems: 1))

        XCTAssertFalse(budget.tryReserve(bytes: 1, items: 1))
        budget.release(bytes: 12, items: 3)
        XCTAssertTrue(budget.tryReserve(bytes: 8, items: 4))
        XCTAssertFalse(budget.tryReserve(bytes: 0, items: 1))
        budget.release(bytes: 8, items: 4)
    }

    func testDownReconfigurePreservesUdpReserveForHistoricalMaxTcpPump() {
        let oldTcpMax = 8 * 1024 * 1024
        let udpReserve = WriterMemoryPolicy.minimumUdpPressureReserveBytes
        let transitBytes = 64 * 1024
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 64 * 1024 * 1024,
                maxItems: 1_024,
                tcpWaiterMaxBytes: oldTcpMax,
                udpPressureReserveBytes: 1024 * 1024,
                udpPressureReserveItems: 16))
        budget.reconfigure(
            policy: WriterMemoryPolicy(
                maxBytes: oldTcpMax,
                maxItems: 512,
                tcpWaiterMaxBytes: oldTcpMax - udpReserve - transitBytes,
                udpPressureReserveBytes: udpReserve,
                udpPressureReserveItems: 8))

        let oldRetryRejected = expectation(description: "old-size retry rejected")
        let oldRetry = budget.waitForTcpCapacity(
            bytes: oldTcpMax,
            onUnavailable: { oldRetryRejected.fulfill() },
            onGrant: { grant in
                grant.release()
                XCTFail("an old 8 MiB retry cannot consume UDP's new 64 KiB reserve")
            })
        wait(for: [oldRetryRejected], timeout: 3)
        withExtendedLifetime(oldRetry) {}
        XCTAssertFalse(budget.snapshot().tcpWaiterGate)
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)

        var transit = budget.makeTcpTransitCursor(Data(repeating: 0xA7, count: transitBytes))
        XCTAssertNotNil(transit, "down-reconfigure must also retain a TCP read")
        let currentTcpShare = oldTcpMax - udpReserve - transitBytes
        XCTAssertTrue(budget.tryReserve(bytes: currentTcpShare, items: 1))
        let waiter = budget.waitForTcpCapacity(bytes: 1) { grant in grant.release() }
        guard case .pressureUdp? = budget.tryReserveUdp(
            bytes: udpReserve, items: 1)
        else {
            return XCTFail("down-reconfigure must retain nonzero UDP service")
        }
        withExtendedLifetime(waiter) {
            XCTAssertEqual(
                budget.snapshot().retainedBytes,
                oldTcpMax)
        }
        waiter.cancel()
        budget.release(bytes: currentTcpShare, items: 1)
        budget.releaseUdp(
            bytes: udpReserve,
            items: 1,
            pressureBytes: udpReserve,
            pressureItems: 1)
        XCTAssertEqual(transit?.remainingBytes, transitBytes)
        transit = nil
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
    }

    func testAggregatePressureTelemetryIsOrderedSampledAndRecovers() {
        let entered = expectation(description: "entered")
        let recovered = expectation(description: "recovered")
        let events = Locked<[WriterMemoryPressureEvent]>([])
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 4,
                maxItems: 2,
                tcpWaiterMaxBytes: 2,
                udpPressureReserveBytes: 1,
                udpPressureReserveItems: 1),
            onPressureEvent: { event in
                events.withLock { $0.append(event) }
                if event.transition == .entered { entered.fulfill() }
                if event.transition == .recovered { recovered.fulfill() }
            })
        XCTAssertTrue(budget.tryReserve(bytes: 4, items: 1))
        for _ in 0..<128 {
            XCTAssertNil(budget.tryReserveUdp(bytes: 1, items: 1))
        }
        budget.release(bytes: 4, items: 1)
        wait(for: [entered, recovered], timeout: 3)

        let captured = events.withLock { $0 }
        XCTAssertEqual(captured.map(\.transition), [.entered, .recovered])
        XCTAssertEqual(captured.first?.protocol, .udp)
        XCTAssertEqual(captured.first?.reason, .aggregateBytes)
        XCTAssertEqual(captured.first?.maxBytes, 4)
        XCTAssertEqual(captured.last?.retainedBytes, 0)
    }

    func testRepeatedPressureEpisodesPublishOneOrderedPairPerEpisode() {
        let episodeCount = 128
        let delivered = expectation(description: "all pressure episodes completed")
        delivered.expectedFulfillmentCount = episodeCount * 2
        let events = Locked<[WriterMemoryPressureEvent]>([])
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 4,
                maxItems: 2,
                tcpWaiterMaxBytes: 2,
                udpPressureReserveBytes: 1,
                udpPressureReserveItems: 1),
            onPressureEvent: { event in
                events.withLock { $0.append(event) }
                delivered.fulfill()
            })
        for _ in 0..<episodeCount {
            XCTAssertTrue(budget.tryReserve(bytes: 4, items: 1))
            XCTAssertNil(budget.tryReserveUdp(bytes: 1, items: 1))
            XCTAssertNil(budget.tryReserveUdp(bytes: 1, items: 1))
            budget.release(bytes: 4, items: 1)
        }
        wait(for: [delivered], timeout: 3)
        let captured = events.withLock { $0 }
        XCTAssertEqual(captured.count, episodeCount * 2)
        for (index, event) in captured.enumerated() {
            XCTAssertEqual(event.transition, index.isMultiple(of: 2) ? .entered : .recovered)
            XCTAssertEqual(event.retainedBytes, index.isMultiple(of: 2) ? 4 : 0)
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
        XCTAssertTrue(budget.tryReserve(bytes: 4, items: 1))
        budget.release(bytes: 4, items: 1)
    }

    func testRecoveryCrossingEnteredEnqueueStaysOrderedAndNextEpisodeVisible() {
        let fourEvents = expectation(description: "two ordered episodes")
        fourEvents.expectedFulfillmentCount = 4
        let events = Locked<[WriterMemoryPressureEvent]>([])
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 4,
                maxItems: 2,
                tcpWaiterMaxBytes: 2,
                udpPressureReserveBytes: 1,
                udpPressureReserveItems: 1),
            onPressureEvent: { event in
                events.withLock { $0.append(event) }
                fourEvents.fulfill()
            })
        XCTAssertTrue(budget.tryReserve(bytes: 4))
        let entering = DispatchSemaphore(value: 0)
        let enqueueAllowed = DispatchSemaphore(value: 0)
        let hookCalls = Locked(0)
        budget.testBeforePressureEventEnqueue = {
            let shouldBlock = hookCalls.withLock { value -> Bool in
                value += 1
                return value == 1
            }
            if shouldBlock {
                entering.signal()
                XCTAssertEqual(enqueueAllowed.wait(timeout: .now() + 3), .success)
            }
        }
        let firstDenialDone = expectation(description: "first denial")
        DispatchQueue.global(qos: .userInitiated).async {
            XCTAssertFalse(budget.tryReserve(bytes: 1))
            firstDenialDone.fulfill()
        }
        XCTAssertEqual(entering.wait(timeout: .now() + 3), .success)
        budget.release(bytes: 4)
        enqueueAllowed.signal()
        wait(for: [firstDenialDone], timeout: 3)

        XCTAssertTrue(budget.tryReserve(bytes: 4))
        XCTAssertFalse(budget.tryReserve(bytes: 1))
        budget.release(bytes: 4)
        wait(for: [fourEvents], timeout: 3)
        XCTAssertEqual(
            events.withLock { $0.map(\.transition) },
            [.entered, .recovered, .entered, .recovered])
    }

    func testFifoWaitersReceivePrechargedGrantsWithoutBarging() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 8,
                maxItems: 2,
                udpPressureReserveBytes: 0,
                udpPressureReserveItems: 0))
        XCTAssertTrue(budget.tryReserve(bytes: 8))

        let delivered = expectation(description: "both grants delivered")
        delivered.expectedFulfillmentCount = 2
        let order = Locked<[Int]>([])
        let grants = Locked<[WriterMemoryGrant]>([])
        let first = budget.waitForTcpCapacity(bytes: 4) { grant in
            order.withLock { $0.append(4) }
            grants.withLock { $0.append(grant) }
            delivered.fulfill()
        }
        let second = budget.waitForTcpCapacity(bytes: 2) { grant in
            order.withLock { $0.append(2) }
            grants.withLock { $0.append(grant) }
            delivered.fulfill()
        }

        XCTAssertFalse(budget.tryReserve(bytes: 1), "published waiters close the atomic gate")
        budget.release(bytes: 8)
        wait(for: [delivered], timeout: 3)

        withExtendedLifetime((first, second)) {
            XCTAssertEqual(order.withLock { $0 }, [4, 2])
            XCTAssertEqual(
                budget.snapshot(),
                WriterMemorySnapshot(
                    retainedBytes: 6,
                    retainedItems: 2,
                    tcpWaiterGate: false))
        }
        let deliveredGrants = grants.withLock { value -> [WriterMemoryGrant] in
            defer { value.removeAll() }
            return value
        }
        for grant in deliveredGrants {
            XCTAssertTrue(grant.consume())
            budget.release(bytes: grant.bytes, items: grant.items)
            grant.release()
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testCanceledWaiterAndUnusedGrantRefundExactlyOnce() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        XCTAssertTrue(budget.tryReserve(bytes: 4))
        let never = expectation(description: "canceled waiter")
        never.isInverted = true
        let canceled = budget.waitForTcpCapacity(bytes: 4) { _ in never.fulfill() }
        canceled.cancel()
        XCTAssertFalse(budget.snapshot().tcpWaiterGate)
        budget.release(bytes: 4)
        wait(for: [never], timeout: 0.05)

        let delivered = expectation(description: "unused grant")
        let grantBox = Locked<WriterMemoryGrant?>(nil)
        let waiter = budget.waitForTcpCapacity(bytes: 4) { grant in
            grantBox.withLock { $0 = grant }
            delivered.fulfill()
        }
        wait(for: [delivered], timeout: 3)
        withExtendedLifetime(waiter) {}
        let grant = grantBox.withLock { value -> WriterMemoryGrant? in
            defer { value = nil }
            return value
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        grant?.release()
        grant?.release()
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testTcpPumpRetriesExactChunkAfterAnotherPumpReleasesCapacity() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        let firstQueue = DispatchQueue(label: "rama.writer-budget.tcp.first")
        let secondQueue = DispatchQueue(label: "rama.writer-budget.tcp.second")
        let firstWriteStarted = expectation(description: "first write started")
        let firstCompletion = Locked<((Error?) -> Void)?>(nil)
        let secondWriteStarted = expectation(description: "second write started")
        let secondCompletion = Locked<((Error?) -> Void)?>(nil)
        let retryReady = expectation(description: "aggregate retry ready")
        let policy = TcpWritePumpPolicy(maxPendingBytes: 4)

        let first = TcpWritePumpCore(
            queue: firstQueue,
            onDrained: {},
            doWrite: { _, completion in
                firstCompletion.withLock { $0 = completion }
                firstWriteStarted.fulfill()
            },
            logHwm: { _ in },
            writerMemoryBudget: budget,
            writePolicy: policy)
        let second = TcpWritePumpCore(
            queue: secondQueue,
            onDrained: { retryReady.fulfill() },
            doWrite: { _, completion in
                secondCompletion.withLock { $0 = completion }
                secondWriteStarted.fulfill()
            },
            logHwm: { _ in },
            writerMemoryBudget: budget,
            writePolicy: policy)

        XCTAssertEqual(first.enqueue(Data(repeating: 1, count: 4)), .accepted)
        wait(for: [firstWriteStarted], timeout: 3)
        XCTAssertEqual(second.enqueue(Data(repeating: 2, count: 4)), .paused)
        XCTAssertTrue(budget.snapshot().tcpWaiterGate)

        firstCompletion.withLock { completion in
            completion?(nil)
            completion = nil
        }
        wait(for: [retryReady], timeout: 3)
        XCTAssertEqual(budget.snapshot().retainedBytes, 4, "grant is precharged")
        XCTAssertEqual(second.enqueue(Data(repeating: 2, count: 4)), .accepted)
        wait(for: [secondWriteStarted], timeout: 3)
        secondCompletion.withLock { completion in
            completion?(nil)
            completion = nil
        }
        secondQueue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testTcpCancelRefundsAcceptedBytesAndUndeliveredGrant() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        let firstQueue = DispatchQueue(label: "rama.writer-budget.cancel.first")
        let secondQueue = DispatchQueue(label: "rama.writer-budget.cancel.second")
        let grantReady = expectation(description: "grant ready")
        let policy = TcpWritePumpPolicy(maxPendingBytes: 4)
        let first = TcpWritePumpCore(
            queue: firstQueue,
            initialLifecycle: .pending,
            onDrained: {},
            doWrite: { _, _ in XCTFail("pending pump must not write") },
            logHwm: { _ in },
            writerMemoryBudget: budget,
            writePolicy: policy)
        let second = TcpWritePumpCore(
            queue: secondQueue,
            initialLifecycle: .pending,
            onDrained: { grantReady.fulfill() },
            doWrite: { _, _ in XCTFail("pending pump must not write") },
            logHwm: { _ in },
            writerMemoryBudget: budget,
            writePolicy: policy)

        XCTAssertEqual(first.enqueue(Data(repeating: 1, count: 4)), .accepted)
        XCTAssertEqual(second.enqueue(Data(repeating: 2, count: 4)), .paused)
        let firstCleanup = first.prepareCancel()
        firstQueue.async(execute: firstCleanup)
        wait(for: [grantReady], timeout: 3)
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        XCTAssertEqual(budget.snapshot().retainedItems, 1)

        let secondCleanup = second.prepareCancel()
        secondQueue.async(execute: secondCleanup)
        secondQueue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testTcpBlockedQueueCancelKeepsDispatchPayloadChargedUntilDropped() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        let queue = DispatchQueue(label: "rama.writer-budget.tcp.blocked-cancel")
        let queueEntered = expectation(description: "queue blocker entered")
        let releaseQueue = DispatchSemaphore(value: 0)
        queue.async {
            queueEntered.fulfill()
            releaseQueue.wait()
        }
        wait(for: [queueEntered], timeout: 3)
        let core = TcpWritePumpCore(
            queue: queue,
            initialLifecycle: .pending,
            onDrained: {},
            doWrite: { _, _ in XCTFail("blocked cancelled pump must not write") },
            logHwm: { _ in },
            writerMemoryBudget: budget,
            writePolicy: TcpWritePumpPolicy(maxPendingBytes: 4))

        XCTAssertEqual(core.enqueue(Data(repeating: 1, count: 4)), .accepted)
        let cleanup = core.prepareCancel()
        queue.async(execute: cleanup)
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        XCTAssertFalse(
            budget.tryReserve(bytes: 1),
            "cancel cannot refund Data still retained by a blocked dispatch")

        releaseQueue.signal()
        queue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testTcpStuckWriteCancelKeepsPayloadChargedUntilCompletionRetires() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        let queue = DispatchQueue(label: "rama.writer-budget.tcp.stuck-cancel")
        let completion = Locked<((Error?) -> Void)?>(nil)
        let started = expectation(description: "write started")
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, callback in
                completion.withLock { $0 = callback }
                started.fulfill()
            },
            logHwm: { _ in },
            writerMemoryBudget: budget,
            writePolicy: TcpWritePumpPolicy(maxPendingBytes: 4))
        queue.sync { core.markOpen() }
        XCTAssertEqual(core.enqueue(Data(repeating: 1, count: 4)), .accepted)
        wait(for: [started], timeout: 3)

        let cleanup = core.prepareCancel()
        queue.async(execute: cleanup)
        queue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        XCTAssertFalse(budget.tryReserve(bytes: 1))

        completion.withLock { callback in
            callback?(nil)
            callback = nil
        }
        queue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testUdpAggregateOverloadDropsWithoutMaterializingExtraRetention() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        let firstQueue = DispatchQueue(label: "rama.writer-budget.udp.first")
        let secondQueue = DispatchQueue(label: "rama.writer-budget.udp.second")
        let first = UdpClientWritePump(
            flow: MockUdpFlow(), queue: firstQueue, logger: { _ in },
            onTerminalError: { _ in }, writerMemoryBudget: budget)
        let second = UdpClientWritePump(
            flow: MockUdpFlow(), queue: secondQueue, logger: { _ in },
            onTerminalError: { _ in }, writerMemoryBudget: budget)
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "443")

        first.enqueue(Data(repeating: 1, count: 4), sentBy: endpoint)
        second.enqueue(Data(repeating: 2, count: 4), sentBy: endpoint)
        XCTAssertEqual(first.testAdmissionSnapshot.acceptedDispatches, 1)
        XCTAssertEqual(second.testAdmissionSnapshot.acceptedDispatches, 0)
        XCTAssertEqual(second.testAdmissionSnapshot.droppedFull, 1)
        XCTAssertEqual(second.testAdmissionSnapshot.droppedAggregate, 1)
        XCTAssertEqual(budget.snapshot().retainedBytes, 4)
        XCTAssertEqual(budget.snapshot().retainedItems, 1)

        first.close()
        firstQueue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        second.enqueue(Data(repeating: 3, count: 4), sentBy: endpoint)
        XCTAssertEqual(second.testAdmissionSnapshot.acceptedDispatches, 1)
        second.close()
        secondQueue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testUdpStuckWriteCloseKeepsBatchChargedUntilCompletionRetires() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(maxBytes: 4, maxItems: 1))
        let firstQueue = DispatchQueue(label: "rama.writer-budget.udp.stuck.first")
        let secondQueue = DispatchQueue(label: "rama.writer-budget.udp.stuck.second")
        let firstFlow = MockUdpFlow()
        let first = UdpClientWritePump(
            flow: firstFlow, queue: firstQueue, logger: { _ in },
            onTerminalError: { _ in }, writerMemoryBudget: budget)
        let second = UdpClientWritePump(
            flow: MockUdpFlow(), queue: secondQueue, logger: { _ in },
            onTerminalError: { _ in }, writerMemoryBudget: budget)
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "443")
        first.markOpened()
        first.enqueue(Data(repeating: 1, count: 4), sentBy: endpoint)
        firstQueue.sync {}
        XCTAssertEqual(firstFlow.writtenBatches.count, 1)

        first.close()
        firstQueue.sync {}
        XCTAssertEqual(
            budget.snapshot().retainedBytes, 4,
            "close cannot refund a writeDatagrams batch retained by the transport")
        second.enqueue(Data(repeating: 2, count: 4), sentBy: endpoint)
        XCTAssertEqual(second.testAdmissionSnapshot.acceptedDispatches, 0)
        XCTAssertEqual(second.testAdmissionSnapshot.droppedAggregate, 1)

        XCTAssertTrue(firstFlow.completePendingWrite())
        firstQueue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        second.enqueue(Data(repeating: 3, count: 4), sentBy: endpoint)
        XCTAssertEqual(second.testAdmissionSnapshot.acceptedDispatches, 1)
        second.close()
        secondQueue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.snapshot().retainedItems, 0)
    }

    func testReconfigureKeepsExistingNoCopyTransitRootChargedUntilArcRelease() {
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 256, maxItems: 16, tcpWaiterMaxBytes: 64,
                udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        let pointer = UnsafeMutableRawPointer.allocate(byteCount: 96, alignment: 1)
        pointer.initializeMemory(as: UInt8.self, repeating: 0x21, count: 96)
        let released = TestValue(false)
        autoreleasepool {
            var data = Data(
                bytesNoCopy: pointer,
                count: 96,
                deallocator: .custom { pointer, _ in
                    released.set(true)
                    pointer.deallocate()
                })
            var cursor = budget.makeTcpTransitCursor(data)
            XCTAssertNotNil(cursor)
            data = Data()
            XCTAssertEqual(budget.snapshot().retainedBytes, 96)
            XCTAssertEqual(budget.testTcpTransitSnapshot.retainedBytes, 96)

            budget.reconfigure(
                policy: WriterMemoryPolicy(
                    maxBytes: 256, maxItems: 16, tcpWaiterMaxBytes: 64,
                    udpPressureReserveBytes: 128, udpPressureReserveItems: 2))
            XCTAssertEqual(
                budget.snapshot().retainedBytes, 96,
                "lower limits cannot refund a live physical root")
            XCTAssertNil(
                budget.makeTcpTransitCursor(Data([0x99])),
                "new transit roots stay blocked while old usage exceeds the lowered subcap")

            pointer.storeBytes(of: UInt8(0xE7), as: UInt8.self)
            XCTAssertEqual(cursor?.prefix(maxBytes: 64).copiedData.first, 0xE7)
            XCTAssertFalse(released.get())
            cursor = nil
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.testTcpTransitSnapshot.retainedBytes, 0)
        XCTAssertTrue(released.get())
    }

    func testTcpTransitSubcapPreservesLargeWaiterAndUdpReserveWithNoCopyRoot() {
        let kib = 1024
        let policy = WriterMemoryPolicy(
            maxBytes: 512 * kib,
            maxItems: 16,
            tcpWaiterMaxBytes: 128 * kib,
            udpPressureReserveBytes: 32 * kib,
            udpPressureReserveItems: 3)
        XCTAssertEqual(policy.tcpPayloadViewMaxBytes, 64 * kib)
        XCTAssertEqual(policy.tcpTransitMaxBytes, 352 * kib)
        XCTAssertEqual(policy.tcpTransitMaxItems, 12)

        let budget = WriterMemoryBudget(policy: policy)
        let pointer = UnsafeMutableRawPointer.allocate(
            byteCount: policy.tcpTransitMaxBytes,
            alignment: MemoryLayout<UInt8>.alignment)
        pointer.initializeMemory(
            as: UInt8.self, repeating: 0x41, count: policy.tcpTransitMaxBytes)
        let released = TestValue(false)
        autoreleasepool {
            var data = Data(
                bytesNoCopy: pointer,
                count: policy.tcpTransitMaxBytes,
                deallocator: .custom { pointer, _ in
                    released.set(true)
                    pointer.deallocate()
                })
            var transit = budget.makeTcpTransitCursor(data)
            XCTAssertNotNil(transit)
            data = Data()
            XCTAssertNil(
                budget.makeTcpTransitCursor(Data([0x01])),
                "the physical transit byte subcap is saturated")

            pointer.storeBytes(of: UInt8(0xA7), as: UInt8.self)
            XCTAssertEqual(
                transit?.prefix(maxBytes: policy.tcpPayloadViewMaxBytes).copiedData.first,
                0xA7,
                "the saturated transit cursor must retain the original backing allocation")
            XCTAssertFalse(released.get())

            XCTAssertTrue(
                budget.tryReserve(bytes: policy.tcpWaiterMaxBytes),
                "one full >64 KiB TCP waiter remains outside the transit subcap")

            let waiterGranted = expectation(description: "full TCP waiter granted")
            let granted = TestValue<WriterMemoryGrant?>(nil)
            var waiter: WriterMemoryWaiter? = budget.waitForTcpCapacity(
                bytes: policy.tcpWaiterMaxBytes,
                onGrant: { grant in
                    granted.set(grant)
                    waiterGranted.fulfill()
                })
            XCTAssertNotNil(waiter)
            guard let udpAdmission = budget.tryReserveUdp(
                bytes: policy.udpPressureReserveBytes)
            else {
                XCTFail("UDP reserve must remain usable while the full TCP waiter is queued")
                return
            }
            guard case .pressureUdp = udpAdmission else {
                XCTFail("UDP must use its pressure reserve behind the TCP waiter gate")
                return
            }

            budget.release(bytes: policy.tcpWaiterMaxBytes)
            wait(for: [waiterGranted], timeout: 2)
            XCTAssertEqual(
                budget.snapshot().retainedBytes,
                policy.tcpTransitMaxBytes
                    + policy.tcpWaiterMaxBytes
                    + policy.udpPressureReserveBytes)

            granted.update { grant in
                grant?.release()
                grant = nil
            }
            waiter = nil
            budget.releaseUdp(
                bytes: policy.udpPressureReserveBytes,
                items: 1,
                pressureBytes: policy.udpPressureReserveBytes,
                pressureItems: 1)
            transit = nil
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertEqual(budget.testTcpTransitSnapshot.retainedBytes, 0)
        XCTAssertTrue(released.get())
    }
}
