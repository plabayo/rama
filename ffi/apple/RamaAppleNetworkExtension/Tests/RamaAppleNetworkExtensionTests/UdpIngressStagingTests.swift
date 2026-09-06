import Foundation
import Darwin
import MachO
@preconcurrency import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

final class UdpIngressStagingTests: XCTestCase {
    private static func loadedThreadSanitizerRuntimes() -> [String] {
        (0..<_dyld_image_count()).compactMap { index in
            guard let name = _dyld_get_image_name(index) else { return nil }
            let path = String(cString: name)
            let filename = URL(fileURLWithPath: path).lastPathComponent
            guard filename.hasPrefix("libclang_rt.tsan_"),
                filename.hasSuffix("_dynamic.dylib")
            else { return nil }
            return path
        }
    }

    private final class WeakWaiterProbe {
        weak var value: NSObject?
        init(_ value: NSObject) { self.value = value }
    }

    func testDroppingAllIndexedOwnersBreaksTreeAndFifoOwnershipCycles() {
        let count = 128
        let forward = Array(0..<count)
        let outsideIn = (0..<(count / 2)).flatMap { [$0, count - 1 - $0] }
        for order in [forward, Array(forward.reversed()), outsideIn] {
            let generation = UdpIngressGenerationStagingBudget(
                policy: UdpIngressStagingPolicy(
                    maxItemsPerFlow: 1, maxItemsPerGeneration: count + 1,
                    maxBytesPerFlow: 1, maxBytesPerGeneration: 1),
                automaticScheduling: false)
            let holder = UdpIngressFlowStaging(generation: generation)
            let held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
            var flows: [UdpIngressFlowStaging?] = []
            var probes: [WeakWaiterProbe] = []
            for _ in 0..<count {
                let flow = UdpIngressFlowStaging(generation: generation)
                let probe = NSObject()
                probes.append(WeakWaiterProbe(probe))
                XCTAssertTrue(flow.waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: 1
                ) { [probe] _ in withExtendedLifetime(probe) {} })
                flows.append(flow)
            }
            XCTAssertEqual(generation.testWaiterCount, count)
            XCTAssertEqual(probes.filter { $0.value != nil }.count, count)
            for index in order { flows[index] = nil }
            XCTAssertEqual(generation.testWaiterCount, 0)
            XCTAssertEqual(generation.testWaiterGate, 0)
            XCTAssertEqual(generation.testGrantCount, 0)
            XCTAssertTrue(probes.allSatisfy { $0.value == nil },
                "retired FIFO next and AVL child links must release every waiter callback")
            withExtendedLifetime(held) {}
            holder.close()
        }
    }

    func testCoordinatorIdentityLookupAllowsConcurrentFinalOwnerCancellation() throws {
        let marker = "RAMA_UDP_OWNER_DEINIT_CHILD"
        let sanitizerMarker = "RAMA_UDP_OWNER_DEINIT_TSAN_RUNTIMES"
        if ProcessInfo.processInfo.environment[marker] == "1" {
            if let expected = ProcessInfo.processInfo.environment[sanitizerMarker] {
                let loaded = Set(Self.loadedThreadSanitizerRuntimes())
                XCTAssertTrue(expected.split(separator: ":").allSatisfy { loaded.contains(String($0)) },
                    "the subprocess must preserve the parent's loaded ThreadSanitizer runtime")
            }
            let policy = UdpIngressStagingPolicy(
                maxItemsPerFlow: 1, maxItemsPerGeneration: 2,
                maxBytesPerFlow: 1, maxBytesPerGeneration: 1)
            let generation = UdpIngressGenerationStagingBudget(
                policy: policy, automaticScheduling: false)
            let holder = UdpIngressFlowStaging(generation: generation)
            let held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
            let owner = Locked<UdpIngressFlowStaging?>(UdpIngressFlowStaging(generation: generation))
            let releaseProgress = DispatchSemaphore(value: 0)
            let dropCompleted = DispatchSemaphore(value: 0)
            owner.withLock {
                $0!.testBeforeCloseCancellation = {
                    XCTAssertFalse(Thread.isMainThread)
                    releaseProgress.signal()
                }
            }
            XCTAssertTrue(owner.withLock {
                $0!.waitForCapacity(reason: .generationBytes, neededItems: 1, neededBytes: 1) {
                    _ in XCTFail("the disappearing owner must not receive a grant")
                }
            })
            XCTAssertEqual(generation.testWaiterCount, 1)
            generation.testAfterCoordinatorIdentityLookup = {
                // The coordinator holds its state lock while another thread
                // drops the last external owner. No flow lifetime may be
                // extended by the coordinator's identity/epoch inspection:
                // deinit must begin on the dropping thread and reach cancel.
                DispatchQueue.global().async {
                    owner.withLock { $0 = nil }
                    dropCompleted.signal()
                    // On the broken implementation, the coordinator's weak
                    // upgrade retains the flow so this drop returns first.
                    // Let that coordinator proceed too: releasing its own
                    // final temporary then reproduces the real recursive lock.
                    releaseProgress.signal()
                }
                releaseProgress.wait()
                // Cancellation itself needs this lock, so let the coordinator
                // finish before waiting for the synchronous deinit to return.
            }
            generation.reconfigure(policy: policy)
            generation.testAfterCoordinatorIdentityLookup = nil
            dropCompleted.wait()
            XCTAssertNil(owner.withLock { $0 })
            XCTAssertEqual(generation.testWaiterCount, 0)
            XCTAssertEqual(generation.testWaiterGate, 0)
            XCTAssertEqual(generation.testGrantCount, 0)
            withExtendedLifetime(held) {}
            holder.close()
            return
        }

        // A regression deadlocks an NSLock, so isolate it from the XCTest
        // runner and kill only this owned child if its bounded run stalls.
        let child = Process()
        child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        child.arguments = [
            "-XCTest",
            "RamaAppleNetworkExtensionTests.UdpIngressStagingTests/testCoordinatorIdentityLookupAllowsConcurrentFinalOwnerCancellation",
            Bundle(for: Self.self).bundleURL.path,
        ]
        var environment = ProcessInfo.processInfo.environment
        environment[marker] = "1"
        let sanitizerRuntimes = Self.loadedThreadSanitizerRuntimes()
        if !sanitizerRuntimes.isEmpty {
            // SwiftPM's xctest launcher may consume DYLD_INSERT_LIBRARIES.
            // A directly launched child must preload the actual parent runtime
            // before dlopen loads the instrumented test bundle. Discover its
            // loaded image instead of assuming a selected Xcode/toolchain path.
            var preloads = (environment["DYLD_INSERT_LIBRARIES"] ?? "")
                .split(separator: ":").map(String.init)
            for runtime in sanitizerRuntimes where !preloads.contains(runtime) {
                preloads.append(runtime)
            }
            environment["DYLD_INSERT_LIBRARIES"] = preloads.joined(separator: ":")
            environment[sanitizerMarker] = sanitizerRuntimes.joined(separator: ":")
        }
        child.environment = environment
        let output = Pipe()
        child.standardOutput = output
        child.standardError = output
        try child.run()
        let deadline = Date(timeIntervalSinceNow: 10)
        while child.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        let timedOut = child.isRunning
        if timedOut { _ = kill(child.processIdentifier, SIGKILL) }
        child.waitUntilExit()
        let diagnostic = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertFalse(timedOut, "coordinator owner deinit deadlocked: \(diagnostic)")
        XCTAssertEqual(child.terminationStatus, 0, diagnostic)
        XCTAssertTrue(diagnostic.contains("Executed 1 test"), diagnostic)
    }

    func testNonfittingDiscoveryReparksUseLinearTotalInspections() {
        for flowCount in [128, 256] {
            assertDiscoveryUsesLinearTotalInspections(flowCount: flowCount)
        }
    }

    func testEightThousandOneHundredNinetyTwoNonfittingDiscoveryReparksStayLinear() {
        assertDiscoveryUsesLinearTotalInspections(flowCount: 8_192)
    }

    func testSuccessfulDiscoveriesUseLinearTotalInspectionsAcrossPhysicalReleases() {
        for flowCount in [128, 256, 8_192] {
            assertDiscoveryUsesLinearTotalInspections(
                flowCount: flowCount, nextDatagramFits: true)
        }
    }

    func testDiscoveryTraversalKeepsUntouchedTailAfterVisitedCancellationAndArrivals() {
        assertDiscoveryUsesLinearTotalInspections(flowCount: 128, withWaiterChurn: true)
    }

    func testRecurringFittingWaiterKeepsReceivingDuringLongDiscoveryCohort() {
        for flowCount in [128, 8_192] {
            let generation = UdpIngressGenerationStagingBudget(
                policy: UdpIngressStagingPolicy(
                    maxItemsPerFlow: 2, maxItemsPerGeneration: flowCount + 2,
                    maxBytesPerFlow: 3, maxBytesPerGeneration: 3),
                automaticScheduling: false)
            let holder = UdpIngressFlowStaging(generation: generation)
            var held = holder.stage(datagrams: [Data(count: 2)], endpoints: nil).batch
            var released = holder.stage(datagrams: [Data(count: 1)], endpoints: nil).batch
            let large = (0..<flowCount).map { _ in UdpIngressFlowStaging(generation: generation) }
            let discoveries = Locked(0)
            for flow in large {
                XCTAssertTrue(flow.waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: 2
                ) { _ in discoveries.withLock { $0 += 1 } })
            }
            let fitting = UdpIngressFlowStaging(generation: generation)
            let fittingTickets = Locked<[UInt64]>([])
            let onFittingGrant: @Sendable (UInt64) -> Void = { ticket in
                fittingTickets.withLock { $0.append(ticket) }
            }
            XCTAssertTrue(fitting.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1,
                onReady: onFittingGrant))
            withExtendedLifetime(released) {}
            released = nil
            for _ in 0..<(flowCount / udpIngressStagingMaxInspectionsPerTurn + 4) {
                if !fittingTickets.withLock({ $0.isEmpty }) { break }
                generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            }
            guard let firstTicket = fittingTickets.withLock({ $0.first }) else {
                return XCTFail("initial exact fitting pass never reached the fitter")
            }
            fitting.completeWithoutStaging(grantTicket: firstTicket)
            XCTAssertTrue(fitting.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1,
                onReady: onFittingGrant))

            // Other kernel callbacks may never arrive. Advancing only their
            // provisional lease clock must not require traversing the entire
            // 8k discovery cohort before this exact fitting retry is granted.
            let before = generation.testCoordinatorInspections
            let now = DispatchTime.now().uptimeNanoseconds
            for turn in 1...16 {
                if fittingTickets.withLock({ $0.count }) > 1 { break }
                generation.testRunCoordinator(now: now + UInt64(turn) * 11_000_000)
            }
            XCTAssertEqual(fittingTickets.withLock { $0.count }, 2,
                "a fitting retry waited behind the complete \(flowCount)-flow discovery cohort")
            XCTAssertGreaterThan(discoveries.withLock { $0 }, 0,
                "fitting traffic must still allow discovery")
            XCTAssertLessThanOrEqual(
                generation.testCoordinatorInspections - before,
                UInt64(16 * udpIngressStagingMaxInspectionsPerTurn))
            fitting.close()
            large.forEach { $0.close() }
            withExtendedLifetime(held) {}
            held = nil
            holder.close()
            XCTAssertEqual(generation.testReservedBytes, 0)
            XCTAssertEqual(generation.testReservedItems, 0)
        }
    }

    func testZeroByteWaitersCannotFillAndStrandDiscoverySample() {
        assertZeroByteWaitersCannotStrandDiscovery(holderCount: 1)
        // With the supported live hard cap disabled, channel capacity two
        // leaves a process item cap of 2 * 8,192 even with more live flows.
        // This population reproduces the same stall within all public caps.
        assertZeroByteWaitersCannotStrandDiscovery(holderCount: 8_192)
    }

    func testDifferentSizeRecurringFittersBothProgressDuringDiscovery() {
        for flowCount in [128, 8_192] {
            let generation = UdpIngressGenerationStagingBudget(
                policy: UdpIngressStagingPolicy(
                    maxItemsPerFlow: 2, maxItemsPerGeneration: flowCount + 3,
                    maxBytesPerFlow: 65_535, maxBytesPerGeneration: 65_535),
                automaticScheduling: false)
            let holder = UdpIngressFlowStaging(generation: generation)
            var held = holder.stage(datagrams: [Data(count: 65_524)], endpoints: nil).batch
            var released = holder.stage(datagrams: [Data(count: 11)], endpoints: nil).batch
            let large = (0..<flowCount).map { _ in UdpIngressFlowStaging(generation: generation) }
            let discoveries = Locked(0)
            for flow in large {
                XCTAssertTrue(flow.waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: 20
                ) { _ in discoveries.withLock { $0 += 1 } })
            }
            let fitting = (0..<2).map { _ in UdpIngressFlowStaging(generation: generation) }
            let tickets = Locked<[(Int, UInt64)]>([])
            func park(_ index: Int) {
                XCTAssertTrue(fitting[index].waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: index == 0 ? 1 : 10
                ) { ticket in tickets.withLock { $0.append((index, ticket)) } })
            }
            func takeTickets() -> [(Int, UInt64)] {
                tickets.withLock { values in
                    let taken = values
                    values.removeAll(keepingCapacity: true)
                    return taken
                }
            }
            park(0)
            park(1)
            withExtendedLifetime(released) {}
            released = nil
            for _ in 0..<(flowCount / udpIngressStagingMaxInspectionsPerTurn + 4) {
                if tickets.withLock({ $0.count }) == 2 { break }
                generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            }
            let initial = takeTickets()
            XCTAssertEqual(initial.count, 2)
            // Requeue the medium packet first: each complete release can fit
            // either size, so a size-first index must not favor tiny forever.
            for (index, ticket) in initial.sorted(by: { $0.0 > $1.0 }) {
                fitting[index].completeWithoutStaging(grantTicket: ticket)
                park(index)
            }
            var deliveries = [0, 0]
            let now = DispatchTime.now().uptimeNanoseconds
            for turn in 1...64 {
                let before = generation.testCoordinatorInspections
                generation.testRunCoordinator(now: now + UInt64(turn) * 11_000_000)
                XCTAssertLessThanOrEqual(
                    generation.testCoordinatorInspections - before,
                    UInt64(udpIngressStagingMaxInspectionsPerTurn))
                for (index, ticket) in takeTickets() {
                    deliveries[index] += 1
                    fitting[index].completeWithoutStaging(grantTicket: ticket)
                    park(index)
                }
            }
            XCTAssertGreaterThanOrEqual(deliveries[0], 8)
            XCTAssertGreaterThanOrEqual(deliveries[1], 8,
                "tiny recurring reads starved a fitting medium packet behind \(flowCount) stale hints")
            XCTAssertGreaterThan(discoveries.withLock { $0 }, 0)
            fitting.forEach { $0.close() }
            large.forEach { $0.close() }
            withExtendedLifetime(held) {}
            held = nil
            holder.close()
            XCTAssertEqual(generation.testReservedBytes, 0)
            XCTAssertEqual(generation.testReservedItems, 0)
        }
    }

    private func assertZeroByteWaitersCannotStrandDiscovery(holderCount: Int) {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 2, maxItemsPerGeneration: holderCount * 2,
                maxBytesPerFlow: 65_535, maxBytesPerGeneration: 65_535),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data(count: 65_534)], endpoints: nil).batch
        var released = holder.stage(datagrams: [Data(count: 1)], endpoints: nil).batch
        let padding = (1..<holderCount).map { _ in UdpIngressFlowStaging(generation: generation) }
        var paddingBatches = padding.compactMap {
            $0.stage(datagrams: [Data(), Data()], endpoints: nil).batch
        }
        let large = UdpIngressFlowStaging(generation: generation)
        let largeTicket = Locked<UInt64>(0)
        XCTAssertTrue(large.waitForCapacity(
            reason: .generationBytes, neededItems: 1, neededBytes: 2
        ) { ticket in largeTicket.withLock { $0 = ticket } })
        let zeros = (0..<6).map { _ in UdpIngressFlowStaging(generation: generation) }
        let zeroTickets = Locked<[(Int, UInt64)]>([])
        for (index, flow) in zeros.enumerated() {
            XCTAssertTrue(flow.waitForCapacity(
                reason: .generationItems, neededItems: 1, neededBytes: 0
            ) { ticket in zeroTickets.withLock { $0.append((index, ticket)) } })
        }
        withExtendedLifetime(released) {}
        released = nil
        guard let first = zeroTickets.withLock({ $0.first }) else {
            return XCTFail("the first zero-byte exact fit was not granted")
        }
        zeros[first.0].completeWithoutStaging(grantTicket: first.1)
        zeros[first.0].close()
        // Correct exact-fit service may immediately grant the next zero-byte
        // packet. Otherwise let the older positive-size hint discover and
        // reject another nonfitting packet before checking recovery.
        if zeroTickets.withLock({ $0.count }) == 1 {
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            let ticket = largeTicket.withLock { $0 }
            if ticket != 0 {
                let rejected = large.stage(
                    datagrams: [Data(count: 2)], endpoints: nil, grantTicket: ticket)
                XCTAssertNil(rejected.batch)
                XCTAssertTrue(large.waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: 2
                ) { ticket in largeTicket.withLock { $0 = ticket } })
            }
        }
        for _ in 0..<16 {
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
        }
        XCTAssertGreaterThan(zeroTickets.withLock { $0.count }, 1,
            "zero-byte discovery hints stranded fitting packets despite free item capacity")
        zeros.forEach { $0.close() }
        large.close()
        withExtendedLifetime(held) {}
        held = nil
        holder.close()
        paddingBatches.removeAll()
        padding.forEach { $0.close() }
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    private func assertDiscoveryUsesLinearTotalInspections(
        flowCount: Int, nextDatagramFits: Bool = false, withWaiterChurn: Bool = false
    ) {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 2, maxItemsPerGeneration: flowCount + 2,
                maxBytesPerFlow: 2, maxBytesPerGeneration: 2),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        var released = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        var flows = (0..<flowCount).map { _ in UdpIngressFlowStaging(generation: generation) }
        let grants = Locked<[(Int, UInt64)]>([])
        func park(_ index: Int, neededBytes: Int = 2) {
            XCTAssertTrue(flows[index].waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: neededBytes
            ) { ticket in grants.withLock { $0.append((index, ticket)) } })
        }
        for index in flows.indices { park(index) }
        let beforeRelease = generation.testCoordinatorInspections
        withExtendedLifetime(released) {}
        released = nil
        var discovered = Set<Int>()
        var cancelled = Set<Int>()
        for _ in 0..<(flowCount * 8) {
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            let issued = grants.withLock { values -> [(Int, UInt64)] in
                let issued = values
                values.removeAll(keepingCapacity: true)
                return issued
            }
            for (index, ticket) in issued {
                if nextDatagramFits {
                    // Successful reads establish fresh physical-release
                    // epochs. They must not restart the cohort's traversal.
                    var received = flows[index].stage(
                        datagrams: [Data([1])], endpoints: nil, grantTicket: ticket).batch
                    guard received != nil else {
                        // A scheduler pause may exceed the real 10ms grant
                        // lease. Match the session's next exact-sized waiter
                        // instead of treating an expired ticket as capacity.
                        park(index, neededBytes: 1)
                        continue
                    }
                    XCTAssertTrue(discovered.insert(index).inserted)
                    withExtendedLifetime(received) {}
                    received = nil
                    flows[index].close()
                    continue
                }
                XCTAssertTrue(discovered.insert(index).inserted,
                    "a nonfitting owner must receive only one speculative read per physical release")
                // Match the session's callback/refund/repark path. The next
                // kernel datagram is still too large, so no retained payload
                // is created or released to establish another discovery epoch.
                let rejected = flows[index].stage(
                    datagrams: [Data([1, 2])], endpoints: nil, grantTicket: ticket)
                XCTAssertNil(rejected.batch)
                park(index)
                if withWaiterChurn, cancelled.isEmpty {
                    // Refunding the first partial grant has already rotated
                    // and sampled this neighbor. Its cancellation must not
                    // truncate the still-unvisited original FIFO tail.
                    flows[1].close()
                    cancelled.insert(1)
                    for _ in 0..<32 {
                        let newcomer = flows.count
                        flows.append(UdpIngressFlowStaging(generation: generation))
                        park(newcomer)
                    }
                }
            }
            if discovered.count == flows.count - cancelled.count,
                generation.testScanRemaining == 0
            { break }
        }
        let inspections = generation.testCoordinatorInspections - beforeRelease
        print("UDP discovery traversal: flows=\(flows.count) nextFits=\(nextDatagramFits) churn=\(withWaiterChurn) inspections=\(inspections)")
        XCTAssertEqual(discovered.count, flows.count - cancelled.count)
        XCTAssertTrue(discovered.contains(flowCount - 1), "the original cohort's tail must advance")
        XCTAssertLessThanOrEqual(inspections, UInt64(flows.count * 8),
            "discovery callbacks repeated complete population scans: flows=\(flows.count), inspections=\(inspections)")
        XCTAssertLessThanOrEqual(
            generation.testMaxCoordinatorInspectionsPerTurn,
            udpIngressStagingMaxInspectionsPerTurn)
        XCTAssertEqual(generation.testRetainedBytes, 1)
        XCTAssertEqual(generation.testReservedBytes, 1)
        XCTAssertEqual(generation.testGrantCount, 0)
        let quiescent = generation.testCoordinatorInspections
        for _ in 0..<16 {
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
        }
        XCTAssertEqual(generation.testCoordinatorInspections, quiescent)
        XCTAssertTrue(grants.withLock { $0.isEmpty })
        flows.forEach { $0.close() }
        withExtendedLifetime(held) {}
        held = nil
        holder.close()
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    func testFittingReparkCannotEraseDiscoveryWhileCapacityWakeIsQueued() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 4, maxItemsPerGeneration: 16,
                maxBytesPerFlow: 3, maxBytesPerGeneration: 3))
        let holder = UdpIngressFlowStaging(generation: generation)
        var retained = holder.stage(datagrams: [Data(count: 2)], endpoints: nil).batch
        var released = holder.stage(datagrams: [Data(count: 1)], endpoints: nil).batch
        let large = UdpIngressFlowStaging(generation: generation)
        let fitting = UdpIngressFlowStaging(generation: generation)
        let largeTicket = Locked<UInt64>(0)
        let fittingPayload = Locked<UdpIngressStagedBatch?>(nil)
        let acceptedFittingGrants = Locked(0)
        let receiveFittingGrant: @Sendable (UInt64) -> Void = { [weak fitting] ticket in
            guard let fitting else { return }
            let payload = fitting.stage(
                datagrams: [Data([0xAC])], endpoints: nil, grantTicket: ticket).batch
            if let payload {
                fittingPayload.withLock { $0 = payload }
                acceptedFittingGrants.withLock { $0 += 1 }
            }
        }
        XCTAssertTrue(large.waitForCapacity(
            reason: .generationBytes, neededItems: 1, neededBytes: 2
        ) { ticket in largeTicket.withLock { $0 = ticket } })
        XCTAssertTrue(fitting.waitForCapacity(
            reason: .generationBytes, neededItems: 1, neededBytes: 1,
            onReady: receiveFittingGrant))

        func blockCoordinator() -> DispatchSemaphore {
            let started = DispatchSemaphore(value: 0)
            let allowed = DispatchSemaphore(value: 0)
            generation.testBlockCoordinatorQueue(started: started, until: allowed)
            XCTAssertEqual(started.wait(timeout: .now() + 5), .success)
            return allowed
        }
        var coordinatorGate = blockCoordinator()
        defer { coordinatorGate.signal() }
        withExtendedLifetime(released) {}
        released = nil
        coordinatorGate.signal()
        coordinatorGate = blockCoordinator()

        for _ in 0..<32 {
            if largeTicket.withLock({ $0 != 0 }) { break }
            var payload = fittingPayload.withLock { value -> UdpIngressStagedBatch? in
                let payload = value
                value = nil
                return payload
            }
            guard payload != nil else {
                XCTFail("neither the fitting flow nor the older discovery received capacity")
                break
            }
            withExtendedLifetime(payload) {}
            payload = nil

            // Physical release queues a coalesced wake. A flow queue can
            // process its next callback and re-park before that wake runs.
            let blocked = fitting.stage(datagrams: [Data([0xAC])], endpoints: nil)
            XCTAssertNil(blocked.batch)
            XCTAssertTrue(fitting.waitForCapacity(
                reason: blocked.blockedReason ?? .generationItems,
                neededItems: 1, neededBytes: 1,
                onReady: receiveFittingGrant))

            // Run the real capacity wake and any serial discovery it queues.
            // Holding the next fitting payload until both turns finish ensures
            // this is a coordinator fairness failure, not queue starvation.
            for _ in 0..<2 {
                coordinatorGate.signal()
                coordinatorGate = blockCoordinator()
            }
            XCTAssertLessThanOrEqual(generation.testReservedBytes, 3)
        }
        XCTAssertNotEqual(
            largeTicket.withLock { $0 }, 0,
            "a fitting re-park erased the older pending discovery on every release")
        XCTAssertGreaterThan(acceptedFittingGrants.withLock { $0 }, 0)
        XCTAssertLessThanOrEqual(
            generation.testMaxCoordinatorInspectionsPerTurn,
            udpIngressStagingMaxInspectionsPerTurn)
        large.close()
        fitting.close()
        fittingPayload.withLock { $0 = nil }
        withExtendedLifetime(retained) {}
        retained = nil
        holder.close()
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
    }

    func testCloseBeforeGrantDeliveryRejectsCallbackAndReleasesProvisionalCapacity() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1, maxItemsPerGeneration: 1,
                maxBytesPerFlow: 1, maxBytesPerGeneration: 1))
        let holder = UdpIngressFlowStaging(generation: generation)
        let flow = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        let callbackInvoked = Locked(false)
        XCTAssertTrue(flow.waitForCapacity(
            reason: .generationItems, neededItems: 1, neededBytes: 1
        ) { _ in callbackInvoked.withLock { $0 = true } })

        let grantIssued = DispatchSemaphore(value: 0)
        let allowDelivery = DispatchSemaphore(value: 0)
        generation.testAfterCapacityWakeScan = {
            grantIssued.signal()
            allowDelivery.wait()
        }
        var deliveryBlocked = true
        defer {
            generation.testAfterCapacityWakeScan = nil
            if deliveryBlocked { allowDelivery.signal() }
        }
        withExtendedLifetime(held) {}
        held = nil
        XCTAssertEqual(grantIssued.wait(timeout: .now() + 30), .success)
        XCTAssertEqual(generation.testGrantCount, 1)
        XCTAssertTrue(flow.testWaitSnapshot.waiting)
        XCTAssertEqual(flow.testWaitSnapshot.activeTicket, 0)

        flow.close()
        let late = flow.stage(datagrams: [Data([1])], endpoints: nil)
        XCTAssertEqual(late.blockedReason, .closed)
        XCTAssertNil(late.batch)
        XCTAssertFalse(callbackInvoked.withLock { $0 })
        XCTAssertEqual(generation.testRetainedBytes, 0)
        // Issuance removed the waiter before the flow learned its ticket.
        // This payload-free provisional credit can remain until delivery
        // rejects the closed owner, or close observes an expired lease.
        XCTAssertLessThanOrEqual(generation.testGrantCount, 1)
        XCTAssertLessThanOrEqual(generation.testReservedBytes, 1)

        allowDelivery.signal()
        deliveryBlocked = false
        let settled = DispatchSemaphore(value: 0)
        let allowCoordinator = DispatchSemaphore(value: 0)
        generation.testBlockCoordinatorQueue(started: settled, until: allowCoordinator)
        defer { allowCoordinator.signal() }
        XCTAssertEqual(settled.wait(timeout: .now() + 30), .success)
        XCTAssertFalse(callbackInvoked.withLock { $0 })
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testReservedBytes, 0)
        holder.close()
    }

    func testContinuousFittingReleasesPreserveBoundedPartialDiscovery() {
        assertContinuousFittingReleasesPreserveBoundedPartialDiscovery(flowCount: 64)
    }

    func testEightThousandOneHundredNinetyTwoMixedWaitersPreserveBoundedPartialDiscovery() {
        assertContinuousFittingReleasesPreserveBoundedPartialDiscovery(flowCount: 8_192)
    }

    private func assertContinuousFittingReleasesPreserveBoundedPartialDiscovery(flowCount: Int) {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 32, maxItemsPerGeneration: 32 * flowCount,
                maxBytesPerFlow: 65_535, maxBytesPerGeneration: 65_535),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var retained = holder.stage(datagrams: [Data(count: 65_525)], endpoints: nil).batch
        var released = holder.stage(datagrams: [Data(count: 10)], endpoints: nil).batch
        let flows = (0..<flowCount).map { _ in UdpIngressFlowStaging(generation: generation) }
        let grants = Locked<[(Int, UInt64)]>([])
        func park(_ index: Int, reason: UdpIngressStagingDropReason) {
            XCTAssertTrue(flows[index].waitForCapacity(
                reason: reason, neededItems: 1, neededBytes: index.isMultiple(of: 2) ? 20 : 1
            ) { ticket in grants.withLock { $0.append((index, ticket)) } })
        }
        for index in 0..<flowCount {
            let outcome = flows[index].stage(
                datagrams: [Data(count: index.isMultiple(of: 2) ? 20 : 1)], endpoints: nil)
            XCTAssertNil(outcome.batch)
            park(index, reason: outcome.blockedReason!)
        }
        withExtendedLifetime(released) {}
        released = nil
        var discovered = Set<Int>()
        var fittingFlows = Set<Int>()
        var fittingDeliveries = 0
        let discoveryGoal = min(flowCount / 2, 32)
        for _ in 0..<(flowCount * 8) {
            let before = generation.testCoordinatorInspections
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            XCTAssertLessThanOrEqual(
                generation.testCoordinatorInspections - before,
                UInt64(udpIngressStagingMaxInspectionsPerTurn))
            let issued = grants.withLock { values -> [(Int, UInt64)] in
                let issued = values
                values.removeAll(keepingCapacity: true)
                return issued
            }
            for (index, _) in issued where !index.isMultiple(of: 2) {
                fittingFlows.insert(index)
            }
            for (index, ticket) in issued {
                var payload = flows[index].stage(
                    datagrams: [Data([0xAC])], endpoints: nil, grantTicket: ticket).batch
                guard payload != nil else {
                    // Real 10ms leases may expire if the test process is
                    // descheduled. Re-park the callback exactly as the session
                    // does, rather than treating a stale ticket as ownership.
                    park(index, reason: .generationItems)
                    continue
                }
                withExtendedLifetime(payload) {}
                payload = nil
                if index.isMultiple(of: 2) {
                    if discovered.isEmpty {
                        XCTAssertEqual(
                            fittingFlows.count, flowCount / 2,
                            "discovery must preserve the initial complete exact-fit opportunity")
                    }
                    discovered.insert(index)
                    flows[index].close()
                } else {
                    fittingDeliveries += 1
                    let blocked = flows[index].stage(datagrams: [Data([0xAC])], endpoints: nil)
                    if let reason = blocked.blockedReason {
                        park(index, reason: reason)
                    }
                }
            }
            if discovered.count == discoveryGoal { break }
        }
        XCTAssertGreaterThan(fittingDeliveries, 0)
        XCTAssertEqual(
            discovered.count, discoveryGoal,
            "continuous fitting releases starved large hints: discovered=\(discovered.count), fitting=\(fittingDeliveries), inspections=\(generation.testCoordinatorInspections), scan_remaining=\(generation.testScanRemaining)")
        flows.forEach { $0.close() }
        withExtendedLifetime(retained) {}
        retained = nil
        holder.close()
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
    }

    private func makeFlow(
        items: Int = 4,
        flowBytes: Int = 16,
        generationBytes: Int = 64
    ) -> (UdpIngressGenerationStagingBudget, UdpIngressFlowStaging) {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: items,
                maxBytesPerFlow: flowBytes,
                maxBytesPerGeneration: generationBytes))
        return (generation, UdpIngressFlowStaging(generation: generation))
    }

    func testOversizedArrayInspectsAndRetainsOnlyBoundedPrefix() {
        let (generation, flow) = makeFlow(items: 4)
        var outcome: UdpIngressStageOutcome? = flow.stage(
            datagrams: Array(repeating: Data([0xAA]), count: 10_000),
            endpoints: nil)

        XCTAssertEqual(outcome?.batch?.itemCount, 4)
        XCTAssertEqual(outcome?.batch?.byteCount, 4)
        XCTAssertEqual(outcome?.dropSample?.reason, .flowItems)
        XCTAssertEqual(outcome?.dropSample?.cumulativeDroppedItems, 9_996)
        XCTAssertEqual(generation.testLastInspectedItems, 4)
        XCTAssertEqual(generation.testRetainedBytes, 4)
        outcome = nil
        XCTAssertEqual(generation.testRetainedBytes, 0)
    }

    func testZeroLengthDatagramsAreBoundedByItemCount() {
        let (generation, flow) = makeFlow(items: 3, flowBytes: 1, generationBytes: 1)
        var outcome: UdpIngressStageOutcome? = flow.stage(
            datagrams: Array(repeating: Data(), count: 100),
            endpoints: nil)

        XCTAssertEqual(outcome?.batch?.itemCount, 3)
        XCTAssertEqual(outcome?.batch?.byteCount, 0)
        XCTAssertEqual(outcome?.dropSample?.reason, .flowItems)
        XCTAssertEqual(outcome?.dropSample?.cumulativeDroppedItems, 97)
        XCTAssertEqual(outcome?.dropSample?.cumulativeDroppedBytesLowerBound, 0)
        XCTAssertEqual(flow.testSnapshot.items, 3)
        outcome = nil
        XCTAssertEqual(flow.testSnapshot.items, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
    }

    func testAdmissiblePrefixPreservesEndpointMismatchAndPairing() {
        let (_, flow) = makeFlow(items: 3)
        let endpoints: [NWEndpoint] = [
            NWHostEndpoint(hostname: "192.0.2.1", port: "53"),
            NWHostEndpoint(hostname: "192.0.2.2", port: "54"),
        ]
        var outcome: UdpIngressStageOutcome? = flow.stage(
            datagrams: [Data([1]), Data([2]), Data([3]), Data([4])],
            endpoints: endpoints)

        #if DEBUG || RAMA_TESTING
            XCTAssertTrue(
                outcome?.batch?.testPayloadEquals(
                    [Data([1]), Data([2]), Data([3])], endpointCount: 2
                ) == true)
        #endif
        XCTAssertEqual(outcome?.batch?.sourceDatagramCount, 4)
        XCTAssertEqual(outcome?.batch?.sourceEndpointCount, 2)
        outcome = nil
    }

    func testCloseRejectsNewCaptureButOutstandingBatchStaysChargedUntilFinalAlias() {
        let (generation, flow) = makeFlow()
        var batch = flow.stage(datagrams: [Data([1, 2, 3])], endpoints: nil).batch
        XCTAssertEqual(generation.testRetainedBytes, 3)

        flow.close()
        let rejected = flow.stage(datagrams: [Data([4])], endpoints: nil)
        XCTAssertNil(rejected.batch)
        XCTAssertNil(rejected.dropSample, "normal teardown is not pressure telemetry")
        XCTAssertEqual(generation.testRetainedBytes, 3)

        var alias = batch
        batch = nil
        withExtendedLifetime(alias) {
            XCTAssertEqual(
                generation.testRetainedBytes, 3,
                "an alias must keep the exact allocation charged")
        }
        alias = nil
        XCTAssertEqual(generation.testRetainedBytes, 0)
        XCTAssertEqual(flow.testSnapshot.items, 0)
    }

    func testConcurrentAliasDropsRefundOnlyAfterFinalBatchOwner() {
        let (generation, flow) = makeFlow()
        var batch = flow.stage(
            datagrams: [Data([1, 2, 3, 4])], endpoints: nil
        ).batch
        let aliases = (0..<32).map { _ in
            Locked<UdpIngressStagedBatch?>(batch)
        }
        batch = nil

        DispatchQueue.concurrentPerform(iterations: aliases.count - 1) { index in
            aliases[index].withLock { $0 = nil }
        }
        XCTAssertEqual(generation.testRetainedItems, 1)
        XCTAssertEqual(generation.testRetainedBytes, 4)
        XCTAssertEqual(generation.testReservedItems, 1)
        XCTAssertEqual(generation.testReservedBytes, 4)

        aliases[aliases.count - 1].withLock { $0 = nil }
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testReservedBytes, 0)
    }

    func testPayloadStorageIsDestroyedBeforeCapacityRefund() {
        let (generation, flow) = makeFlow(
            items: 1, flowBytes: 8_192, generationBytes: 8_192)
        let retainedBytesSeenByDeallocator = Locked<[Int]>([])

        func makeBatch() -> UdpIngressStagedBatch? {
            let count = 4_096
            let bytes = UnsafeMutableRawPointer.allocate(
                byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
            bytes.initializeMemory(as: UInt8.self, repeating: 0xA5, count: count)
            let data = Data(
                bytesNoCopy: bytes,
                count: count,
                deallocator: .custom { pointer, _ in
                    retainedBytesSeenByDeallocator.withLock {
                        $0.append(generation.testRetainedBytes)
                    }
                    pointer.deallocate()
                })
            return flow.stage(datagrams: [data], endpoints: nil).batch
        }

        var batch = makeBatch()
        XCTAssertNotNil(batch)
        XCTAssertEqual(generation.testRetainedBytes, 4_096)
        XCTAssertTrue(retainedBytesSeenByDeallocator.withLock { $0.isEmpty })

        batch = nil
        XCTAssertEqual(retainedBytesSeenByDeallocator.withLock { $0 }, [4_096])
        XCTAssertEqual(generation.testRetainedBytes, 0)
        XCTAssertEqual(generation.testReservedBytes, 0)
    }

    func testFiveHundredFlowsShareOneExactGenerationCap() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 200,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 100))
        let flows = (0..<500).map { _ in UdpIngressFlowStaging(generation: generation) }
        let batches = Locked<[UdpIngressStagedBatch]>([])
        DispatchQueue.concurrentPerform(iterations: flows.count) { index in
            if let batch = flows[index]
                .stage(datagrams: [Data([0])], endpoints: nil).batch
            {
                batches.withLock { $0.append(batch) }
            }
        }

        XCTAssertEqual(batches.withLock { $0.count }, 100)
        XCTAssertEqual(generation.testRetainedItems, 100)
        XCTAssertEqual(generation.testRetainedBytes, 100)
        XCTAssertEqual(generation.testReservedItems, 100)
        XCTAssertEqual(generation.testReservedBytes, 100)
        let batchOwners = batches.withLock { batches -> [Locked<UdpIngressStagedBatch?>] in
            let owners = batches.map { Locked<UdpIngressStagedBatch?>($0) }
            batches.removeAll()
            return owners
        }
        DispatchQueue.concurrentPerform(iterations: batchOwners.count) { index in
            batchOwners[index].withLock { $0 = nil }
        }
        XCTAssertEqual(generation.testRetainedBytes, 0)
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    func testHealthyConcurrentStageAndReleaseNeverAcquireCoordinatorLock() {
        let flowCount = 2_048
        let bytesPerFlow = 8
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: flowCount,
                maxBytesPerFlow: bytesPerFlow,
                maxBytesPerGeneration: flowCount * bytesPerFlow),
            automaticScheduling: false)
        let flows = (0..<flowCount).map { _ in UdpIngressFlowStaging(generation: generation) }
        let batches = Locked<[UdpIngressStagedBatch]>([])
        let coordinatorLocksBefore = generation.testCoordinatorLockAcquisitions
        XCTAssertTrue(
            generation.testCapacityAtomicsAreLockFree,
            "the supported Apple targets must provide lock-free C11 u64 atomics")

        DispatchQueue.concurrentPerform(iterations: flowCount) { index in
            let outcome = flows[index].stage(
                datagrams: [Data(count: bytesPerFlow)], endpoints: nil)
            if let batch = outcome.batch {
                batches.withLock { $0.append(batch) }
            }
        }

        XCTAssertEqual(batches.withLock { $0.count }, flowCount)
        XCTAssertEqual(generation.testRetainedItems, flowCount)
        XCTAssertEqual(generation.testRetainedBytes, flowCount * bytesPerFlow)
        XCTAssertEqual(generation.testReservedItems, flowCount)
        XCTAssertEqual(generation.testReservedBytes, flowCount * bytesPerFlow)
        XCTAssertEqual(
            generation.testCoordinatorLockAcquisitions, coordinatorLocksBefore,
            "healthy atomic admission must not enter waiter/grant coordination")

        let retainedBatches = batches.withLock { batches -> [Locked<UdpIngressStagedBatch?>] in
            let owners = batches.map { Locked<UdpIngressStagedBatch?>($0) }
            batches.removeAll()
            return owners
        }
        DispatchQueue.concurrentPerform(iterations: retainedBatches.count) { index in
            retainedBatches[index].withLock { $0 = nil }
        }

        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(
            generation.testCoordinatorLockAcquisitions, coordinatorLocksBefore,
            "healthy atomic release must not enter waiter/grant coordination")
        // Keep flow teardown outside the measured healthy-release interval.
        // Optimized ARC may otherwise destroy each flow with its final batch,
        // correctly entering the coordinator to cancel that flow's state.
        withExtendedLifetime(flows) {}
    }

    func testPublishedWaiterGatePreventsNewcomerBargingBeforeAsyncWake() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 1,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1))
        let holder = UdpIngressFlowStaging(generation: generation)
        let oldest = UdpIngressFlowStaging(generation: generation)
        let newcomer = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        XCTAssertNotNil(held)

        let oldestOutcome = oldest.stage(datagrams: [Data([1])], endpoints: nil)
        XCTAssertEqual(oldestOutcome.blockedReason, .generationItems)
        let oldestBatch = Locked<UdpIngressStagedBatch?>(nil)
        let oldestGranted = DispatchSemaphore(value: 0)
        XCTAssertTrue(
            oldest.waitForCapacity(
                reason: oldestOutcome.blockedReason!, neededItems: 1, neededBytes: 1
            ) { ticket in
                oldestBatch.withLock {
                    $0 = oldest.stage(
                        datagrams: [Data([1])], endpoints: nil, grantTicket: ticket
                    ).batch
                }
                oldestGranted.signal()
            })
        XCTAssertEqual(generation.testWaiterGate, 1)
        XCTAssertEqual(generation.testWaiterCount, 1)

        // Hold the serial coordinator queue after the initial no-fit pass.
        // Releasing capacity therefore leaves a deterministic window in which
        // a ticket-zero newcomer races the already-published oldest waiter.
        let blockerStarted = DispatchSemaphore(value: 0)
        let allowCoordinator = DispatchSemaphore(value: 0)
        var coordinatorBlocked = true
        defer {
            if coordinatorBlocked { allowCoordinator.signal() }
        }
        generation.testBlockCoordinatorQueue(
            started: blockerStarted, until: allowCoordinator)
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 30), .success)

        held = nil
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        let barger = newcomer.stage(datagrams: [Data([2])], endpoints: nil)
        XCTAssertNil(barger.batch)
        XCTAssertEqual(barger.blockedReason, .generationItems)
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testWaiterGate, 1)

        allowCoordinator.signal()
        coordinatorBlocked = false
        XCTAssertEqual(
            oldestGranted.wait(timeout: .now() + 30), .success,
            "the oldest waiter did not receive released capacity")
        XCTAssertNotNil(oldestBatch.withLock { $0 })
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testWaiterGate, 0)
        XCTAssertEqual(generation.testRetainedItems, 1)
        XCTAssertEqual(generation.testReservedItems, 1)

        oldestBatch.withLock {
            $0 = nil
        }
        holder.close()
        oldest.close()
        newcomer.close()
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    func testCapacityWakeClearCoalescesRacingReleasesWithoutLosingFollowup() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 3,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 3))
        let holders = (0..<3).map { _ in
            UdpIngressFlowStaging(generation: generation)
        }
        let waiters = (0..<3).map { _ in
            UdpIngressFlowStaging(generation: generation)
        }
        let held = holders.map {
            Locked<UdpIngressStagedBatch?>(
                $0.stage(datagrams: [Data([0])], endpoints: nil).batch!)
        }
        let resumedBatches = Locked<[UdpIngressStagedBatch]>([])
        let resumed = DispatchSemaphore(value: 0)
        @Sendable func receiveGrant(
            waiter: UdpIngressFlowStaging, index: Int, ticket: UInt64
        ) {
            let outcome = waiter.stage(
                datagrams: [Data([UInt8(index)])], endpoints: nil,
                grantTicket: ticket)
            if let batch = outcome.batch {
                resumedBatches.withLock { $0.append(batch) }
                resumed.signal()
                return
            }
            // The deliberate post-issue pause can outlive the production
            // lease under load. Match the session's stale-ticket recovery;
            // only accepted payloads satisfy the release-delivery assertion.
            guard let reason = outcome.blockedReason else {
                XCTFail("a stale staging grant lost its capacity-pressure reason")
                return
            }
            XCTAssertTrue(waiter.waitForCapacity(
                reason: reason,
                neededItems: outcome.neededItems,
                neededBytes: outcome.neededBytes
            ) { ticket in receiveGrant(waiter: waiter, index: index, ticket: ticket) })
        }
        for (index, waiter) in waiters.enumerated() {
            XCTAssertTrue(
                waiter.waitForCapacity(
                    reason: .generationItems, neededItems: 1, neededBytes: 1
                ) { ticket in
                    receiveGrant(waiter: waiter, index: index, ticket: ticket)
                })
        }
        XCTAssertEqual(generation.testWaiterCount, 3)

        // Pause the first wake after it cleared the coalescing flag and
        // completed its bounded scan, but before it delivers the first grant.
        // Both releases in this window must coalesce into one additional turn.
        let firstScanFinished = DispatchSemaphore(value: 0)
        let allowFirstDelivery = DispatchSemaphore(value: 0)
        let firstHook = Locked(true)
        generation.testAfterCapacityWakeScan = {
            let shouldPause = firstHook.withLock { first -> Bool in
                guard first else { return false }
                first = false
                return true
            }
            if shouldPause {
                firstScanFinished.signal()
                allowFirstDelivery.wait()
            }
        }
        var firstDeliveryBlocked = true
        defer {
            if firstDeliveryBlocked { allowFirstDelivery.signal() }
            generation.testAfterCapacityWakeScan = nil
        }

        held[0].withLock { $0 = nil }
        XCTAssertEqual(firstScanFinished.wait(timeout: .now() + 30), .success)
        DispatchQueue.concurrentPerform(iterations: 2) { index in
            held[index + 1].withLock { $0 = nil }
        }
        allowFirstDelivery.signal()
        firstDeliveryBlocked = false

        for _ in waiters {
            XCTAssertEqual(
                resumed.wait(timeout: .now() + 30), .success,
                "a release after the flag clear was lost")
        }
        pollUntil("coalesced follow-up capacity wake did not run") {
            generation.testCapacityWakeTurns == 2
        }
        XCTAssertEqual(
            generation.testCapacityWakeTurns, 2,
            "two racing releases must schedule one follow-up turn")
        XCTAssertEqual(resumedBatches.withLock { $0.count }, 3)
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testReservedItems, 3)

        resumedBatches.withLock { $0.removeAll() }
        holders.forEach { $0.close() }
        waiters.forEach { $0.close() }
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    func testWaiterPublicationDuringReservationRollsBackAndPreservesExactCaps() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 2,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        let oldest = UdpIngressFlowStaging(generation: generation)
        let newcomer = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        XCTAssertNotNil(held)

        let newcomerReservedItem = DispatchSemaphore(value: 0)
        let allowNewcomerToFinish = DispatchSemaphore(value: 0)
        generation.testAfterItemReservation = {
            newcomerReservedItem.signal()
            allowNewcomerToFinish.wait()
        }
        let newcomerResult = Locked<UdpIngressStageOutcome?>(nil)
        let newcomerFinished = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            newcomerResult.withLock {
                $0 = newcomer.stage(datagrams: [Data()], endpoints: nil)
            }
            newcomerFinished.signal()
        }
        XCTAssertEqual(
            newcomerReservedItem.wait(timeout: .now() + 30), .success,
            "newcomer never reached its provisional item reservation")
        XCTAssertEqual(generation.testReservedItems, 2)
        XCTAssertEqual(generation.testReservedBytes, 1)

        let oldestGranted = DispatchSemaphore(value: 0)
        XCTAssertTrue(
            oldest.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1
            ) { ticket in
                oldest.completeWithoutStaging(grantTicket: ticket)
                oldestGranted.signal()
            })
        XCTAssertEqual(generation.testWaiterGate, 1)
        XCTAssertEqual(generation.testWaiterCount, 1)

        allowNewcomerToFinish.signal()
        XCTAssertEqual(
            newcomerFinished.wait(timeout: .now() + 30), .success,
            "newcomer did not finish its gate-loss rollback")
        generation.testAfterItemReservation = nil
        XCTAssertNil(newcomerResult.withLock { $0?.batch })
        XCTAssertEqual(newcomerResult.withLock { $0?.blockedReason }, .generationItems)
        XCTAssertEqual(generation.testReservationRollbacks, 1)
        XCTAssertEqual(generation.testRetainedItems, 1)
        XCTAssertEqual(generation.testRetainedBytes, 1)
        XCTAssertEqual(generation.testReservedItems, 1)
        XCTAssertEqual(generation.testReservedBytes, 1)

        held = nil
        XCTAssertEqual(oldestGranted.wait(timeout: .now() + 30), .success)
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testWaiterGate, 0)
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testReservedBytes, 0)

        var retry = newcomer.stage(datagrams: [Data()], endpoints: nil).batch
        XCTAssertNotNil(retry)
        XCTAssertEqual(generation.testRetainedItems, 1)
        XCTAssertEqual(generation.testRetainedBytes, 0)
        retry = nil
        holder.close()
        oldest.close()
        newcomer.close()
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    func testLoweredCapCannotStrandFullDiscoverySampleAheadOfFittingWaiter() {
        let high = UdpIngressStagingPolicy(
            maxItemsPerFlow: 2, maxItemsPerGeneration: 16,
            maxBytesPerFlow: 8, maxBytesPerGeneration: 8)
        let low = UdpIngressStagingPolicy(
            maxItemsPerFlow: 2, maxItemsPerGeneration: 16,
            maxBytesPerFlow: 4, maxBytesPerGeneration: 4)
        let budget = UdpIngressGenerationStagingBudget(
            policy: high, automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: budget)
        var held = holder.stage(datagrams: [Data(count: 7)], endpoints: nil).batch
        var released = holder.stage(datagrams: [Data(count: 1)], endpoints: nil).batch
        let oversized = (0..<8).map { _ in UdpIngressFlowStaging(generation: budget) }
        for flow in oversized {
            XCTAssertTrue(flow.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 8
            ) { _ in XCTFail("old oversized hint received a grant under the lower cap") })
        }
        withExtendedLifetime(released) {}
        released = nil
        XCTAssertGreaterThan(budget.testScanRemaining, udpIngressStagingMaxGrants)

        // The exact pass has filled its discovery sample but no speculative
        // callback has run. Lowering invalidates all four sampled sizes.
        budget.reconfigure(policy: low)
        withExtendedLifetime(held) {}
        held = nil
        let fitting = UdpIngressFlowStaging(generation: budget)
        let grants = Locked(0)
        XCTAssertTrue(fitting.waitForCapacity(
            reason: .generationBytes, neededItems: 1, neededBytes: 1
        ) { ticket in
            grants.withLock { $0 += 1 }
            fitting.completeWithoutStaging(grantTicket: ticket)
        })
        for _ in 0..<16 {
            budget.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
        }
        XCTAssertEqual(grants.withLock { $0 }, 1,
            "an invalid full discovery sample stranded a fitting waiter")
        XCTAssertEqual(budget.testScanRemaining, 0)
        fitting.close()
        oversized.forEach { $0.close() }
        holder.close()
        XCTAssertEqual(budget.testReservedBytes, 0)
        XCTAssertEqual(budget.testReservedItems, 0)
        XCTAssertEqual(budget.testWaiterCount, 0)
    }

    func testReconfigureLowerThenRaiseKeepsOneFifoAndFlowLocalSnapshot() {
        let high = UdpIngressStagingPolicy(
            maxItemsPerFlow: 2,
            maxItemsPerGeneration: 2,
            maxBytesPerFlow: 8,
            maxBytesPerGeneration: 8)
        let low = UdpIngressStagingPolicy(
            maxItemsPerFlow: 1,
            maxItemsPerGeneration: 1,
            maxBytesPerFlow: 4,
            maxBytesPerGeneration: 4)
        let budget = UdpIngressGenerationStagingBudget(
            policy: high, automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: budget, policy: high)
        let oldest = UdpIngressFlowStaging(generation: budget, policy: high)
        var held = holder.stage(
            datagrams: [Data(count: 3), Data(count: 3)], endpoints: nil
        ).batch
        XCTAssertEqual(held?.itemCount, 2)
        XCTAssertEqual(held?.byteCount, 6)

        let blocked = oldest.stage(datagrams: [Data(count: 5)], endpoints: nil)
        XCTAssertEqual(blocked.blockedReason, .generationItems)
        let granted = Locked<[UInt64]>([])
        XCTAssertTrue(
            oldest.waitForCapacity(
                reason: blocked.blockedReason!, neededItems: 1, neededBytes: 5
            ) { ticket in
                granted.withLock { $0.append(ticket) }
                oldest.completeWithoutStaging(grantTicket: ticket)
            })
        XCTAssertEqual(budget.testWaiterCount, 1)

        budget.reconfigure(policy: low)
        XCTAssertEqual(budget.testGlobalMaxItems, 1)
        XCTAssertEqual(budget.testGlobalMaxBytes, 4)
        XCTAssertEqual(granted.withLock { $0.count }, 0)
        held = nil
        XCTAssertEqual(budget.testRetainedItems, 0)
        XCTAssertEqual(budget.testRetainedBytes, 0)
        XCTAssertEqual(
            granted.withLock { $0.count }, 0,
            "a request larger than lowered global caps must remain queued")
        XCTAssertEqual(budget.testWaiterCount, 1)
        XCTAssertEqual(budget.testWaiterGate, 1)

        let lowSnapshotFlow = UdpIngressFlowStaging(generation: budget)
        budget.reconfigure(policy: high)
        XCTAssertEqual(granted.withLock { $0.count }, 1)
        XCTAssertEqual(budget.testWaiterCount, 0)
        XCTAssertEqual(budget.testGrantCount, 0)
        XCTAssertEqual(budget.testWaiterGate, 0)

        let stillLocallyOversized = lowSnapshotFlow.stage(
            datagrams: [Data(count: 5)], endpoints: nil)
        XCTAssertEqual(stillLocallyOversized.blockedReason, .oversizedBytes)
        XCTAssertNil(stillLocallyOversized.dropSample)
        var oldSnapshotBatch = holder.stage(
            datagrams: [Data(count: 8)], endpoints: nil
        ).batch
        XCTAssertNotNil(oldSnapshotBatch)
        oldSnapshotBatch = nil

        holder.close()
        oldest.close()
        lowSnapshotFlow.close()
        XCTAssertEqual(budget.testRetainedItems, 0)
        XCTAssertEqual(budget.testReservedItems, 0)
        XCTAssertEqual(budget.testWaiterCount, 0)
    }

    func testFlowAndGenerationByteReasonsAreDistinct() {
        let (_, flowLimited) = makeFlow(items: 4, flowBytes: 2, generationBytes: 10)
        var flowHeld = flowLimited.stage(datagrams: [Data([1])], endpoints: nil).batch
        let flowDrop = flowLimited.stage(datagrams: [Data([2, 3])], endpoints: nil)
        withExtendedLifetime(flowHeld) {
            XCTAssertNil(flowDrop.batch)
            XCTAssertEqual(flowDrop.dropSample?.reason, .flowBytes)
            XCTAssertEqual(flowDrop.dropSample?.cumulativeDroppedBytesLowerBound, 2)
        }
        flowHeld = nil

        let (_, generationLimited) = makeFlow(items: 4, flowBytes: 10, generationBytes: 2)
        var generationHeld = generationLimited.stage(
            datagrams: [Data([1])], endpoints: nil
        ).batch
        let generationDrop = generationLimited.stage(datagrams: [Data([2, 3])], endpoints: nil)
        withExtendedLifetime(generationHeld) {
            XCTAssertNil(generationDrop.batch)
            XCTAssertEqual(generationDrop.dropSample?.reason, .generationBytes)
            XCTAssertEqual(generationDrop.dropSample?.cumulativeDroppedBytesLowerBound, 2)
        }
        generationHeld = nil
    }

    func testPermanentlyOversizedFirstDatagramIsNonretryable() {
        let (_, flowLimited) = makeFlow(items: 4, flowBytes: 2, generationBytes: 10)
        let flowDrop = flowLimited.stage(datagrams: [Data(count: 3)], endpoints: nil)
        XCTAssertNil(flowDrop.batch)
        XCTAssertEqual(flowDrop.blockedReason, .oversizedBytes)
        XCTAssertNil(flowDrop.dropSample)
        XCTAssertFalse(
            flowLimited.waitForCapacity(
                reason: .oversizedBytes,
                neededItems: flowDrop.neededItems,
                neededBytes: flowDrop.neededBytes
            ) { _ in XCTFail("oversized input must never arm a capacity waiter") })

        let (_, generationLimited) = makeFlow(items: 4, flowBytes: 10, generationBytes: 2)
        let generationDrop = generationLimited.stage(
            datagrams: [Data(count: 3)], endpoints: nil)
        XCTAssertNil(generationDrop.batch)
        XCTAssertEqual(generationDrop.blockedReason, .oversizedBytes)
        XCTAssertNil(generationDrop.dropSample)
    }

    func testTerminalReasonsCannotArmCapacityWaiters() {
        let (_, flow) = makeFlow()
        for reason in [UdpIngressStagingDropReason.oversizedBytes, .closed] {
            XCTAssertFalse(
                flow.waitForCapacity(reason: reason, neededItems: 1, neededBytes: 1) { _ in
                    XCTFail("terminal reason must never receive a capacity grant")
                })
        }
        XCTAssertFalse(flow.testWaitSnapshot.waiting)
        XCTAssertEqual(flow.testWaitSnapshot.activeTicket, 0)
    }

    func testGenerationItemReasonBoundsZeroLengthDatagramsAcrossFlows() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 1,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1))
        let first = UdpIngressFlowStaging(generation: generation)
        let second = UdpIngressFlowStaging(generation: generation)
        var held = first.stage(datagrams: [Data()], endpoints: nil).batch
        let rejected = second.stage(datagrams: [Data()], endpoints: nil)

        XCTAssertNil(rejected.batch)
        XCTAssertEqual(rejected.dropSample?.reason, .generationItems)
        withExtendedLifetime(held) {
            XCTAssertEqual(generation.testRetainedItems, 1)
        }
        held = nil
        XCTAssertEqual(generation.testRetainedItems, 0)
    }





    func testGenerationCoordinatorCapsFourQuietGrantsAndFifthAdvancesOnLeaseExpiry() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 10,
                maxBytesPerFlow: 4,
                maxBytesPerGeneration: 4),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data(count: 4)], endpoints: nil).batch
        let flows = (0..<5).map { _ in UdpIngressFlowStaging(generation: generation) }
        let granted = Locked<[(Int, UInt64)]>([])
        for (index, flow) in flows.enumerated() {
            let rejected = flow.stage(datagrams: [Data([1])], endpoints: nil)
            XCTAssertEqual(rejected.blockedReason, .generationBytes)
            XCTAssertTrue(
                flow.waitForCapacity(
                    reason: rejected.blockedReason!,
                    neededItems: rejected.neededItems,
                    neededBytes: rejected.neededBytes
                ) { ticket in
                    granted.withLock { $0.append((index, ticket)) }
                })
        }

        withExtendedLifetime(held) {}
        held = nil
        XCTAssertEqual(granted.withLock { $0.map(\.0) }, [0, 1, 2, 3])
        XCTAssertEqual(generation.testGrantCount, 4)
        XCTAssertEqual(generation.testPeakGrantCount, 4)
        generation.testRunCoordinator(now: UInt64.max)
        XCTAssertEqual(granted.withLock { $0.map(\.0) }, [0, 1, 2, 3, 4])
        XCTAssertEqual(generation.testGrantCount, 1)

        flows.forEach { $0.close() }
        holder.close()
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
    }

    func testGenerationGrantCloseReleasesAndAdvancesNextWaiter() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 10,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        let first = UdpIngressFlowStaging(generation: generation)
        let second = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        let granted = Locked<[Int]>([])
        for (index, flow) in [first, second].enumerated() {
            let rejected = flow.stage(datagrams: [Data([1])], endpoints: nil)
            XCTAssertTrue(
                flow.waitForCapacity(
                    reason: rejected.blockedReason!, neededItems: 1, neededBytes: 1
                ) { _ in granted.withLock { $0.append(index) } })
        }
        withExtendedLifetime(held) {}
        held = nil
        XCTAssertEqual(granted.withLock { $0 }, [0])
        XCTAssertEqual(generation.testGrantCount, 1)
        first.close()
        XCTAssertEqual(granted.withLock { $0 }, [0, 1])
        XCTAssertEqual(generation.testGrantCount, 1)
        second.close()
        holder.close()
        XCTAssertEqual(generation.testGrantCount, 0)
    }

    func testCloseWhileGenerationWaitingCancelsBeforeCapacityReturns() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 2,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        let waiter = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        let rejected = waiter.stage(datagrams: [Data([1])], endpoints: nil)

        XCTAssertEqual(rejected.blockedReason, .generationBytes)
        XCTAssertTrue(
            waiter.waitForCapacity(
                reason: rejected.blockedReason!, neededItems: 1, neededBytes: 1
            ) { _ in XCTFail("a closed waiter must never receive a late grant") })
        XCTAssertEqual(generation.testWaiterCount, 1)
        XCTAssertTrue(waiter.testWaitSnapshot.waiting)

        waiter.close()
        XCTAssertTrue(waiter.testSnapshot.closed)
        XCTAssertFalse(waiter.testWaitSnapshot.waiting)
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testGrantCount, 0)

        withExtendedLifetime(held) {}
        held = nil
        generation.testRunCoordinator(now: UInt64.max)
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
        holder.close()
    }

    func testDroppingFlowOwnerCancelsQueuedWaiterAndClearsGate() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 1,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        var flow: UdpIngressFlowStaging? = UdpIngressFlowStaging(generation: generation)
        XCTAssertTrue(
            flow!.waitForCapacity(
                reason: .generationItems, neededItems: 1, neededBytes: 1
            ) { _ in XCTFail("a deinitialized owner must not receive a grant") })
        XCTAssertEqual(generation.testWaiterCount, 1)
        XCTAssertEqual(generation.testWaiterGate, 1)

        flow = nil
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testWaiterGate, 0)
        XCTAssertEqual(generation.testGrantCount, 0)
        withExtendedLifetime(held) {
            XCTAssertEqual(generation.testReservedItems, 1, "only the holder remains charged")
        }
        held = nil
        holder.close()
        XCTAssertEqual(generation.testReservedItems, 0)

        // The same idempotent deinit path must revoke an already delivered
        // provisional grant immediately, without waiting for its lease timer.
        var grantedFlow: UdpIngressFlowStaging? = UdpIngressFlowStaging(
            generation: generation)
        let deliveredTicket = Locked<UInt64>(0)
        XCTAssertTrue(
            grantedFlow!.waitForCapacity(
                reason: .generationItems, neededItems: 1, neededBytes: 1
            ) { ticket in deliveredTicket.withLock { $0 = ticket } })
        XCTAssertNotEqual(deliveredTicket.withLock { $0 }, 0)
        XCTAssertEqual(generation.testGrantCount, 1)
        XCTAssertEqual(generation.testReservedItems, 1)

        grantedFlow = nil
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testWaiterGate, 0)
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    func testCloseDuringGrantCallbackReleasesCreditAndAdvancesNextWaiter() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 3,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        let first = UdpIngressFlowStaging(generation: generation)
        let second = UdpIngressFlowStaging(generation: generation)
        let held = Locked<UdpIngressStagedBatch?>(
            holder.stage(datagrams: [Data([0])], endpoints: nil).batch)
        let firstTicket = Locked<UInt64>(0)
        let secondTicket = Locked<UInt64>(0)
        let firstCallbackStarted = DispatchSemaphore(value: 0)
        let allowFirstCallbackReturn = DispatchSemaphore(value: 0)

        let firstCallback: @Sendable (UInt64) -> Void = { ticket in
            firstTicket.withLock { $0 = ticket }
            firstCallbackStarted.signal()
            allowFirstCallbackReturn.wait()
        }
        let secondCallback: @Sendable (UInt64) -> Void = { ticket in
            secondTicket.withLock { $0 = ticket }
        }
        let waitingFlows: [(UdpIngressFlowStaging, @Sendable (UInt64) -> Void)] = [
            (first, firstCallback), (second, secondCallback),
        ]
        for (flow, callback) in waitingFlows {
            let rejected = flow.stage(datagrams: [Data([1])], endpoints: nil)
            XCTAssertTrue(
                flow.waitForCapacity(
                    reason: rejected.blockedReason!, neededItems: 1, neededBytes: 1,
                    onReady: callback))
        }

        let releaseFinished = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            held.withLock { $0 = nil }
            releaseFinished.signal()
        }
        XCTAssertEqual(
            firstCallbackStarted.wait(timeout: .now() + 30), .success,
            "grant callback did not start")
        XCTAssertNotEqual(firstTicket.withLock { $0 }, 0)
        XCTAssertEqual(generation.testGrantCount, 1)
        XCTAssertEqual(first.testWaitSnapshot.activeTicket, firstTicket.withLock { $0 })

        // `receiveGenerationGrant` has installed the ticket and entered the
        // consumer callback. Closing during that delivery must release the
        // provisional credit exactly once and synchronously advance FIFO.
        first.close()
        first.close()
        XCTAssertTrue(first.testSnapshot.closed)
        XCTAssertEqual(first.testWaitSnapshot.activeTicket, 0)
        XCTAssertNotEqual(secondTicket.withLock { $0 }, 0)
        XCTAssertEqual(second.testWaitSnapshot.activeTicket, secondTicket.withLock { $0 })
        XCTAssertEqual(generation.testGrantCount, 1)

        allowFirstCallbackReturn.signal()
        XCTAssertEqual(
            releaseFinished.wait(timeout: .now() + 30), .success,
            "in-flight grant callback did not return")
        second.close()
        holder.close()
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
    }

    func testStaleGrantFallsBackToExactAdmissionAndReparks() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 10,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        let waiter = UdpIngressFlowStaging(generation: generation)
        let thief = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        let tickets = Locked<[UInt64]>([])
        let initialDrop = waiter.stage(datagrams: [Data([1])], endpoints: nil)
        XCTAssertTrue(
            waiter.waitForCapacity(
                reason: initialDrop.blockedReason!, neededItems: 1, neededBytes: 1
            ) { ticket in tickets.withLock { $0.append(ticket) } })
        withExtendedLifetime(held) {}
        held = nil
        let staleTicket = tickets.withLock { $0[0] }
        generation.testRunCoordinator(now: UInt64.max)
        XCTAssertEqual(generation.testGrantCount, 0)

        var stolen = thief.stage(datagrams: [Data([9])], endpoints: nil).batch
        let late = waiter.stage(
            datagrams: [Data([2])], endpoints: nil, grantTicket: staleTicket)
        XCTAssertNil(late.batch)
        XCTAssertEqual(late.blockedReason, .generationBytes)
        XCTAssertTrue(
            waiter.waitForCapacity(
                reason: late.blockedReason!, neededItems: 1, neededBytes: 1
            ) { ticket in tickets.withLock { $0.append(ticket) } })
        withExtendedLifetime(stolen) {}
        stolen = nil
        XCTAssertEqual(tickets.withLock { $0.count }, 2)
        XCTAssertNotEqual(tickets.withLock { $0[1] }, staleTicket)

        waiter.close()
        thief.close()
        holder.close()
    }

    func testGenerationGrantCanArriveDuringArmWithoutMissedWake() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 1,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let flow = UdpIngressFlowStaging(generation: generation)
        let tickets = Locked<[UInt64]>([])
        XCTAssertTrue(
            flow.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1
            ) { ticket in tickets.withLock { $0.append(ticket) } })
        let granted = tickets.withLock { $0 }
        XCTAssertEqual(granted.count, 1)
        let ticket = granted[0]
        XCTAssertNotEqual(ticket, 0)
        var staged: UdpIngressStageOutcome? = flow.stage(
            datagrams: [Data([1])], endpoints: nil, grantTicket: ticket)
        XCTAssertNotNil(staged?.batch)
        staged = nil
        flow.close()
        XCTAssertEqual(generation.testGrantCount, 0)
    }

    func testErrorOrEofCompletionReleasesActiveGrantImmediately() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 1,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1),
            automaticScheduling: false)
        let flow = UdpIngressFlowStaging(generation: generation)
        let tickets = Locked<[UInt64]>([])
        XCTAssertTrue(
            flow.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1
            ) { ticket in tickets.withLock { $0.append(ticket) } })
        let ticket = tickets.withLock { $0[0] }
        XCTAssertEqual(generation.testGrantCount, 1)
        flow.completeWithoutStaging(grantTicket: ticket)
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(flow.testWaitSnapshot.activeTicket, 0)
        flow.close()
    }

    func testEightThousandOneHundredNinetyTwoNonfitWaiterRegistrationsStayLinear() {
        let flowCount = 8_192
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: flowCount + 1,
                maxBytesPerFlow: 10,
                maxBytesPerGeneration: 10),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data(count: 10)], endpoints: nil).batch
        var flows: [UdpIngressFlowStaging] = []
        flows.reserveCapacity(flowCount)
        let beforeRegistrations = generation.testCoordinatorInspections

        for _ in 0..<flowCount {
            let flow = UdpIngressFlowStaging(generation: generation)
            let rejected = flow.stage(datagrams: [Data(count: 2)], endpoints: nil)
            XCTAssertEqual(rejected.blockedReason, .generationBytes)
            XCTAssertTrue(
                flow.waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: 2
                ) { _ in XCTFail("nonfitting waiter received a grant") })
            flows.append(flow)
        }

        while generation.testScanRemaining > 0 {
            let before = generation.testCoordinatorInspections
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            XCTAssertLessThanOrEqual(
                generation.testCoordinatorInspections - before,
                UInt64(udpIngressStagingMaxInspectionsPerTurn))
        }
        XCTAssertEqual(
            generation.testCoordinatorInspections - beforeRegistrations,
            UInt64(flowCount),
            "each new nonfitting tail is inspected once, not by restarting the FIFO")
        XCTAssertLessThanOrEqual(
            generation.testMaxCoordinatorInspectionsPerTurn,
            udpIngressStagingMaxInspectionsPerTurn)
        let quiescent = generation.testCoordinatorInspections
        generation.testRunCoordinator(now: UInt64.max)
        XCTAssertEqual(generation.testCoordinatorInspections, quiescent)
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertLessThanOrEqual(generation.testPeakGrantCount, udpIngressStagingMaxGrants)

        flows.forEach { $0.close() }
        withExtendedLifetime(held) {}
        held = nil
        holder.close()
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
    }

    func testAutomaticEightThousandOneHundredNinetyTwoWaiterBurstQuiescesWithLinearWork() {
        let flowCount = 8_192
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: flowCount + 1,
                maxBytesPerFlow: 10,
                maxBytesPerGeneration: 10))
        let holder = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data(count: 10)], endpoints: nil).batch
        let flows = Locked<[UdpIngressFlowStaging]>([])
        let setupFailures = Locked(0)
        let registrationsFinished = DispatchSemaphore(value: 0)
        let before = generation.testCoordinatorInspections

        DispatchQueue.global(qos: .userInitiated).async {
            var localFlows: [UdpIngressFlowStaging] = []
            localFlows.reserveCapacity(flowCount)
            for _ in 0..<flowCount {
                let flow = UdpIngressFlowStaging(generation: generation)
                let rejected = flow.stage(
                    datagrams: [Data(count: 2)], endpoints: nil)
                if rejected.blockedReason != .generationBytes {
                    setupFailures.withLock { $0 += 1 }
                }
                if !flow.waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: 2,
                    onReady: { _ in
                        XCTFail("nonfitting waiter received a grant")
                    })
                {
                    setupFailures.withLock { $0 += 1 }
                }
                localFlows.append(flow)
            }
            flows.withLock { $0 = localFlows }
            registrationsFinished.signal()
        }
        XCTAssertEqual(
            registrationsFinished.wait(timeout: .now() + 60), .success,
            "automatic 8k waiter burst exceeded the wall-time watchdog")
        XCTAssertEqual(setupFailures.withLock { $0 }, 0)
        pollUntil("automatic 8k waiter burst did not quiesce") {
            generation.testScanRemaining == 0
        }

        let quiescentInspections = generation.testCoordinatorInspections
        XCTAssertLessThanOrEqual(
            quiescentInspections - before,
            UInt64(flowCount + udpIngressStagingMaxInspectionsPerTurn),
            "registration/continuation interleaving must remain linear")
        XCTAssertLessThanOrEqual(
            generation.testMaxCoordinatorInspectionsPerTurn,
            udpIngressStagingMaxInspectionsPerTurn)
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testLeaseTimerReprograms, 0)

        // A quiescent no-fit pass must not self-reschedule or spin timers.
        let remainedQuiescent = DispatchSemaphore(value: 0)
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(100)) {
            remainedQuiescent.signal()
        }
        XCTAssertEqual(remainedQuiescent.wait(timeout: .now() + 30), .success)
        XCTAssertEqual(generation.testCoordinatorInspections, quiescentInspections)
        XCTAssertEqual(generation.testLeaseTimerReprograms, 0)

        flows.withLock { $0 }.forEach { $0.close() }
        withExtendedLifetime(held) {}
        held = nil
        holder.close()
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
    }

    func testBoundedRotationFindsSmallTailBehindLargeWaiters() {
        let largeCount = 64
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 2,
                maxItemsPerGeneration: 100,
                maxBytesPerFlow: 2,
                maxBytesPerGeneration: 2),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var released = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        var retained = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        var flows: [UdpIngressFlowStaging] = []
        let granted = Locked<[Int]>([])
        for index in 0..<largeCount {
            let flow = UdpIngressFlowStaging(generation: generation)
            let rejected = flow.stage(datagrams: [Data(count: 2)], endpoints: nil)
            XCTAssertTrue(
                flow.waitForCapacity(
                    reason: rejected.blockedReason!, neededItems: 1, neededBytes: 2
                ) { _ in granted.withLock { $0.append(index) } })
            flows.append(flow)
        }
        let small = UdpIngressFlowStaging(generation: generation)
        let smallDrop = small.stage(datagrams: [Data([1])], endpoints: nil)
        XCTAssertTrue(
            small.waitForCapacity(
                reason: smallDrop.blockedReason!, neededItems: 1, neededBytes: 1
            ) { _ in granted.withLock { $0.append(largeCount) } })
        flows.append(small)

        let beforeRelease = generation.testCoordinatorInspections
        withExtendedLifetime(released) {}
        released = nil
        for _ in 0..<3 where granted.withLock({ !$0.contains(largeCount) }) {
            let before = generation.testCoordinatorInspections
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            XCTAssertLessThanOrEqual(
                generation.testCoordinatorInspections - before,
                UInt64(udpIngressStagingMaxInspectionsPerTurn))
        }
        XCTAssertTrue(granted.withLock { $0.contains(largeCount) })
        XCTAssertLessThanOrEqual(
            generation.testCoordinatorInspections - beforeRelease,
            UInt64((largeCount + 1) + udpIngressStagingMaxInspectionsPerTurn))
        XCTAssertLessThanOrEqual(generation.testPeakGrantCount, udpIngressStagingMaxGrants)

        flows.forEach { $0.close() }
        withExtendedLifetime(retained) {}
        retained = nil
        holder.close()
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
    }

    func testAutomaticSchedulingFindsFittingTailWithinOneBoundedPass() {
        let largeCount = 512
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 2,
                maxItemsPerGeneration: largeCount + 16,
                maxBytesPerFlow: 3,
                maxBytesPerGeneration: 3))
        let holder = UdpIngressFlowStaging(generation: generation)
        var released = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        var retained = holder.stage(datagrams: [Data(count: 2)], endpoints: nil).batch

        let large = (0..<largeCount).map { _ in
            UdpIngressFlowStaging(generation: generation)
        }
        for flow in large {
            XCTAssertTrue(
                flow.waitForCapacity(
                    reason: .generationBytes, neededItems: 1, neededBytes: 2
                ) { [weak flow] ticket in
                    // After the exact fitting tail has run, a discarded-size
                    // hint may receive one bounded partial discovery read.
                    flow?.completeWithoutStaging(grantTicket: ticket)
                })
        }
        let small = UdpIngressFlowStaging(generation: generation)
        let smallGranted = DispatchSemaphore(value: 0)
        let smallTicket = Locked<UInt64>(0)
        let inspectionsAtSmallGrant = Locked<UInt64>(0)
        XCTAssertTrue(
            small.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1
            ) { ticket in
                smallTicket.withLock { $0 = ticket }
                inspectionsAtSmallGrant.withLock {
                    $0 = generation.testCoordinatorInspections
                }
                // Consume the short production lease from the callback so
                // scheduler delay after fulfillment cannot affect cleanup.
                small.completeWithoutStaging(grantTicket: ticket)
                smallGranted.signal()
            })
        XCTAssertEqual(generation.testWaiterCount, largeCount + 1)
        XCTAssertEqual(generation.testGrantCount, 0)

        // Registration deliberately occurs against a full byte budget. Wait
        // for that finite no-fit pass to quiesce before measuring the release
        // edge; the 30-second cap is only a deadlock watchdog, not a scheduler
        // latency assertion.
        pollUntil("automatic coordinator did not quiesce the initial no-fit pass") {
            generation.testScanRemaining == 0
        }
        let beforeWake = generation.testCoordinatorInspections
        withExtendedLifetime(released) {}
        released = nil
        XCTAssertEqual(
            smallGranted.wait(timeout: .now() + 30), .success,
            "automatic coordinator did not reach the fitting tail")

        XCTAssertNotEqual(smallTicket.withLock { $0 }, 0)
        XCTAssertEqual(
            inspectionsAtSmallGrant.withLock { $0 } - beforeWake,
            UInt64(largeCount + 1))
        // The fitting tail has completed. The coordinator may now be between
        // issuing and delivering one of the older partial discovery grants.
        XCTAssertLessThanOrEqual(generation.testGrantCount, udpIngressStagingMaxGrants)
        XCTAssertLessThanOrEqual(generation.testPeakGrantCount, udpIngressStagingMaxGrants)

        small.close()
        large.forEach { $0.close() }
        withExtendedLifetime(retained) {}
        retained = nil
        holder.close()
        pollUntil("already-issued discovery did not settle after every flow closed") {
            generation.testGrantCount == 0
        }
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
    }

    func testPartialHeadroomDiscoversSmallerNextDatagramWithoutReleasingOtherBatches() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 4, maxItemsPerGeneration: 8,
                maxBytesPerFlow: 2_048, maxBytesPerGeneration: 2_048),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        let flow = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data(count: 1_024)], endpoints: nil).batch
        let rejected = flow.stage(datagrams: [Data(count: 1_350)], endpoints: nil)
        XCTAssertEqual(rejected.blockedReason, .generationBytes)
        let tickets = Locked<[UInt64]>([])
        XCTAssertTrue(flow.waitForCapacity(
            reason: rejected.blockedReason!, neededItems: 1, neededBytes: 1_350
        ) { ticket in tickets.withLock { $0.append(ticket) } })
        XCTAssertTrue(tickets.withLock { $0.isEmpty }, "discovery must leave the caller's stack")
        generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
        guard let ticket = tickets.withLock({ $0.first }) else {
            return XCTFail("the discarded large packet must not hide a later small packet")
        }
        XCTAssertEqual(generation.testReservedBytes, 2_048)
        let endpoint = NWHostEndpoint(hostname: "192.0.2.1", port: "443")
        var small = flow.stage(
            datagrams: [Data(repeating: 0xAC, count: 64)], endpoints: [endpoint],
            grantTicket: ticket).batch
        XCTAssertEqual(small?.byteCount, 64)
        XCTAssertEqual(small?.itemCount, 1)
        XCTAssertTrue(small?.testPayloadEquals(
            [Data(repeating: 0xAC, count: 64)], endpointCount: 1) == true)
        XCTAssertEqual(generation.testReservedBytes, 1_088)
        XCTAssertEqual(generation.testRetainedBytes, 1_088)
        small = nil
        withExtendedLifetime(held) {}
        held = nil
        flow.close()
        holder.close()
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
    }

    func testNonfittingDiscoveryWaitsForPhysicalReleaseBeforeAnotherAttempt() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 4, maxItemsPerGeneration: 8,
                maxBytesPerFlow: 2_048, maxBytesPerGeneration: 2_048),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        let flow = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data(count: 1_024)], endpoints: nil).batch
        var released = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        let tickets = Locked<[UInt64]>([])
        func park() {
            XCTAssertTrue(flow.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1_350
            ) { ticket in tickets.withLock { $0.append(ticket) } })
        }
        XCTAssertNil(flow.stage(datagrams: [Data(count: 1_350)], endpoints: nil).batch)
        park()
        generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
        guard let first = tickets.withLock({ $0.first }) else {
            return XCTFail("initial partial discovery was not issued")
        }
        let rejected = flow.stage(
            datagrams: [Data(count: 1_350)], endpoints: nil, grantTicket: first)
        XCTAssertNil(rejected.batch, "discovery cannot admit a physically nonfitting payload")
        XCTAssertEqual(generation.testReservedBytes, 1_025)
        park()
        let quiescent = generation.testCoordinatorInspections
        for _ in 0..<100 { generation.testRunCoordinator(now: UInt64.max) }
        XCTAssertEqual(tickets.withLock { $0.count }, 1)
        XCTAssertEqual(generation.testCoordinatorInspections, quiescent)
        XCTAssertEqual(generation.testGrantCount, 0)

        withExtendedLifetime(released) {}
        released = nil
        generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
        XCTAssertEqual(tickets.withLock { $0.count }, 2)
        flow.close()
        withExtendedLifetime(held) {}
        held = nil
        holder.close()
        XCTAssertEqual(generation.testReservedBytes, 0)
        XCTAssertEqual(generation.testReservedItems, 0)
        XCTAssertEqual(generation.testWaiterCount, 0)
    }

    func testPartialDiscoveryPreservesOldestOpportunityAndUnlinksCancelledCandidates() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 2, maxItemsPerGeneration: 100,
                maxBytesPerFlow: 10, maxBytesPerGeneration: 10),
            automaticScheduling: false)
        let holder = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data(count: 9)], endpoints: nil).batch
        let flows = (0..<65).map { _ in UdpIngressFlowStaging(generation: generation) }
        let grants = Locked<[(Int, UInt64)]>([])
        for (index, flow) in flows.enumerated() {
            XCTAssertTrue(flow.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 2
            ) { ticket in grants.withLock { $0.append((index, ticket)) } })
        }
        flows[0].close()
        for _ in 0..<4 where grants.withLock({ $0.isEmpty }) {
            let before = generation.testCoordinatorInspections
            generation.testRunCoordinator(now: DispatchTime.now().uptimeNanoseconds)
            XCTAssertLessThanOrEqual(
                generation.testCoordinatorInspections - before,
                UInt64(udpIngressStagingMaxInspectionsPerTurn))
        }
        XCTAssertEqual(grants.withLock { $0.map(\.0) }, [1])
        XCTAssertEqual(generation.testReservedBytes, 10)
        flows.forEach { $0.close() }
        XCTAssertEqual(generation.testWaiterCount, 0)
        XCTAssertEqual(generation.testGrantCount, 0)
        generation.testRunCoordinator(now: UInt64.max)
        XCTAssertEqual(grants.withLock { $0.count }, 1)
        withExtendedLifetime(held) {}
        held = nil
        holder.close()
        XCTAssertEqual(generation.testReservedBytes, 0)
    }

    func testHealthyStageReleaseDoesNotReprogramDisarmedLeaseTimer() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 4,
                maxItemsPerGeneration: 16,
                maxBytesPerFlow: 64,
                maxBytesPerGeneration: 256))
        let flow = UdpIngressFlowStaging(generation: generation)

        for _ in 0..<1_000 {
            let batch = flow.stage(datagrams: [Data([1])], endpoints: nil).batch
            XCTAssertNotNil(batch)
            withExtendedLifetime(batch) {}
        }

        XCTAssertEqual(generation.testLeaseTimerReprograms, 0)
        XCTAssertEqual(generation.testGrantCount, 0)
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
        flow.close()
    }

    func testLeaseTimerProgramsOnlyOnGrantDeadlineTransitions() {
        let generation = UdpIngressGenerationStagingBudget(
            policy: UdpIngressStagingPolicy(
                maxItemsPerFlow: 1,
                maxItemsPerGeneration: 2,
                maxBytesPerFlow: 1,
                maxBytesPerGeneration: 1))
        let holder = UdpIngressFlowStaging(generation: generation)
        let waiter = UdpIngressFlowStaging(generation: generation)
        var held = holder.stage(datagrams: [Data([0])], endpoints: nil).batch
        let resumedBatch = Locked<UdpIngressStagedBatch?>(nil)
        let resumed = DispatchSemaphore(value: 0)

        XCTAssertTrue(
            waiter.waitForCapacity(
                reason: .generationBytes, neededItems: 1, neededBytes: 1
            ) { ticket in
                resumedBatch.withLock { batch in
                    batch = waiter.stage(
                        datagrams: [Data([1])], endpoints: nil,
                        grantTicket: ticket
                    ).batch
                }
                resumed.signal()
            })
        XCTAssertEqual(generation.testLeaseTimerReprograms, 0)

        withExtendedLifetime(held) {}
        held = nil
        XCTAssertEqual(
            resumed.wait(timeout: .now() + 30), .success,
            "capacity release did not drive the coalesced coordinator wake")
        XCTAssertNotNil(resumedBatch.withLock { $0 })
        XCTAssertEqual(
            generation.testLeaseTimerReprograms, 2,
            "one grant arm and its exact consume/disarm are the only timer programs")
        XCTAssertEqual(generation.testGrantCount, 0)

        resumedBatch.withLock { batch in
            batch = nil
        }
        waiter.close()
        holder.close()
        XCTAssertEqual(generation.testLeaseTimerReprograms, 2)
        XCTAssertEqual(generation.testRetainedItems, 0)
        XCTAssertEqual(generation.testRetainedBytes, 0)
    }
}
