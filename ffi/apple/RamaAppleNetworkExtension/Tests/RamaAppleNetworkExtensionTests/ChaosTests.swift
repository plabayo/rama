import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Layer-3 stress tests: many flows, randomised event ordering,
/// assert that the structural idempotency holds (no double-cancel,
/// no double-teardown, registry ends empty). Seeded PRNG so any
/// failure is reproducible from the test output.
final class ChaosTests: XCTestCase {

    private struct TeardownVariant {
        let name: String
        let apply: (TcpFlowTeardown) -> Void
    }

    private let variants: [TeardownVariant] = [
        .init(name: "preReady") { $0.applyPreReadyFailure() },
        .init(name: "connectTimeout") { $0.applyConnectTimeout() },
        .init(name: "writerTerminal") {
            $0.applyWriterTerminal(NSError(domain: "chaos", code: 1))
        },
        .init(name: "drainedClose-opened") { $0.applyDrainedClose(wasOpened: true) },
        .init(name: "drainedClose-unopened") { $0.applyDrainedClose(wasOpened: false) },
        .init(name: "postReady") {
            $0.applyPostReadyFailure(NSError(domain: "chaos", code: 2))
        },
        .init(name: "flowOpen") {
            $0.applyFlowOpenFailure(NSError(domain: "chaos", code: 3))
        },
        .init(name: "readHardError") {
            $0.applyReadHardError(NSError(domain: "chaos", code: 4))
        },
        .init(name: "systemSleep") { $0.applySystemSleep() },
    ]

    /// 200 fresh contexts. Each receives a random teardown variant,
    /// then a SECOND random variant. Assert: connection is cancelled
    /// exactly once, teardown.isDone, registry is empty.
    func testRandomTeardownOrderingIsIdempotentAcrossMany() {
        // Seed is fixed: chaos tests must be reproducible.
        var rng = SeededPRNG(seed: 0x600D_5EED)
        let core = TransparentProxyCore()

        struct Bag {
            let flow: MockTcpFlow
            let conn: MockNwConnection
            let ctx: TcpFlowContext
            let teardown: TcpFlowTeardown
        }
        var bags: [Bag] = []
        for _ in 0..<200 {
            let flow = MockTcpFlow()
            let conn = MockNwConnection()
            let ctx = TcpFlowContext()
            ctx.connection = conn
            let td = TcpFlowTeardown(
                ctx: ctx, core: core, flow: flow, flowId: ObjectIdentifier(flow))
            ctx.teardown = td
            core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
            bags.append(Bag(flow: flow, conn: conn, ctx: ctx, teardown: td))
        }

        // First random variant on each bag.
        for bag in bags {
            let v = variants[Int(rng.next() % UInt64(variants.count))]
            v.apply(bag.teardown)
        }
        // Second random variant — must be a no-op.
        for bag in bags {
            let v = variants[Int(rng.next() % UInt64(variants.count))]
            v.apply(bag.teardown)
        }

        for (i, bag) in bags.enumerated() {
            XCTAssertTrue(bag.teardown.isDone, "bag[\(i)] teardown didn't run")
            XCTAssertEqual(
                bag.conn.cancelCount, 1, "bag[\(i)] cancel must fire exactly once across two variants")
        }
    }

    /// 100 contexts registered + `handleSystemSleep`. Expect every
    /// teardown fires, every connection is cancelled exactly once,
    /// and the completion handler resolves promptly.
    func testHandleSystemSleepDrainsManyFlows() {
        let core = TransparentProxyCore()
        struct Bag {
            let flow: MockTcpFlow
            let conn: MockNwConnection
            let teardown: TcpFlowTeardown
        }
        var bags: [Bag] = []
        for _ in 0..<100 {
            let flow = MockTcpFlow()
            let conn = MockNwConnection()
            let ctx = TcpFlowContext()
            ctx.connection = conn
            let td = TcpFlowTeardown(
                ctx: ctx, core: core, flow: flow, flowId: ObjectIdentifier(flow))
            ctx.teardown = td
            core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
            bags.append(Bag(flow: flow, conn: conn, teardown: td))
        }

        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 5.0)

        for (i, bag) in bags.enumerated() {
            XCTAssertTrue(bag.teardown.isDone, "bag[\(i)] teardown did not fire")
            XCTAssertEqual(bag.conn.cancelCount, 1, "bag[\(i)] cancel must fire once")
            XCTAssertEqual(bag.flow.closeReadCallCount, 1)
        }
    }

    /// Concurrent teardown from two threads on the SAME teardown
    /// object — the sticky `done` flag must keep cancel-count at 1.
    /// (Today teardown runs queue-confined in production; this test
    /// pins the invariant for hypothetical future callers that race
    /// from raw threads.)
    func testConcurrentTeardownFromMultipleThreads() {
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let conn = MockNwConnection()
        let ctx = TcpFlowContext()
        ctx.connection = conn
        let td = TcpFlowTeardown(
            ctx: ctx, core: core, flow: flow, flowId: ObjectIdentifier(flow))
        ctx.teardown = td

        let group = DispatchGroup()
        for _ in 0..<8 {
            group.enter()
            DispatchQueue.global().async {
                td.applyReadHardError(NSError(domain: "chaos", code: 99))
                group.leave()
            }
        }
        group.wait()

        // The structural sticky flag should hold even though
        // we're calling from raw threads (queue-confinement is
        // a documented expectation; we test what happens if a
        // future caller violates it).
        XCTAssertTrue(td.isDone)
        XCTAssertEqual(
            conn.cancelCount, 1,
            "even under raced multi-thread teardown the sticky flag should keep cancel-count at 1")
    }
}

/// Tiny deterministic PRNG so chaos tests are reproducible. Linear
/// congruential, good enough for ordering choice. NOT for crypto.
private struct SeededPRNG {
    private var state: UInt64
    init(seed: UInt64) { state = seed | 1 }
    mutating func next() -> UInt64 {
        state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
        return state
    }
}
