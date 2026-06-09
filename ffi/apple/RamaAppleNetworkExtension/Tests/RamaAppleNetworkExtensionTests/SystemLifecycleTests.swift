import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for `TransparentProxyCore.handleSystemSleep` /
/// `handleSystemWake`.
///
/// `handleSystemSleep` is a brief pause-and-return hook: it stops
/// telemetry and fires the engine's sleep notification, but it does
/// NOT tear flows down. Flows that don't survive the suspend are
/// reaped post-wake by the per-flow `.failed` path. These tests pin
/// that non-destructive contract.
final class SystemLifecycleTests: XCTestCase {

    // MARK: - core.handleSystemSleep

    /// `handleSystemSleep` leaves every registered flow intact —
    /// no teardown, no connection cancel, registry untouched — and
    /// fires its completion promptly.
    func testHandleSystemSleepLeavesRegisteredTcpFlowsIntact() {
        let core = TransparentProxyCore()
        var teardowns: [TcpFlowTeardown] = []
        var flows: [MockTcpFlow] = []
        var conns: [MockNwConnection] = []
        // Build a few mock contexts and shove them straight into
        // the registry. Engine-less; we're only testing that sleep
        // does not disturb them.
        for _ in 0..<5 {
            let f = MockTcpFlow()
            let c = MockNwConnection()
            let ctx = TcpFlowContext()
            ctx.connection = c
            let td = TcpFlowTeardown(
                ctx: ctx, core: core, flow: f, flowId: ObjectIdentifier(f))
            ctx.teardown = td
            // Use the registry directly — registerTcpFlow needs a
            // RamaTcpSessionHandle which we can't construct here.
            core.testInsertTcpContext(ObjectIdentifier(f), ctx)
            flows.append(f)
            conns.append(c)
            teardowns.append(td)
        }
        XCTAssertEqual(core.tcpFlowCount, 5)

        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        // Nothing was torn down: the flows survive the suspend and
        // are reaped (if needed) only by the post-wake path.
        XCTAssertEqual(core.tcpFlowCount, 5, "sleep must not drop flows")
        for (i, td) in teardowns.enumerated() {
            XCTAssertFalse(td.isDone, "teardown[\(i)] must not fire on sleep")
            XCTAssertEqual(conns[i].cancelCount, 0)
            XCTAssertEqual(flows[i].closeReadCallCount, 0)
        }
    }

    /// `handleSystemSleep` with NO registered flows fires its
    /// completion immediately and is a no-op otherwise.
    func testHandleSystemSleepOnEmptyRegistryFiresCompletion() {
        let core = TransparentProxyCore()
        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)
    }

    /// `handleSystemWake` is a no-op when no engine attached;
    /// must not crash.
    func testHandleSystemWakeWithoutEngineIsHarmless() {
        let core = TransparentProxyCore()
        core.handleSystemWake()
    }

    // MARK: - core post-wake dead-path reset (checkWakeDeadPath)

    /// Build a registered, established (`egressReady`) TCP flow whose
    /// egress connection reports `pathStatus`, and return the pieces a
    /// test needs to assert on. Engine-less: inserted straight into the
    /// registry like the sleep tests above.
    private func makeEstablishedFlow(
        on core: TransparentProxyCore,
        pathStatus: NWPath.Status?,
        flowQueue: DispatchQueue? = nil
    ) -> (flow: MockTcpFlow, conn: MockNwConnection, ctx: TcpFlowContext, teardown: TcpFlowTeardown)
    {
        let f = MockTcpFlow()
        let c = MockNwConnection()
        c.setCurrentPathStatus(pathStatus)
        let ctx = TcpFlowContext()
        ctx.connection = c
        ctx.egressReady = true
        ctx.flowQueue = flowQueue
        let td = TcpFlowTeardown(
            ctx: ctx, core: core, flow: f, flowId: ObjectIdentifier(f))
        ctx.teardown = td
        core.testInsertTcpContext(ObjectIdentifier(f), ctx)
        return (f, c, ctx, td)
    }

    /// An established flow whose egress path is no longer `.satisfied`
    /// after the wake settle is force-reset: teardown fires, the egress
    /// connection is cancelled, and the registry entry is dropped — the
    /// silent-`.ready`-over-dead-path wedge the 60s watchdog used to be
    /// the only backstop for.
    func testWakeDeadPathResetsEstablishedFlowOnUnsatisfiedPath() {
        let core = TransparentProxyCore()
        let f = makeEstablishedFlow(on: core, pathStatus: .unsatisfied)
        XCTAssertEqual(core.tcpFlowCount, 1)

        core.testCheckWakeDeadPath(f.ctx)

        XCTAssertTrue(f.teardown.isDone, "dead-path established flow must be torn down")
        XCTAssertEqual(f.conn.cancelCount, 1, "egress connection cancelled")
        XCTAssertEqual(core.tcpFlowCount, 0, "registry entry removed")
    }

    /// An established flow whose path survived the sleep (`.satisfied`,
    /// e.g. a no-op Power-Nap wake) is left untouched — no teardown, no
    /// cancel, registry intact.
    func testWakeDeadPathKeepsEstablishedFlowOnSatisfiedPath() {
        let core = TransparentProxyCore()
        let f = makeEstablishedFlow(on: core, pathStatus: .satisfied)

        core.testCheckWakeDeadPath(f.ctx)

        XCTAssertFalse(f.teardown.isDone, "healthy flow must survive the wake re-check")
        XCTAssertEqual(f.conn.cancelCount, 0)
        XCTAssertEqual(core.tcpFlowCount, 1)
    }

    /// The re-check only judges established flows. A still-connecting
    /// (`!egressReady`) flow is handled by the `applySystemWake` branch,
    /// not this one, so `checkWakeDeadPath` no-ops on it even with a dead
    /// path — guarding against a double-teardown if the two ever overlap.
    func testWakeDeadPathIgnoresPreReadyFlow() {
        let core = TransparentProxyCore()
        let f = makeEstablishedFlow(on: core, pathStatus: .unsatisfied)
        f.ctx.egressReady = false

        core.testCheckWakeDeadPath(f.ctx)

        XCTAssertFalse(f.teardown.isDone)
        XCTAssertEqual(core.tcpFlowCount, 1)
    }

    /// End-to-end through `handleSystemWake`: with a short settle override
    /// and a real `flowQueue`, a dead-path established flow is reset by the
    /// scheduled re-check (not just the directly-invoked hook).
    func testHandleSystemWakeSchedulesDeadPathResetViaTimer() {
        let core = TransparentProxyCore()
        let prevDelay = defaultPostWakePathRecheckMs
        defaultPostWakePathRecheckMs = 10
        defer { defaultPostWakePathRecheckMs = prevDelay }

        let queue = DispatchQueue(label: "rama.test.flow.wake")
        let f = makeEstablishedFlow(on: core, pathStatus: .unsatisfied, flowQueue: queue)

        core.handleSystemWake()

        // The re-check is scheduled on `queue` at +10ms; a barrier at
        // +200ms on the same serial queue runs strictly after it.
        let exp = expectation(description: "post-wake re-check fired")
        queue.asyncAfter(deadline: .now() + .milliseconds(200)) { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        XCTAssertTrue(f.teardown.isDone, "scheduled re-check must reset the dead-path flow")
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    /// Same end-to-end path, healthy connection: a `.satisfied` flow with
    /// a real `flowQueue` survives the scheduled re-check.
    func testHandleSystemWakeKeepsHealthyFlowViaTimer() {
        let core = TransparentProxyCore()
        let prevDelay = defaultPostWakePathRecheckMs
        defaultPostWakePathRecheckMs = 10
        defer { defaultPostWakePathRecheckMs = prevDelay }

        let queue = DispatchQueue(label: "rama.test.flow.wake.ok")
        let f = makeEstablishedFlow(on: core, pathStatus: .satisfied, flowQueue: queue)

        core.handleSystemWake()

        let exp = expectation(description: "post-wake re-check fired")
        queue.asyncAfter(deadline: .now() + .milliseconds(200)) { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        XCTAssertFalse(f.teardown.isDone, "healthy flow must survive the scheduled re-check")
        XCTAssertEqual(core.tcpFlowCount, 1)
    }
}
