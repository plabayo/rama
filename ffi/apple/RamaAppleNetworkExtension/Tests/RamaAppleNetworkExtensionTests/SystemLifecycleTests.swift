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
}
