import Foundation
import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// No installed extension, entitlements, remote server or real sockets. The
/// production promoted forwarder, writers and session state handler run over
/// held transport callbacks. This tests Rama's lifecycle, not XNU memory safety.
final class ClientAbortLifecycleTests: XCTestCase {
    func testClientAbortWithEveryLateCallbackOrder() throws {
        // All 24 orders, including a stale state callback captured before the
        // connection's handlers were detached. Repeat with successful and failed
        // send completions: cancellation cannot assume either result wins.
        for order in permutations([0, 1, 2, 3]) {
            for sendFails in [false, true] {
                try exercise(order: order, sendFails: sendFails, concurrent: false)
            }
        }
    }

    func testClientAbortWithConcurrentLateCallbacks() throws {
        for iteration in 0..<200 {
            try autoreleasepool {
                try exercise(
                    order: [0, 1, 2, 3], sendFails: iteration % 2 == 0,
                    concurrent: true)
            }
        }
    }

    private func permutations(_ values: [Int]) -> [[Int]] {
        guard !values.isEmpty else { return [[]] }
        return values.flatMap { head in
            permutations(values.filter { $0 != head }).map { [head] + $0 }
        }
    }

    private func exercise(order: [Int], sendFails: Bool, concurrent: Bool) throws {
        var harness: AbortHarness? = AbortHarness()
        weak var session = harness?.session
        weak var forwarder = harness?.forwarder
        try autoreleasepool {
            try run(
                try XCTUnwrap(harness), order: order, sendFails: sendFails, concurrent: concurrent)
        }
        harness = nil
        XCTAssertNil(session, "late callbacks retained the session")
        XCTAssertNil(forwarder, "late callbacks retained the forwarder")
        session = nil
        forwarder = nil
    }

    private func run(_ h: AbortHarness, order: [Int], sendFails: Bool, concurrent: Bool) throws {
        defer { h.cleanup() }
        let label = "order=\(order) sendFails=\(sendFails) concurrent=\(concurrent)"

        try h.wait { h.flow.pendingReadCount == 1 && h.connection.pendingReceiveCount == 1 }
        h.flow.completeReadSynchronously(data: Data(repeating: 0xA5, count: 517), error: nil)
        try h.wait { h.connection.pendingSendCount == 1 && h.flow.pendingReadCount == 1 }
        XCTAssertTrue(
            h.connection.completePendingReceive(
                data: Data(repeating: 0x5A, count: 99), isComplete: false))
        try h.wait {
            h.flow.pendingWriteCompletionCount == 1 && h.connection.pendingReceiveCount == 1
        }

        // This models the client having closed while its response write was
        // outstanding. Do not directly invoke a teardown method to trigger it.
        let staleStateHandler = try XCTUnwrap(h.connection.stateUpdateHandler)
        XCTAssertTrue(h.flow.completeNextWrite())
        try h.wait { h.queue.sync { h.ctx.isDone } }
        h.drain()
        XCTAssertEqual(h.connection.forceCancelCount, 1, label)
        XCTAssertEqual(h.connection.cancelCount, 1, label)
        XCTAssertEqual(h.core.tcpFlowCount, 0, "teardown retained the registry entry")
        XCTAssertNil(h.connection.stateUpdateHandler, label)
        XCTAssertNil(h.connection.viabilityUpdateHandler, label)
        XCTAssertNil(h.queue.sync { h.ctx.connection }, label)
        XCTAssertEqual(h.connection.pendingSendCount, 1, "test must retain a send in flight")
        XCTAssertEqual(h.connection.pendingReceiveCount, 1, "test must retain a receive in flight")
        XCTAssertEqual(h.flow.pendingReadCount, 1, "test must retain a client read in flight")
        let sends = h.connection.sentChunks.count
        let writes = h.flow.writeCount

        // A cancelled mock transition discards pending callbacks. Deliberately
        // retain and deliver them ourselves so the test cannot pass by erasing
        // the very work whose lifetime it is checking.
        let callbacks: [@Sendable () -> Void] = [
            {
                XCTAssertTrue(
                    h.connection.completePendingSend(error: sendFails ? .posix(.ECANCELED) : nil))
            },
            {
                XCTAssertTrue(
                    h.connection.completePendingReceive(
                        data: Data(repeating: 0xCC, count: 24), isComplete: true,
                        error: .posix(.ECONNRESET)))
            },
            { h.flow.completeReadSynchronously(data: Data([0xDD]), error: nil) },
            {
                h.queue.async {
                    staleStateHandler(.failed(.posix(.ECONNRESET)))
                    staleStateHandler(.cancelled)
                }
            },
        ]
        if concurrent {
            DispatchQueue.concurrentPerform(iterations: callbacks.count) { callbacks[$0]() }
        } else {
            for index in order {
                callbacks[index]()
                h.drain()
            }
        }
        h.drain()
        try h.wait { h.budget.snapshot().retainedBytes == 0 }
        XCTAssertEqual(h.budget.snapshot().retainedItems, 0, label)
        XCTAssertEqual(h.flow.closeReadCallCount, 1, label)
        XCTAssertEqual(h.flow.closeWriteCallCount, 1, label)
        XCTAssertEqual(
            (h.flow.lastCloseReadError as NSError?)?.domain, NEAppProxyErrorDomain, label)
        XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, 1, label)
        XCTAssertEqual(h.connection.forceCancelCount, 1, label)
        XCTAssertEqual(h.connection.cancelCount, 1, label)
        XCTAssertEqual(
            h.connection.sentChunks.count, sends, "late callback sent more bytes: \(label)")
        XCTAssertEqual(h.flow.writeCount, writes, "late callback wrote to closed flow: \(label)")
        XCTAssertEqual(h.connection.pendingReceiveCount, 0, label)
        XCTAssertEqual(h.connection.pendingSendCount, 0, label)
        XCTAssertEqual(h.flow.pendingReadCount, 0, label)
        XCTAssertEqual(h.flow.pendingWriteCompletionCount, 0, label)
        XCTAssertEqual(h.client.enqueue(Data([1])), .closed, label)
        XCTAssertEqual(h.egress.enqueue(Data([2])), .closed, label)

    }
}

private final class AbortHarness: @unchecked Sendable {
    let core = TransparentProxyCore()
    let flow = MockTcpFlow()
    let connection = MockNwConnection()
    let budget = WriterMemoryBudget()
    let session: TcpFlowSession<MockTcpFlow>
    let client: TcpClientWritePump
    let egress: NwTcpConnectionWritePump
    let forwarder: TcpDirectForwarder
    var queue: DispatchQueue { session.flowQueue }
    var ctx: TcpFlowContext { session.ctx }

    init() {
        flow.captureWriteCompletions = true
        flow.handler = { _, _ in NSError(domain: NEAppProxyErrorDomain, code: 1) }
        session = TcpFlowSession(
            core: core, flow: flow,
            meta: RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 1, remoteHost: "127.0.0.1", remotePort: 443,
                localHost: nil, localPort: 0, sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil, sourceAppAuditToken: nil, sourceAppPid: 4242),
            egressReportEnabled: { false })
        let ctx = session.ctx
        let ref = ForwarderRef()
        client = TcpClientWritePump(
            flow: flow, queue: session.flowQueue, logger: { _ in },
            onTerminalError: { [weak ctx] in ctx?.applyWriterTerminal($0) },
            onDrained: { ref.value?.onClientPumpDrained() }, writerMemoryBudget: budget)
        egress = NwTcpConnectionWritePump(
            connection: connection, queue: session.flowQueue,
            onDrained: { ref.value?.onEgressPumpDrained() },
            onTerminal: { [weak ctx] in ctx?.applyPromotedEgressWriterTerminal($0) },
            writerMemoryBudget: budget)
        connection.setStateSilently(.ready)
        connection.start(queue: session.flowQueue)
        let session = session
        let core = core
        let flow = flow
        let connection = connection
        let client = client
        let egress = egress
        forwarder = session.flowQueue.sync {
            ctx.connection = connection
            ctx.clientWritePump = client
            ctx.egressWritePump = egress
            ctx.mode = .promoted
            ctx.egressReady = true
            session.egressReady = true
            session.installEgressStateHandler(connection: connection)
            let result = core.makePromotedForwarder(
                ctx: ctx, flow: flow, connection: connection, clientWritePump: client,
                egressWritePump: egress, flowQueue: session.flowQueue)
            ref.value = result
            return result
        }
        core.testInsertTcpContext(ObjectIdentifier(flow), ctx)
        XCTAssertEqual(core.tcpFlowCount, 1)
        client.markOpened()
        forwarder.markClientReadDrained()
        forwarder.markEgressReadDrained()
        forwarder.markRustC2SDone()
        forwarder.markRustS2CDone()
    }

    // Pump callbacks may enqueue further work behind a barrier. Poll explicit
    // milestones with a deadline instead of treating one sync as quiescence.
    func wait(_ condition: () -> Bool) throws {
        let deadline = Date().addingTimeInterval(3)
        while !condition() {
            guard Date() < deadline else {
                XCTFail("client-abort lifecycle milestone timed out")
                throw NSError(domain: "ClientAbortLifecycleTests", code: 1)
            }
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    func drain() { for _ in 0..<8 { queue.sync {} } }

    func cleanup() {
        queue.sync { ctx.applyEngineDetached() }
        while flow.completeNextWrite() {}
        flow.completeReadSynchronously(data: nil, error: nil)
        while connection.completePendingSend(error: .posix(.ECANCELED)) {}
        while connection.completePendingReceive(isComplete: true, error: .posix(.ECANCELED)) {}
        drain()
    }
}
