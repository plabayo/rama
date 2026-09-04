import Foundation
import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Edge-case tests that exercise specific code paths the main
/// lifecycle suite doesn't cover by accident. Every test here is
/// motivated by an actual bug shape that *could* exist if a future
/// edit got the path wrong; none of them are "test coverage for
/// coverage's sake."
final class CoreEdgeCaseTests: XCTestCase {
    func testFlowIdleAgeSaturatesWhenActivityIsNewerThanClock() {
        let ctx = TcpFlowContext()
        let nowNs = DispatchTime.now().uptimeNanoseconds
        ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: nowNs + 1)

        XCTAssertEqual(ctx.idleMs(nowNs: nowNs), 0)
    }


    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        return engine
    }

    private func makeMeta(
        protocolRaw: UInt32 = 1,
        port: UInt16 = 443
    ) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: protocolRaw,
            remoteHost: "example.com",
            remotePort: port,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 5.0,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    /// Promote-aware clean teardown — mirrors
    /// `CoreTcpLifecycleTests.drainAndAwaitRemoval`. See that
    /// docstring for the rationale (cutover wait + both EOFs +
    /// send-completer for the FIN drain).
    private func drainAndAwaitRemoval(
        _ core: TransparentProxyCore,
        flow: MockTcpFlow,
        conn: MockNwConnection,
        description: String = "flow removed",
        timeout: TimeInterval = 5.0
    ) {
        guard let ctx = core.testInspectTcpContext(for: flow) else {
            XCTFail("no ctx for flow — cutover wait impossible"); return
        }
        waitFor("cutover flips ctx.mode away from .viaRust", timeout: 3.0) {
            ctx.mode != .viaRust
        }

        // Re-fire EOFs each tick (not once): post-cutover the forwarder
        // re-issues its own flow.readData / connection.receive, and a
        // single EOF fired during the gap before that read is issued is
        // lost (the mocks no-op when nothing is pending), stalling
        // teardown. See `CoreTcpLifecycleTests.drainAndAwaitRemoval`.
        let completer = AtomicFlag()
        DispatchQueue.global().async {
            while !completer.load() {
                _ = conn.completePendingSend(error: nil)
                flow.completeRead(data: nil, error: nil)
                _ = conn.completePendingReceive(isComplete: true)
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        defer { completer.store(true) }

        waitFor(description, timeout: timeout) { core.tcpFlowCount == 0 }
    }

    // MARK: - handleAppMessage in various engine states

    func testHandleAppMessageBeforeEngineAttached() {
        let core = TransparentProxyCore()
        // No `attachEngine` call — engine is nil.
        let reply = core.handleAppMessage(Data("ping".utf8))
        XCTAssertNil(reply, "handleAppMessage with no engine must short-circuit to nil")
    }

    func testHandleAppMessageAfterEngineDetached() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        core.detachEngine(reason: 0)
        let reply = core.handleAppMessage(Data("ping".utf8))
        XCTAssertNil(
            reply, "handleAppMessage after detachEngine must short-circuit to nil"
        )
    }

    func testHandleAppMessageWithEngineAttached() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        // The test engine's demo handler treats unparseable JSON as a
        // no-reply scenario, so the request → empty reply path is
        // exercised end-to-end. The point isn't the reply content
        // (the demo's policy) but that the route doesn't crash and
        // returns a `Data` shape consistent with `nil = no reply`.
        let reply = core.handleAppMessage(Data("ping".utf8))
        // Either nil or non-nil is acceptable — we're testing the
        // routing, not the demo handler's choice. What we check is
        // that no exception was raised.
        _ = reply
    }

    // MARK: - applyMetadata path

    func testApplyMetadataInvokedWhenPreserveOriginalIsDefault() {
        // The Swift core consults `egressOpts.parameters.preserve_original_meta_data`
        // and only calls `flow.applyMetadata(to:)` when it's true. The
        // engine's demo handler doesn't override the egress options
        // (so `egressOpts == nil`), and the core's default for that
        // case is `?? true`. Mock flow asserts the call happened.
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let flow = MockTcpFlow()
        XCTAssertTrue(core.handleTcpFlow(flow, meta: makeMeta()))
        waitFor("post-registration startup applies metadata") {
            flow.applyMetadataCallCount == 1
        }
        XCTAssertEqual(
            flow.applyMetadataCallCount, 1,
            "applyMetadata must run by default (preserve_original_meta_data ?? true)"
        )

        let conn = capture.waitForLastConnection()
        conn.transition(to: .failed(.posix(.ECONNREFUSED)))
        waitFor("flow cleaned up") { core.tcpFlowCount == 0 }
        conn.simulateCancelled()
        capture.releaseAll()
    }

    // MARK: - Engine attached twice without detach

    func testEngineAttachReplacesPreviousEngine() {
        // Defensive — `attachEngine` is documented as a single-shot
        // operation from `startProxy`, but a future code path that
        // calls it twice without detaching shouldn't leak the first
        // engine via the core's `engine` storage. This pins that
        // semantic.
        let core = TransparentProxyCore()
        weak var weakE1: RamaTransparentProxyEngineHandle?
        autoreleasepool {
            let e1 = makeEngine()
            weakE1 = e1
            core.attachEngine(e1)
        }
        // Replace via second attach — first must release.
        core.attachEngine(makeEngine())
        // Engine handle deinit fires asynchronously after the Rust
        // runtime drains; allow a brief window before asserting.
        let deadline = Date().addingTimeInterval(2.0)
        while weakE1 != nil && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertNil(
            weakE1,
            "second attachEngine must release the first engine handle"
        )
        core.detachEngine(reason: 0)
    }

    func testStaleEngineGenerationCannotAdmitOrRegisterAfterRestart() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let staleGeneration = core.testEngineGeneration
        core.detachEngine(reason: 0)
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }

        let flow = MockTcpFlow()
        let ctx = TcpFlowContext()
        let anchor = _TestTcpFlowSessionAnchor(ctx: ctx)
        XCTAssertNil(
            core.registerTcpFlow(
                ObjectIdentifier(flow),
                anchor: anchor,
                engineGeneration: staleGeneration))
        XCTAssertNil(
            core.admitTcpStart(
                flowId: ObjectIdentifier(flow),
                meta: makeMeta(),
                engineGeneration: staleGeneration))
        XCTAssertEqual(core.tcpFlowCount, 0)
        XCTAssertEqual(core.testTcpStartsInFlight, 0)
    }

    func testDetachRejectsStaleRegistrationAndStartup() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let generation = core.testEngineGeneration
        core.detachEngine(reason: 0)
        let flow = MockTcpFlow()
        let ctx = TcpFlowContext()
        let queue = DispatchQueue(label: "rama.test.stale-start")
        ctx.flowQueue = queue
        ctx.core = core
        ctx.flow = flow
        ctx.flowId = ObjectIdentifier(flow)
        let anchor = _TestTcpFlowSessionAnchor(ctx: ctx)
        let started = AtomicFlag()
        XCTAssertFalse(
            core.registerTcpFlowAndScheduleStartup(
                ObjectIdentifier(flow),
                anchor: anchor,
                appId: nil,
                engineGeneration: generation,
                on: queue
            ) {
                started.store(true)
            })
        let drained = expectation(description: "stale flow queue drained")
        queue.async { drained.fulfill() }
        wait(for: [drained], timeout: 1.0)
        XCTAssertFalse(started.load())
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    func testTcpRegistrationWaitsForFlowQueueStartup() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let generation = core.testEngineGeneration
        let flow = MockTcpFlow()
        let ctx = TcpFlowContext()
        let queue = DispatchQueue(label: "rama.test.ordered-start")
        ctx.flowQueue = queue
        ctx.core = core
        ctx.flow = flow
        ctx.flowId = ObjectIdentifier(flow)
        let started = AtomicFlag()
        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)

        let result = TestValue<Bool?>(nil)
        let registrationReturned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let registered = core.registerTcpFlowAndScheduleStartup(
                ObjectIdentifier(flow),
                anchor: _TestTcpFlowSessionAnchor(ctx: ctx),
                appId: nil,
                engineGeneration: generation,
                on: queue
            ) {
                started.store(true)
            }
            result.set(registered)
            registrationReturned.signal()
        }

        waitFor("TCP flow is registered before its startup submission") {
            core.tcpFlowCount == 1
        }
        XCTAssertEqual(registrationReturned.wait(timeout: .now()), .timedOut)
        XCTAssertFalse(started.load())
        releaseBlocker.signal()
        XCTAssertEqual(registrationReturned.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(result.get(), true)
        XCTAssertTrue(started.load(), "registration cannot return before startup runs")

        core.detachEngine(reason: 0)
        queue.sync { XCTAssertTrue(ctx.isDone) }
    }

    func testUdpRegistrationWaitsForFlowQueueStartup() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let generation = core.testEngineGeneration
        let flow = MockUdpFlow()
        let ctx = UdpFlowContext()
        let queue = DispatchQueue(label: "rama.test.ordered-udp-start")
        ctx.flowQueue = queue
        let started = AtomicFlag()
        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)

        let result = TestValue<Bool?>(nil)
        let registrationReturned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let registered = core.registerUdpFlowAndScheduleStartup(
                ObjectIdentifier(flow),
                anchor: _TestUdpFlowSessionAnchor(ctx: ctx),
                engineGeneration: generation,
                on: queue
            ) {
                started.store(true)
            }
            result.set(registered)
            registrationReturned.signal()
        }

        waitFor("UDP flow is registered before its startup submission") {
            core.udpFlowCount == 1
        }
        XCTAssertEqual(registrationReturned.wait(timeout: .now()), .timedOut)
        XCTAssertFalse(started.load())
        releaseBlocker.signal()
        XCTAssertEqual(registrationReturned.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(result.get(), true)
        XCTAssertTrue(started.load(), "registration cannot return before startup runs")

        core.detachEngine(reason: 0)
        queue.sync {}
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    func testUdpRegistrationReconcilesCloseThatPrecededInsertion() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        let generation = core.testEngineGeneration
        let flow = MockUdpFlow()
        let ctx = UdpFlowContext()
        let queue = DispatchQueue(label: "rama.test.preclosed-udp-start")
        ctx.flowQueue = queue
        ctx.readState = .closed

        // Model the pre-activation max-lifetime callback: its first removal
        // ran before registration and therefore had no entry to remove.
        core.removeUdpFlow(ObjectIdentifier(flow), engineGeneration: generation)
        XCTAssertEqual(core.udpFlowCount, 0)

        XCTAssertTrue(
            core.registerUdpFlowAndScheduleStartup(
                ObjectIdentifier(flow),
                anchor: _TestUdpFlowSessionAnchor(ctx: ctx),
                engineGeneration: generation,
                on: queue,
                body: {}))
        waitFor("post-insertion reconciliation removes already-closed UDP session") {
            core.udpFlowCount == 0
        }
    }

    func testPendingUdpCloseIsAbandonedWhenDetachRejectsRegistration() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let staleGeneration = core.testEngineGeneration
        core.detachEngine(reason: 0)

        let flow = MockUdpFlow()
        let ctx = UdpFlowContext()
        let queue = DispatchQueue(label: "rama.test.udp.pending-close.detach-reject")
        ctx.flowQueue = queue
        XCTAssertFalse(
            ctx.registrationGate.recordServerClose(),
            "pre-claim close must only be recorded")

        let replayCount = TestValue(0)
        let decision = core.registerUdpFlowAndScheduleStartupDecision(
            ObjectIdentifier(flow),
            anchor: _TestUdpFlowSessionAnchor(ctx: ctx),
            appId: "com.example.pending-close",
            engineGeneration: staleGeneration,
            on: queue,
            body: { XCTFail("detached registration must not start") },
            pendingServerClose: { replayCount.set(replayCount.get() + 1) })

        guard case .unavailable = decision else {
            return XCTFail("stale generation must be unavailable")
        }
        XCTAssertFalse(ctx.registrationGate.recordServerClose())
        queue.sync {}
        XCTAssertEqual(replayCount.get(), 0)
        XCTAssertFalse(flow.openWasInvoked)
        XCTAssertEqual(flow.closeReadCallCount, 0)
        XCTAssertEqual(flow.closeWriteCallCount, 0)
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    func testPendingUdpClosePublishesLeavingAnchorAndReplaysExactlyOnce() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }
        let generation = core.testEngineGeneration
        let flow = MockUdpFlow()
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "53")
        weak var retainedSession: UdpFlowSession<MockUdpFlow>?
        var flowQueue: DispatchQueue?

        autoreleasepool {
            var session: UdpFlowSession<MockUdpFlow>? = UdpFlowSession(
                core: core, flow: flow, meta: makeMeta(protocolRaw: 2, port: 5000))
            guard let liveSession = session else { return XCTFail("session") }
            retainedSession = liveSession
            flowQueue = liveSession.flowQueue
            liveSession.ctx.engineGeneration = generation
            liveSession.installTerminate()
            liveSession.buildClientWritePump()
            liveSession.ctx.writer?.markOpened()
            liveSession.ctx.writer?.enqueue(Data("retained".utf8), sentBy: endpoint)
            liveSession.flowQueue.sync {}

            XCTAssertFalse(liveSession.ctx.registrationGate.recordServerClose())
            XCTAssertFalse(liveSession.ctx.registrationGate.recordServerClose())
            let replayCount = TestValue(0)
            let decision = core.registerUdpFlowAndScheduleStartupDecision(
                liveSession.flowId,
                anchor: liveSession,
                appId: "com.example.pending-close",
                engineGeneration: generation,
                on: liveSession.flowQueue,
                body: { XCTFail("a recorded close must suppress open") },
                pendingServerClose: {
                    replayCount.set(replayCount.get() + 1)
                    liveSession.replayPendingServerCloseBeforeStartup()
                })
            guard case .started = decision else {
                return XCTFail("current generation should claim the flow")
            }

            XCTAssertEqual(replayCount.get(), 1)
            XCTAssertFalse(liveSession.ctx.registrationGate.recordServerClose())
            XCTAssertFalse(flow.openWasInvoked)
            XCTAssertEqual(flow.closeReadCallCount, 1)
            XCTAssertEqual(flow.closeWriteCallCount, 0)
            XCTAssertEqual(core.udpFlowCount, 1, "registry retains the draining owner")
            XCTAssertEqual(
                core.testPressurePendingRemovalCount, 1,
                "the retained closing entry must already count as pressure relief")
            session = nil
        }

        XCTAssertNotNil(retainedSession, "registry must retain the drain owner")
        XCTAssertTrue(flow.completePendingWrite(error: nil))
        flowQueue?.sync {}
        waitFor("pending-close drain removes retained session") {
            core.udpFlowCount == 0 && retainedSession == nil
        }
        XCTAssertEqual(flow.closeWriteCallCount, 1)
        XCTAssertEqual(core.testPressurePendingRemovalCount, 0)
    }

    func testUdpRegistrationGatePublishesGenerationBeforeClaimedCallback() {
        let ctx = UdpFlowContext()
        let generation: UInt64 = 0xA11C_E55
        let publishing = DispatchSemaphore(value: 0)
        let callbackAttempting = DispatchSemaphore(value: 0)
        let done = DispatchGroup()
        let observed = TestValue<UInt64?>(nil)

        done.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            // Intentionally non-atomic: the gate unlock/acquire is the
            // production happens-before edge exercised under TSan.
            ctx.engineGeneration = generation
            _ = ctx.registrationGate.claim { _ in
                publishing.signal()
                callbackAttempting.wait()
            }
            done.leave()
        }
        done.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            publishing.wait()
            callbackAttempting.signal()
            if ctx.registrationGate.recordServerClose() {
                observed.set(ctx.engineGeneration)
            }
            done.leave()
        }

        XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(observed.get(), generation)
    }

    func testValidStartupsStayConcurrentAndDetachWaitsForThem() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let generation = core.testEngineGeneration
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let queues = (0..<2).map {
            DispatchQueue(label: "rama.test.concurrent-start.\($0)")
        }
        let contexts = (0..<2).map { _ in TcpFlowContext() }
        let flows = (0..<2).map { _ in MockTcpFlow() }
        let registrationReturned = DispatchSemaphore(value: 0)
        let results = TestValue([Bool]())

        for index in 0..<2 {
            let ctx = contexts[index]
            let flow = flows[index]
            ctx.flowQueue = queues[index]
            ctx.core = core
            ctx.flow = flow
            ctx.flowId = ObjectIdentifier(flow)
            DispatchQueue.global().async {
                let registered = core.registerTcpFlowAndScheduleStartup(
                    ObjectIdentifier(flow),
                    anchor: _TestTcpFlowSessionAnchor(ctx: ctx),
                    appId: nil,
                    engineGeneration: generation,
                    on: queues[index]
                ) {
                    entered.signal()
                    release.wait()
                }
                results.update { $0.append(registered) }
                registrationReturned.signal()
            }
        }

        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(
            entered.wait(timeout: .now() + 1),
            .success,
            "the lifecycle gate must not serialize independent starts")

        let detachReturned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            core.detachEngine(reason: 0)
            detachReturned.signal()
        }
        waitFor("detach closes admission") { core.engine == nil }
        XCTAssertEqual(
            detachReturned.wait(timeout: .now()),
            .timedOut,
            "detach must wait for starts that already passed the gate")

        release.signal()
        release.signal()
        XCTAssertEqual(registrationReturned.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(registrationReturned.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(detachReturned.wait(timeout: .now() + 1), .success)
        for queue in queues { queue.sync {} }
        XCTAssertEqual(results.get(), [true, true])
        XCTAssertTrue(contexts.allSatisfy(\.isDone))
    }

    func testDetachWaitsForCallbackAlreadyInsideLifecycleGate() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let generation = core.testEngineGeneration
        let callbackEntered = DispatchSemaphore(value: 0)
        let releaseCallback = DispatchSemaphore(value: 0)
        let callbackReturned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            XCTAssertTrue(core.withActiveEngineGeneration(generation) {
                callbackEntered.signal()
                releaseCallback.wait()
            })
            callbackReturned.signal()
        }
        XCTAssertEqual(callbackEntered.wait(timeout: .now() + 1), .success)

        let detachReturned = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            core.detachEngine(reason: 0)
            detachReturned.signal()
        }
        waitFor("detach closes callback admission") { core.engine == nil }
        XCTAssertEqual(
            detachReturned.wait(timeout: .now()),
            .timedOut,
            "detach must wait for a callback already inside the gate")

        releaseCallback.signal()
        XCTAssertEqual(callbackReturned.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(detachReturned.wait(timeout: .now() + 1), .success)
    }

    func testProviderStartCompletionMaySynchronouslyDetachEngine() {
        let core = TransparentProxyCore()
        let generation = core.attachEngine(makeEngine())
        let completionCalled = DispatchSemaphore(value: 0)
        let helperReturned = DispatchSemaphore(value: 0)
        let completionReceivedSuccess = TestValue(false)

        DispatchQueue.global().async {
            RamaTransparentProxyProvider.completeStartAfterSettingsSuccess(
                core: core,
                engineGeneration: generation
            ) { error in
                completionReceivedSuccess.set(error == nil)
                completionCalled.signal()
                // Re-enter teardown synchronously, exactly as an external
                // provider callback is permitted to do.
                core.detachEngine(reason: 0)
            }
            helperReturned.signal()
        }

        XCTAssertEqual(completionCalled.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(
            helperReturned.wait(timeout: .now() + 1),
            .success,
            "provider completion must run after the lifecycle lease is released"
        )
        XCTAssertTrue(completionReceivedSuccess.get())
        XCTAssertNil(core.engine)
    }

    func testQueuedTcpReadyCannotActivateDetachedGeneration() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        let flow = MockTcpFlow()
        XCTAssertTrue(core.handleTcpFlow(flow, meta: makeMeta()))
        guard let queue = core.testInspectTcpContext(for: flow)?.flowQueue else {
            return XCTFail("registered TCP flow queue")
        }
        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)

        let connection = capture.waitForLastConnection()
        connection.transition(to: .ready)
        core.detachEngine(reason: 0)
        XCTAssertFalse(flow.openWasInvoked)

        releaseBlocker.signal()
        queue.sync {}
        XCTAssertFalse(
            flow.openWasInvoked,
            "old-generation ready callback must not open after detach")
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    func testQueuedUdpOpenCannotActivateDetachedGeneration() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let flow = MockUdpFlow()
        XCTAssertTrue(core.handleUdpFlow(flow, meta: makeMeta(protocolRaw: 2)))
        waitFor("UDP open submitted synchronously") { flow.openWasInvoked }
        guard let queue = core.testInspectUdpFlowQueue(for: flow) else {
            return XCTFail("registered UDP flow queue")
        }
        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)

        XCTAssertTrue(flow.completeOpen(error: nil))
        core.detachEngine(reason: 0)
        XCTAssertEqual(flow.pendingReadCount, 0)

        releaseBlocker.signal()
        queue.sync {}
        XCTAssertEqual(
            flow.pendingReadCount, 0,
            "old-generation open completion must not start reads after detach")
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    func testDetachRejectsStaleUdpRegistrationAndStartup() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let generation = core.testEngineGeneration
        core.detachEngine(reason: 0)
        let flow = MockUdpFlow()
        let ctx = UdpFlowContext()
        let queue = DispatchQueue(label: "rama.test.stale-udp-start")
        ctx.flowQueue = queue
        let started = AtomicFlag()

        XCTAssertFalse(
            core.registerUdpFlowAndScheduleStartup(
                ObjectIdentifier(flow),
                anchor: _TestUdpFlowSessionAnchor(ctx: ctx),
                engineGeneration: generation,
                on: queue
            ) {
                started.store(true)
            })
        queue.sync {}
        XCTAssertFalse(started.load())
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    func testStaleRemovalsCannotTouchReattachedRegistries() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let staleGeneration = core.testEngineGeneration
        core.detachEngine(reason: 0)
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        let currentGeneration = core.testEngineGeneration

        let tcpFlow = MockTcpFlow()
        let tcpId = ObjectIdentifier(tcpFlow)
        let tcpCtx = TcpFlowContext()
        XCTAssertNotNil(
            core.registerTcpFlow(
                tcpId,
                anchor: _TestTcpFlowSessionAnchor(ctx: tcpCtx),
                engineGeneration: currentGeneration))
        let udpFlow = MockUdpFlow()
        let udpId = ObjectIdentifier(udpFlow)
        XCTAssertNotNil(
            core.registerUdpFlow(
                udpId,
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: currentGeneration))

        core.removeTcpFlow(
            tcpId,
            context: TcpFlowContext(),
            engineGeneration: staleGeneration)
        core.removeUdpFlow(udpId, engineGeneration: staleGeneration)

        XCTAssertEqual(core.tcpFlowCount, 1)
        XCTAssertEqual(core.udpFlowCount, 1)
    }

    // MARK: - registerTcpFlow / removeTcpFlow idempotence

    func testRemoveTcpFlowIsIdempotent() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }

        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        let flow = MockTcpFlow()
        _ = core.handleTcpFlow(flow, meta: makeMeta())
        let conn = capture.waitForLastConnection()
        conn.transition(to: .failed(.posix(.ECONNREFUSED)))
        waitFor("flow removed") { core.tcpFlowCount == 0 }
        conn.simulateCancelled()

        // Double-remove via the public API surface — should not
        // crash or assert.
        core.removeTcpFlow(ObjectIdentifier(flow))
        core.removeTcpFlow(ObjectIdentifier(flow))
        XCTAssertEqual(core.tcpFlowCount, 0)
    }

    // MARK: - handleNewFlow rejects non-TCP / non-UDP

    func testHandleAppMessageEmptyData() {
        // Edge case: empty payload. Should not crash; semantic is
        // up to the engine's handler. We test that the route
        // doesn't blow up on a zero-length input.
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        _ = core.handleAppMessage(Data())
    }

    // MARK: - State transition after detachEngine

    /// Apple delivers `stateUpdateHandler` state changes asynchronously
    /// on the connection's queue. A state can in principle arrive
    /// after the flow has already been torn down via `detachEngine`.
    /// Because every `[weak self, weak ctx]` capture in the handler
    /// observes both as nil, the late state must be a no-op rather
    /// than crash or invoke any cleanup path.
    func testStateUpdateAfterDetachIsNoOp() {
        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let flow = MockTcpFlow()
        _ = core.handleTcpFlow(flow, meta: makeMeta())
        let conn = capture.waitForLastConnection()
        conn.transition(to: .ready)
        waitFor("flow.open invoked") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("egress receive in flight") { conn.pendingReceiveCount > 0 }

        // The egress connection was started on the per-flow queue, so
        // every teardown and state-handler hop runs there. A `sync`
        // barrier on that serial queue flushes all pending async work
        // deterministically — no sleeps, no races.
        guard let flowQueue = conn.startInvocations.first else {
            return XCTFail("egress connection must have been started on a queue")
        }

        // Tear everything down — the engine is gone, ctx is gone,
        // session is gone. `detachEngine` cancels the egress
        // connection ASYNC on the flow queue; flush so that cancel has
        // landed before we sample the count (else we'd race detach's
        // own cancel and misattribute it to the late transition below).
        core.detachEngine(reason: 0)
        XCTAssertEqual(core.tcpFlowCount, 0)
        flowQueue.sync {}

        // Now fire a late state transition. This models a late kernel
        // callback firing on a connection production code has already
        // abandoned. The handler hops to the flow queue and bails at
        // `guard let connection = ctx.connection` (nil post-detach), so
        // it must NOT cancel or close anything — and must not crash
        // (pre-fix, a strong `ctx` capture would have segfaulted).
        let cancelsBefore = conn.cancelCount
        conn.transition(to: .failed(.posix(.ECONNRESET)))
        flowQueue.sync {}

        XCTAssertEqual(
            conn.cancelCount, cancelsBefore,
            "late state transition must not trigger any new cancel"
        )
        conn.simulateCancelled()
        capture.releaseAll()
    }

    // MARK: - Duplicate .ready (Wi-Fi roam recovery shape)

    /// Post-ready `.waiting` followed by another `.ready` is the
    /// Wi-Fi roam pattern. The duplicate `.ready` arm in the state
    /// handler must cancel any pending `.waiting` tolerance work
    /// item so it doesn't fire on the now-healthy connection.
    func testDuplicateReadyAfterWaitingCancelsToleranceTimer() {
        let savedTolerance = defaultEgressWaitingToleranceMs
        defaultEgressWaitingToleranceMs = 200
        defer { defaultEgressWaitingToleranceMs = savedTolerance }

        let core = TransparentProxyCore()
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let flow = MockTcpFlow()
        _ = core.handleTcpFlow(flow, meta: makeMeta())
        let conn = capture.waitForLastConnection()
        conn.transition(to: .ready)
        waitFor("flow.open invoked") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("egress receive in flight") { conn.pendingReceiveCount > 0 }

        // Go into .waiting then bounce back to .ready. Both states are
        // delivered async on `flowQueue`, so enqueuing them back-to-back
        // (no inter-transition sleep) makes FIFO do the work: the `.waiting`
        // handler arms the 200ms tolerance timer, then the `.ready` handler
        // runs on the very next queue turn and cancels it — long before the
        // deadline. The previous 50ms gap let the timer race the `.ready`
        // delivery under heavy parallel-test load (timer fires first → false
        // teardown), which is the flake this removes.
        conn.transition(to: .waiting(.posix(.ENETDOWN)))
        conn.transition(to: .ready)

        // Wait past where the tolerance WOULD have fired had the duplicate
        // .ready not cancelled it — still a regression guard: a re-introduced
        // delivery hop that lets the timer fire first would tear the flow down
        // here.
        Thread.sleep(forTimeInterval: 0.40)

        XCTAssertEqual(
            core.tcpFlowCount, 1,
            "duplicate .ready must cancel pending waiting-tolerance timer; flow should still be alive"
        )

        // Clean shutdown so the deferred detachEngine doesn't leak.
        drainAndAwaitRemoval(core, flow: flow, conn: conn)
        conn.simulateCancelled()
        capture.releaseAll()
    }

    // MARK: - Periodic flow-count reporting timer

    /// The flow-count reporting timer is scheduled on attachEngine and
    /// cancelled on detachEngine. Without explicit cancel-on-detach, an
    /// attach/detach/attach sequence would leak a timer per cycle. This
    /// drives the sequence repeatedly and checks the DEBUG timer seam so a
    /// wake/detach race cannot silently retain a repeating timer.
    func testAttachDetachCycleDoesNotLeakTimer() {
        let core = TransparentProxyCore()
        for _ in 0..<5 {
            core.attachEngine(makeEngine())
            XCTAssertTrue(core.testFlowCountReportingScheduled)
            core.detachEngine(reason: 0)
            XCTAssertFalse(core.testFlowCountReportingScheduled)
        }
        core.handleSystemWake()
        XCTAssertFalse(
            core.testFlowCountReportingScheduled,
            "wake after detach must not resurrect maintenance")
    }

    /// Mirrors the shape of a `startProxy` failure after `attachEngine`:
    /// the provider gets as far as attaching the engine, hits a later
    /// failure (e.g. `engine.config()` returns nil, or
    /// `setTunnelNetworkSettings` errors), and must locally detach so
    /// the engine + flow-count telemetry timer don't leak — Apple's
    /// runtime does NOT compensate via `stopProxy` after a failed
    /// `startProxy`. The fix in `RamaTransparentProxyProvider.swift`
    /// adds `core.detachEngine(reason: 0)` on each failure branch
    /// after attach; this test pins that the resulting state machine
    /// is usable again (the provider can be re-instantiated and
    /// re-attached cleanly) and that handleAppMessage falls through
    /// to nil in the failed/detached window.
    func testFailedStartupShapeDetachThenReattachIsClean() {
        let core = TransparentProxyCore()

        // Step 1: attach the engine, as `startProxy` does immediately
        // after engine creation.
        core.attachEngine(makeEngine())
        XCTAssertEqual(
            core.tcpFlowCount, 0,
            "freshly attached engine should have zero flows registered"
        )

        // Step 2: simulate a later-step startup failure by calling
        // `detachEngine` before any flows are handed in — what the
        // failure paths in `startProxy` now do.
        core.detachEngine(reason: 0)

        // After cleanup, handleAppMessage must short-circuit (no
        // engine attached) and not crash.
        XCTAssertNil(
            core.handleAppMessage(Data("ping".utf8)),
            "handleAppMessage after failed-startup teardown must return nil"
        )

        // Step 3: re-attach. The flow-count timer was cancelled and
        // the engine pointer cleared, so a fresh engine attaches
        // cleanly — no timer collision, no leftover registration
        // maps. If `detachEngine` had failed to release state, this
        // re-attach would surface as a double-timer schedule or a
        // dangling Rust runtime.
        core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }
        XCTAssertEqual(
            core.tcpFlowCount, 0,
            "re-attached engine should have a clean registration map"
        )
    }
}
