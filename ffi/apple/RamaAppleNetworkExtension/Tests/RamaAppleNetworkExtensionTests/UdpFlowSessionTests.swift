import Foundation
import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

final class UdpFlowSessionTests: XCTestCase {

    private final class Fixture {
        let core: TransparentProxyCore
        let flow: MockUdpFlow
        let session: UdpFlowSession<MockUdpFlow>

        init() {
            self.core = TransparentProxyCore()
            self.flow = MockUdpFlow()
            let meta = RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 2, remoteHost: "example.com", remotePort: 53,
                localHost: nil, localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil,
                sourceAppAuditToken: nil, sourceAppPid: 4242)
            self.session = UdpFlowSession(core: core, flow: flow, meta: meta)
        }

        func claimRegistration() {
            precondition(
                session.ctx.registrationGate.claim(publishing: { _ in () }) != nil)
        }
    }

    /// init() leaves ctx in idle state — no writer / no terminate.
    func testInitContextIsIdleAndEmpty() {
        let fx = Fixture()
        XCTAssertEqual(fx.session.ctx.readState, .idle)
        XCTAssertNil(fx.session.ctx.writer)
        XCTAssertNil(fx.session.ctx.terminate)
        XCTAssertNil(fx.session.ctx.requestRead)
    }

    /// `buildClientWritePump()` attaches the writer.
    func testBuildClientWritePumpAttachesToContext() {
        let fx = Fixture()
        fx.session.buildClientWritePump()
        XCTAssertNotNil(fx.session.ctx.writer)
    }

    /// `installTerminate()` wires the terminate closure; calling it
    /// flips readState to .closed and closes the flow.
    func testInstallTerminateClosesFlowOnFire() {
        let fx = Fixture()
        fx.session.installTerminate()
        XCTAssertNotNil(fx.session.ctx.terminate)
        let exp = expectation(description: "terminate dispatches")
        fx.session.flowQueue.async {
            fx.session.ctx.terminate?(nil)
            fx.session.flowQueue.async { exp.fulfill() }
        }
        wait(for: [exp], timeout: 2.0)
        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
    }

    func testNaturalServerCloseDrainsRepliesBeforeClosingWriteSide() {
        let fx = Fixture()
        fx.claimRegistration()
        fx.session.buildClientWritePump()
        fx.session.ctx.writer?.markOpened()
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "53")
        fx.session.ctx.writer?.enqueue(Data("one".utf8), sentBy: endpoint)
        fx.session.ctx.writer?.enqueue(Data("two".utf8), sentBy: endpoint)
        fx.session.flowQueue.sync {}

        fx.session.requestGracefulServerClose()
        fx.session.ctx.writer?.enqueue(Data("late".utf8), sentBy: endpoint)
        fx.session.flowQueue.sync {}

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 0)
        XCTAssertEqual(fx.flow.writtenBatches.first?.datagrams, [Data("one".utf8)])

        XCTAssertTrue(fx.flow.completePendingWrite(error: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.closeWriteCallCount, 0)
        XCTAssertEqual(fx.flow.writtenBatches.first?.datagrams, [Data("two".utf8)])

        XCTAssertTrue(fx.flow.completePendingWrite(error: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertTrue(fx.flow.writtenBatches.isEmpty)
    }

    func testImmediateTerminateWinsInProgressNaturalDrain() {
        let fx = Fixture()
        fx.claimRegistration()
        fx.session.installTerminate()
        fx.session.buildClientWritePump()
        fx.session.ctx.writer?.markOpened()
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "53")
        fx.session.ctx.writer?.enqueue(Data("stuck".utf8), sentBy: endpoint)
        fx.session.flowQueue.sync {}

        fx.session.requestGracefulServerClose()
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.closeWriteCallCount, 0)

        fx.session.ctx.terminate?(
            NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)

        XCTAssertTrue(fx.flow.completePendingWrite(error: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
    }

    func testQueuedWriteErrorPreemptsLaterNaturalClose() {
        let fx = Fixture()
        fx.claimRegistration()
        fx.session.installTerminate()
        fx.session.buildClientWritePump()
        fx.session.ctx.writer?.markOpened()
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "53")
        fx.session.ctx.writer?.enqueue(Data("stuck".utf8), sentBy: endpoint)
        fx.session.flowQueue.sync {}

        let blockerStarted = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        fx.session.flowQueue.async {
            blockerStarted.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 1), .success)

        let writeError = NSError(domain: NSPOSIXErrorDomain, code: Int(EPIPE))
        XCTAssertTrue(fx.flow.completePendingWrite(error: writeError))
        // The error completion is now queued first; natural close is queued
        // second. Immediate teardown must run inline with the first block so
        // the graceful block cannot replace EPIPE with a clean close.
        fx.session.requestGracefulServerClose()
        releaseBlocker.signal()
        fx.session.flowQueue.sync {}

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual((fx.flow.lastCloseWriteError as NSError?)?.domain, NSPOSIXErrorDomain)
        XCTAssertEqual((fx.flow.lastCloseWriteError as NSError?)?.code, Int(EPIPE))
    }

    func testNaturalServerCloseBackstopTerminatesStuckKernelWrite() {
        let fx = Fixture()
        fx.claimRegistration()
        fx.session.gracefulDrainTimeoutMs = 20
        fx.session.buildClientWritePump()
        fx.session.ctx.writer?.markOpened()
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "53")
        fx.session.ctx.writer?.enqueue(Data("stuck".utf8), sentBy: endpoint)
        fx.session.flowQueue.sync {}

        fx.session.requestGracefulServerClose()
        let backstopObserved = expectation(description: "graceful close backstop fired")
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(100)) {
            backstopObserved.fulfill()
        }
        wait(for: [backstopObserved], timeout: 2)

        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertTrue(fx.session.ctx.writer?.testAdmissionSnapshot.closed == true)
    }

    /// Without an engine attached, `requestEngineSession()` returns nil.
    func testRequestEngineSessionWithoutEngineReturnsNil() {
        let fx = Fixture()
        XCTAssertNil(fx.session.requestEngineSession())
    }

    /// `start()` without an engine returns false (= flow not claimed).
    func testStartWithoutEngineReturnsFalse() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.start())
    }

    /// `installRequestRead()` wires the request-read closure; firing
    /// it kicks `flow.readDatagrams` exactly once.
    func testInstallRequestReadIssuesReadDatagrams() {
        let fx = Fixture()
        fx.session.installRequestRead()
        XCTAssertEqual(fx.flow.pendingReadCount, 0)
        let exp = expectation(description: "requestRead dispatches")
        fx.session.flowQueue.async {
            fx.session.ctx.requestRead?()
            fx.session.flowQueue.async { exp.fulfill() }
        }
        wait(for: [exp], timeout: 2.0)
        XCTAssertEqual(fx.flow.pendingReadCount, 1)
        XCTAssertEqual(fx.session.ctx.readState, .reading)
    }

    func testRequestReadFromFlowQueueNeverReentersReadDatagrams() {
        let fx = Fixture()
        fx.session.installRequestRead()

        fx.session.flowQueue.sync {
            fx.session.ctx.requestRead?()
            XCTAssertEqual(
                fx.flow.pendingReadCount, 0,
                "Rust demand must unwind before a kernel read is issued")
        }
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.pendingReadCount, 1)
    }

    /// While a read is in flight, a second `requestRead` coalesces
    /// into the `readingWithDemand` state — does NOT issue a second
    /// concurrent `readDatagrams`.
    func testRequestReadCoalescesWhileReadInFlight() {
        let fx = Fixture()
        fx.session.installRequestRead()
        let exp = expectation(description: "two demands dispatched")
        fx.session.flowQueue.async {
            fx.session.ctx.requestRead?()
            fx.session.ctx.requestRead?()
            fx.session.flowQueue.async { exp.fulfill() }
        }
        wait(for: [exp], timeout: 2.0)
        XCTAssertEqual(fx.flow.pendingReadCount, 1, "second demand must not issue a second concurrent read")
        XCTAssertEqual(fx.session.ctx.readState, .readingWithDemand)
    }

    func testRequestReadBurstQueuesOneSaturatingRunner() {
        let fx = Fixture()
        fx.session.installRequestRead()
        guard let requestRead = fx.session.ctx.requestRead else {
            return XCTFail("requestRead installed")
        }

        let blockerStarted = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        fx.session.flowQueue.async {
            blockerStarted.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 1), .success)

        DispatchQueue.concurrentPerform(iterations: 50_000) { _ in requestRead() }
        let saturated = fx.session.testReadDemandSnapshot
        XCTAssertEqual(saturated.credits, 2)
        XCTAssertTrue(saturated.runnerQueued)
        XCTAssertEqual(saturated.runnerSchedules, 1)
        XCTAssertEqual(fx.flow.pendingReadCount, 0)

        releaseBlocker.signal()
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.pendingReadCount, 1)
        XCTAssertEqual(fx.session.ctx.readState, .readingWithDemand)
    }

    func testProbeIdsPreserveFirstSecondAndAckSaturatedDemand() {
        let fx = Fixture()
        fx.session.installRequestRead()
        let acknowledged = Locked<[UInt64]>([])
        fx.session.testProbeAcknowledger = { id in
            acknowledged.withLock { $0.append(id) }
        }

        let blockerStarted = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        fx.session.flowQueue.async {
            blockerStarted.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 1), .success)
        fx.session.ctx.requestReadWithProbe?(11)
        fx.session.ctx.requestReadWithProbe?(22)
        fx.session.ctx.requestReadWithProbe?(33)
        XCTAssertEqual(fx.session.testReadDemandSnapshot.firstProbeId, 11)
        XCTAssertEqual(fx.session.testReadDemandSnapshot.secondProbeId, 22)
        XCTAssertEqual(
            acknowledged.withLock { $0 }, [],
            "saturated demand callback must return without synchronous FFI ACK re-entry"
        )

        releaseBlocker.signal()
        fx.session.flowQueue.sync {}
        XCTAssertEqual(acknowledged.withLock { $0 }, [33])
        XCTAssertEqual(fx.flow.pendingReadCount, 1)
        XCTAssertEqual(fx.session.ctx.readState, .readingWithDemand)
        XCTAssertTrue(fx.flow.completePendingRead(datagrams: [Data([1])], endpoints: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(acknowledged.withLock { $0 }, [33, 11, 22])
    }

    func testProbeIdsAckOnErrorAndEofBranches() {
        for (probeId, datagrams, error) in [
            (UInt64(41), Optional<[Data]>.none,
             Optional<Error>.some(NSError(domain: NSPOSIXErrorDomain, code: Int(EIO)))),
            (UInt64(42), Optional<[Data]>.some([]), Optional<Error>.none),
        ] {
            let fx = Fixture()
            fx.session.installRequestRead()
            let acknowledged = Locked<[UInt64]>([])
            fx.session.testProbeAcknowledger = { id in
                acknowledged.withLock { $0.append(id) }
            }
            fx.session.ctx.requestReadWithProbe?(probeId)
            fx.session.ctx.requestReadWithProbe?(probeId + 100)
            fx.session.flowQueue.sync {}
            XCTAssertTrue(
                fx.flow.completePendingRead(datagrams: datagrams, endpoints: nil, error: error))
            fx.session.flowQueue.sync {}
            XCTAssertEqual(acknowledged.withLock { $0 }, [probeId, probeId + 100])
        }
    }

    func testSessionMissingAcksCurrentAndPendingProbeIds() {
        let fx = Fixture()
        fx.session.installRequestRead()
        let acknowledged = Locked<[UInt64]>([])
        fx.session.testProbeAcknowledger = { id in
            acknowledged.withLock { $0.append(id) }
        }
        fx.session.ctx.requestReadWithProbe?(51)
        fx.session.ctx.requestReadWithProbe?(52)
        fx.session.flowQueue.sync {}
        XCTAssertTrue(fx.flow.completePendingRead(datagrams: [Data([1])], endpoints: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(acknowledged.withLock { $0 }, [51, 52])
    }

    func testStagingRejectAcksExactProbeAndIssuesOneReplacementRead() {
        let fx = Fixture()
        fx.session.installRequestRead()
        let acknowledged = Locked<[UInt64]>([])
        fx.session.testProbeAcknowledger = { id in
            acknowledged.withLock { $0.append(id) }
        }
        var retained = fx.session.testFillGlobalIngressStaging()
        XCTAssertNotNil(retained)
        fx.session.ctx.requestReadWithProbe?(61)
        fx.session.ctx.requestReadWithProbe?(62)
        fx.session.flowQueue.sync {}
        XCTAssertTrue(fx.flow.completePendingRead(datagrams: [Data([1])], endpoints: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(acknowledged.withLock { $0 }, [61])
        XCTAssertTrue(fx.session.testStagingCapacityWaiting)
        XCTAssertEqual(
            fx.flow.pendingReadCount, 0,
            "a hot source must stop reading while Swift staging remains full")

        retained = nil
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.pendingReadCount, 1)
        XCTAssertEqual(fx.session.ctx.readState, .reading)
        XCTAssertTrue(fx.flow.completePendingRead(datagrams: [], endpoints: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(acknowledged.withLock { $0 }, [61, 62])
    }

    func testTerminateOvertakesQueuedStagingGrantWithoutIssuingRead() {
        let fx = Fixture()
        fx.session.installTerminate()
        fx.session.installRequestRead()
        let acknowledged = Locked<[UInt64]>([])
        fx.session.testProbeAcknowledger = { id in
            acknowledged.withLock { $0.append(id) }
        }
        var retained = fx.session.testFillGlobalIngressStaging()
        XCTAssertNotNil(retained)
        fx.session.ctx.requestReadWithProbe?(81)
        fx.session.ctx.requestReadWithProbe?(82)
        fx.session.flowQueue.sync {}
        XCTAssertTrue(fx.flow.completePendingRead(datagrams: [Data([1])], endpoints: nil))
        fx.session.flowQueue.sync {}
        XCTAssertEqual(acknowledged.withLock { $0 }, [81])
        XCTAssertTrue(fx.session.testStagingCapacityWaiting)
        XCTAssertEqual(fx.flow.pendingReadCount, 0)

        let blockerStarted = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        fx.session.flowQueue.async {
            blockerStarted.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 30), .success)

        // Queue terminal teardown first. Releasing capacity then installs a
        // provisional grant and queues its resume behind that teardown. Once
        // the queue drains, close must cancel the grant, ACK the parked probe,
        // and make the stale resume incapable of starting an Apple read.
        fx.session.ctx.terminate?(nil)
        retained = nil
        releaseBlocker.signal()
        fx.session.flowQueue.sync {}

        XCTAssertEqual(acknowledged.withLock { $0 }, [81, 82])
        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertFalse(fx.session.testStagingCapacityWaiting)
        XCTAssertEqual(fx.flow.pendingReadCount, 0)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
    }

    func testOversizedStagingDatagramTerminatesAndLogsWithoutParking() {
        let fx = Fixture()
        fx.session.installTerminate()
        fx.session.installRequestRead()
        let notices = Locked<[String]>([])
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        defer { LifecycleLog.noticeOverride = nil }

        fx.session.ctx.requestRead?()
        fx.session.flowQueue.sync {}
        XCTAssertTrue(
            fx.flow.completePendingRead(
                datagrams: [Data(count: UdpIngressStagingPolicy.testDefaults.maxBytesPerFlow + 1)],
                endpoints: nil))
        fx.session.flowQueue.sync {}

        XCTAssertEqual(fx.session.ctx.readState, .closed)
        XCTAssertFalse(fx.session.testStagingCapacityWaiting)
        XCTAssertEqual(fx.flow.pendingReadCount, 0)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertTrue(
            notices.withLock { messages in
                messages.contains { message in
                    message.contains("reason=\"oversized_bytes\"")
                        && message.contains("terminating flow")
                }
            })
    }

    func testCloseAcksQueuedPendingProbeExactlyOnce() {
        let fx = Fixture()
        fx.session.installTerminate()
        fx.session.installRequestRead()
        let acknowledged = Locked<[UInt64]>([])
        fx.session.testProbeAcknowledger = { id in
            acknowledged.withLock { $0.append(id) }
        }
        fx.session.ctx.requestReadWithProbe?(71)
        fx.session.ctx.requestReadWithProbe?(72)
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.session.ctx.readState, .readingWithDemand)

        fx.session.ctx.terminate?(nil)
        fx.session.flowQueue.sync {}
        XCTAssertEqual(acknowledged.withLock { $0 }, [72])
        XCTAssertEqual(fx.session.ctx.readState, .closed)
    }

    func testReadErrorClosesDemandBeforeQueuedRunner() {
        let fx = Fixture()
        fx.session.installTerminate()
        fx.session.installRequestRead()
        fx.session.ctx.requestRead?()
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.pendingReadCount, 1)

        XCTAssertTrue(
            fx.flow.completePendingRead(
                error: NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNRESET))))
        // This runner lands behind the error handler but ahead of the teardown
        // block that the handler queues. The closed demand gate must stop it
        // from issuing a post-terminal kernel read.
        fx.session.ctx.requestRead?()
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.flow.pendingReadCount, 0)
        fx.session.flowQueue.sync {}
        XCTAssertEqual(fx.session.ctx.readState, .closed)
    }

    func testIdleActivityIsMonotonicAndStopsAtTermination() {
        let fx = Fixture()
        fx.session.idleTimeoutMs = 1_000
        fx.session.installTerminate()
        fx.session.recordIdleActivity(nowUptimeNs: 200)
        fx.session.recordIdleActivity(nowUptimeNs: 100)
        XCTAssertEqual(fx.session.testIdleActivitySnapshot.lastUptimeNs, 200)

        fx.session.ctx.terminate?(nil)
        fx.session.flowQueue.sync {}
        fx.session.recordIdleActivity(nowUptimeNs: 300)
        let closed = fx.session.testIdleActivitySnapshot
        XCTAssertTrue(closed.closed)
        XCTAssertNil(closed.lastUptimeNs)
    }
}
