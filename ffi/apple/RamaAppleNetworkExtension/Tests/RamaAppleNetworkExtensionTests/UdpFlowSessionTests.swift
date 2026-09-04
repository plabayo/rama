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

    func testNaturalServerCloseBackstopTerminatesStuckKernelWrite() {
        let fx = Fixture()
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
