import CryptoKit
import Darwin
import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Egress `.failed` after promotion, through the production wiring: the
/// promoted forwarder, its `TcpFlowContext` owner and the session's egress state
/// handler over a `NativeTcpConnection` and a loopback peer. The NE flow is
/// synthetic and promotion signals are injected.
final class PromotedNativeEgressFailureTests: XCTestCase {
    private let writerCap = 262_144

    func testResetBehindQueuedResponseDrainsItBeforeTeardown() throws {
        let milestones = Milestones()
        let upload = UploadPattern.data(offset: 0, count: 48 * 1024 + 5)
        // Below the client writer cap: every byte is returned by `receive`
        // while the synthetic client holds its first write.
        let response = UploadPattern.data(offset: 1 << 30, count: 3 * 64 * 1024 + 4321)
        let peer = try ScriptedPeer(milestones: milestones) { peer in
            var digest = SHA256()
            try peer.readExactly(upload.count, into: &digest)
            guard Data(digest.finalize()) == Data(SHA256.hash(data: upload)) else {
                throw PeerError("upload digest mismatch")
            }
            try peer.send(response)
            // A send completion does not prove remote receipt; wait for the
            // forwarder's receive to return every response byte.
            guard milestones.waitFor(["response received", "upload sent"], timeout: 20)
            else { return }
            try peer.reset()
            milestones.reach("peer reset")
        }
        defer { peer.stop() }

        let h = try PromotedSessionHarness(
            port: peer.port, milestones: milestones, cap: writerCap,
            responseBytes: response.count, uploadBytes: upload.count)
        defer { h.cleanup() }
        guard milestones.expect("ready", timeout: 10) else { return }
        h.promote()

        guard waitForClientRead(h.flow, milestones) else { return }
        h.flow.completeRead(data: upload, error: nil)
        // The upload now waits in `readData` for bytes the client never sends.
        guard waitForClientRead(h.flow, milestones) else { return }
        guard milestones.expect("peer reset", "state failed", "receive ended", timeout: 20)
        else { return }
        let sentBeforeTeardown = h.connection.sentBytes.withLock { $0 }

        h.releaseClientWrites()
        XCTAssertEqual(h.flow.closeWriteCallCount, 1, "client write half never closed")
        let delivered = h.delivered
        XCTAssertEqual(
            delivered.count, response.count,
            "received response bytes were not delivered; events \(milestones.order)")
        XCTAssertEqual(
            delivered, response.prefix(delivered.count), "response delivered out of order")
        XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, Int(ECONNRESET))

        pollUntil("flow not torn down", timeout: 20) { h.queue.sync { h.ctx.isDone } }
        XCTAssertEqual(h.flow.closeReadCallCount, 1)
        XCTAssertEqual((h.flow.lastCloseReadError as NSError?)?.code, Int(ECONNRESET))
        XCTAssertNil(h.queue.sync { h.ctx.connection })

        // The blocked upload read is released: a late result is not forwarded.
        h.flow.completeRead(data: Data([0xAB]), error: nil)
        h.queue.sync {}
        XCTAssertEqual(h.connection.sentBytes.withLock { $0 }, sentBeforeTeardown)
        XCTAssertTrue(milestones.failures.isEmpty, milestones.failures.joined(separator: "\n"))
    }

    func testOrderlyCloseAfterUploadDeliversQueuedResponse() throws {
        let milestones = Milestones()
        let upload = UploadPattern.data(offset: 0, count: 48 * 1024 + 5)
        let response = UploadPattern.data(offset: 1 << 30, count: 3 * 64 * 1024 + 4321)
        let peer = try ScriptedPeer(milestones: milestones) { peer in
            var digest = SHA256()
            guard try peer.readToEnd(into: &digest) == upload.count,
                Data(digest.finalize()) == Data(SHA256.hash(data: upload))
            else { throw PeerError("upload mismatch") }
            try peer.send(response)
            try peer.shutdownWrite()
        }
        defer { peer.stop() }

        let h = try PromotedSessionHarness(
            port: peer.port, milestones: milestones, cap: writerCap,
            responseBytes: response.count, uploadBytes: upload.count)
        defer { h.cleanup() }
        guard milestones.expect("ready", timeout: 10) else { return }
        h.promote()

        guard waitForClientRead(h.flow, milestones) else { return }
        h.flow.completeRead(data: upload, error: nil)
        guard waitForClientRead(h.flow, milestones) else { return }
        h.flow.completeRead(data: nil, error: nil)
        // Network.framework reports `.failed` once both FINs are exchanged.
        guard milestones.expect("peer write closed", "state failed", timeout: 20) else { return }

        h.releaseClientWrites()
        XCTAssertEqual(h.flow.closeWriteCallCount, 1, "client write half never closed")
        let delivered = h.delivered
        XCTAssertEqual(
            delivered.count, response.count,
            "response bytes were not delivered; events \(milestones.order)")
        XCTAssertEqual(
            delivered, response.prefix(delivered.count), "response delivered out of order")
        XCTAssertNil(h.flow.lastCloseWriteError, "orderly close reported as an error")
        pollUntil("flow not closed", timeout: 20) { h.queue.sync { h.ctx.isDone } }
        XCTAssertEqual(h.flow.closeReadCallCount, 1)
        XCTAssertNil(h.flow.lastCloseReadError, "orderly close reported as an error")
        XCTAssertTrue(milestones.failures.isEmpty, milestones.failures.joined(separator: "\n"))
    }

    func testUploadSendFailureAfterResetDrainsQueuedResponse() throws {
        let milestones = Milestones()
        let upload = UploadPattern.data(offset: 0, count: 48 * 1024 + 5)
        let response = UploadPattern.data(offset: 1 << 30, count: 3 * 64 * 1024 + 4321)
        let peer = try ScriptedPeer(milestones: milestones) { peer in
            var digest = SHA256()
            try peer.readExactly(upload.count, into: &digest)
            try peer.send(response)
            // The peer stops reading, so the continued upload fills the socket buffers.
            guard milestones.waitFor(["response received", "upload held"], timeout: 30)
            else { return }
            try peer.reset()
            milestones.reach("peer reset")
        }
        defer { peer.stop() }

        let h = try PromotedSessionHarness(
            port: peer.port, milestones: milestones, cap: writerCap,
            responseBytes: response.count, uploadBytes: upload.count)
        defer { h.cleanup() }
        guard milestones.expect("ready", timeout: 10) else { return }
        h.promote()
        guard waitForClientRead(h.flow, milestones) else { return }
        h.flow.completeRead(data: upload, error: nil)
        guard milestones.expect("response received", timeout: 20) else { return }

        // Keep uploading until one send has been held by the kernel for 200 ms.
        var offset = upload.count
        var held: (completed: Int, since: Date)?
        let deadline = Date().addingTimeInterval(30)
        while milestones.failures.isEmpty && Date() < deadline {
            if h.flow.pendingReadCount > 0 {
                h.flow.completeRead(
                    data: UploadPattern.data(offset: offset, count: 65536), error: nil)
                offset += 65536
            }
            let sends = h.connection.sends.withLock { $0 }
            if sends.issued > sends.completed {
                if held?.completed != sends.completed { held = (sends.completed, Date()) }
                if Date().timeIntervalSince(held!.since) > 0.2 { break }
            } else {
                held = nil
            }
            Thread.sleep(forTimeInterval: 0.002)
        }
        milestones.reach("upload held")
        // The held send or the server read may fail first; both orders are accepted.
        guard milestones.expect("peer reset", "upload send failed", timeout: 20) else { return }

        h.releaseClientWrites()
        XCTAssertEqual(h.flow.closeWriteCallCount, 1, "client write half never closed")
        let delivered = h.delivered
        XCTAssertEqual(
            delivered.count, response.count,
            "received response bytes were not delivered; events \(milestones.order)")
        XCTAssertEqual(
            delivered, response.prefix(delivered.count), "response delivered out of order")
        XCTAssertEqual((h.flow.lastCloseWriteError as NSError?)?.code, Int(ECONNRESET))
        pollUntil("flow not torn down", timeout: 20) { h.queue.sync { h.ctx.isDone } }
        XCTAssertEqual(h.flow.closeReadCallCount, 1)
        XCTAssertEqual((h.flow.lastCloseReadError as NSError?)?.code, Int(ECONNRESET))
        XCTAssertTrue(milestones.failures.isEmpty, milestones.failures.joined(separator: "\n"))
    }
}

// MARK: - Fixtures

/// The production promotion wiring: `makePromotedForwarder`, a `TcpFlowContext`
/// owner and the session's egress state handler over a `NativeTcpConnection`.
/// The synthetic client holds every write until `releaseClientWrites`.
final class PromotedSessionHarness {
    let flow = MockTcpFlow()
    let session: TcpFlowSession<MockTcpFlow>
    let connection: ObservedConnection
    let budget = WriterMemoryBudget()
    let client: TcpClientWritePump
    let egress: NwTcpConnectionWritePump
    private let core = TransparentProxyCore()
    private let forwarderRef = ForwarderRef()
    var ctx: TcpFlowContext { session.ctx }
    var queue: DispatchQueue { session.flowQueue }

    init(
        port: UInt16, milestones: Milestones, cap: Int, responseBytes: Int, uploadBytes: Int
    ) throws {
        flow.captureWriteCompletions = true
        session = TcpFlowSession(
            core: core, flow: flow,
            meta: RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 1, remoteHost: "127.0.0.1", remotePort: port,
                localHost: nil, localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil,
                sourceAppAuditToken: nil, sourceAppPid: 4242),
            egressReportEnabled: { false })
        guard
            let native = NativeTcpConnection(
                host: "127.0.0.1", port: port, parameters: makeTcpNwParameters(nil).native)
        else { throw PeerError("NativeTcpConnection could not be constructed") }
        connection = ObservedConnection(
            base: native, milestones: milestones,
            responseBytes: responseBytes, uploadBytes: uploadBytes)
        let ctx = session.ctx
        let forwarderRef = forwarderRef
        let policy = TcpWritePumpPolicy(maxPendingBytes: cap)
        client = TcpClientWritePump(
            flow: flow, queue: session.flowQueue, logger: { _ in },
            onTerminalError: { [weak ctx] in ctx?.applyWriterTerminal($0) },
            onDrained: { forwarderRef.value?.onClientPumpDrained() },
            writerMemoryBudget: budget, writePolicy: policy)
        // Same terminal routing as the session's promoted egress writer.
        egress = NwTcpConnectionWritePump(
            connection: connection, queue: session.flowQueue,
            onDrained: { forwarderRef.value?.onEgressPumpDrained() },
            onTerminal: { [weak ctx] in ctx?.applyPromotedEgressWriterTerminal($0) },
            writerMemoryBudget: budget, writePolicy: policy)
        connection.start(queue: session.flowQueue)
    }

    /// Cut over an established egress as `beginPromoteCutover` leaves it; the
    /// session's state handler stays installed.
    func promote() {
        let forwarder = queue.sync {
            ctx.connection = connection
            ctx.clientWritePump = client
            ctx.egressWritePump = egress
            ctx.mode = .promoted
            ctx.egressReady = true
            session.egressReady = true
            session.installEgressStateHandler(connection: connection)
            return core.makePromotedForwarder(
                ctx: ctx, flow: flow, connection: connection,
                clientWritePump: client, egressWritePump: egress, flowQueue: queue)
        }
        forwarderRef.value = forwarder
        client.markOpened()
        forwarder.markClientReadDrained()
        forwarder.markEgressReadDrained()
        forwarder.markRustC2SDone()
        forwarder.markRustS2CDone()
    }

    /// Completes held client writes one at a time until the write half closes.
    func releaseClientWrites(timeout: TimeInterval = 20) {
        let deadline = Date().addingTimeInterval(timeout)
        while flow.closeWriteCallCount == 0 && Date() < deadline {
            if !flow.completeNextWrite() { Thread.sleep(forTimeInterval: 0.005) }
            queue.sync {}
        }
    }

    var delivered: Data { flow.writes.reduce(into: Data()) { $0.append($1) } }

    func cleanup(file: StaticString = #filePath, line: UInt = #line) {
        queue.sync { ctx.applyEngineDetached() }
        while flow.completeNextWrite() {}
        flow.completeRead(
            data: nil, error: NSError(domain: NSPOSIXErrorDomain, code: Int(ECANCELED)))
        connection.base.cancelAndDetach()
        queue.sync {}
        let deadline = Date().addingTimeInterval(5)
        while budget.snapshot().retainedBytes != 0 && Date() < deadline {
            flow.completeNextWrite()
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 0, file: file, line: line)
    }
}

/// Passes everything to the native connection and records the receive, send
/// and state milestones the production-wiring tests gate on.
final class ObservedConnection: NwConnectionLike, @unchecked Sendable {
    let base: NativeTcpConnection
    let receivedBytes = Locked(0)
    let sentBytes = Locked(0)
    /// Payload sends issued and completed, so a test can see one held by the kernel.
    let sends = Locked((issued: 0, completed: 0))
    private let handler = Locked<(@Sendable (NWConnection.State) -> Void)?>(nil)
    private let observe: (milestones: Milestones, responseBytes: Int, uploadBytes: Int)

    init(base: NativeTcpConnection, milestones: Milestones, responseBytes: Int, uploadBytes: Int) {
        self.base = base
        observe = (milestones, responseBytes, uploadBytes)
        let handler = handler
        base.stateUpdateHandler = { state in
            switch state {
            case .ready: milestones.reach("ready")
            case .failed: milestones.reach("state failed")
            default: break
            }
            handler.withLock { $0 }?(state)
        }
    }

    var state: NWConnection.State { base.state }

    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? {
        get { handler.withLock { $0 } }
        set { handler.withLock { $0 = newValue } }
    }

    var viabilityUpdateHandler: (@Sendable (Bool) -> Void)? {
        get { base.viabilityUpdateHandler }
        set { base.viabilityUpdateHandler = newValue }
    }

    func start(queue: DispatchQueue) { base.start(queue: queue) }
    func cancel() { base.cancel() }
    func forceCancel() { base.forceCancel() }

    func send(
        content: Data?, contentContext: NWConnection.ContentContext, isComplete: Bool,
        completion: NWConnection.SendCompletion
    ) {
        guard case .contentProcessed(let done) = completion, let count = content?.count else {
            base.send(
                content: content, contentContext: contentContext, isComplete: isComplete,
                completion: completion)
            return
        }
        let observe = observe
        let sentBytes = sentBytes
        let sends = sends
        sends.withLock { $0.issued += 1 }
        base.send(
            content: content, contentContext: contentContext, isComplete: isComplete,
            completion: .contentProcessed { error in
                sends.withLock { $0.completed += 1 }
                if error != nil { observe.milestones.reach("upload send failed") }
                if error == nil {
                    let sent = sentBytes.withLock { $0 += count; return $0 }
                    if sent == observe.uploadBytes { observe.milestones.reach("upload sent") }
                }
                done(error)
            })
    }

    func receive(
        minimumIncompleteLength: Int, maximumLength: Int,
        completion:
            @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        let observe = observe
        let receivedBytes = receivedBytes
        base.receive(
            minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength
        ) { data, context, complete, error in
            if let count = data?.count, count > 0 {
                let total = receivedBytes.withLock { $0 += count; return $0 }
                if total == observe.responseBytes { observe.milestones.reach("response received") }
            }
            if complete || error != nil { observe.milestones.reach("receive ended") }
            completion(data, context, complete, error)
        }
    }

    func requestTcpEstablishmentReport(
        queue: DispatchQueue, completion: @escaping @Sendable (TcpEstablishmentReport?) -> Void
    ) {
        base.requestTcpEstablishmentReport(queue: queue, completion: completion)
    }
}
