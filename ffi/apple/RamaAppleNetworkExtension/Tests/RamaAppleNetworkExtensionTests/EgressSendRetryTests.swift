import CryptoKit
import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// A send completion error may follow partial acceptance: "An error will be
/// sent if the associated content could not be fully sent before an error
/// occurred" (Network.framework `connection.h`). The wrapper below hands every
/// chunk to a real `NativeTcpConnection` and then reports `ENOBUFS` for one.
final class EgressSendRetryTests: XCTestCase {
    func testSendErrorAfterTheStackTookTheChunkIsNotResent() throws {
        let chunk = 64 * 1024
        let chunks = 16
        let failing = 5
        let stream = UploadPattern.data(offset: 0, count: chunk * chunks)
        let sink = try RecordingSink(capture: true)
        defer { sink.stop() }

        let queue = DispatchQueue(label: "rama.test.send-retry")
        let native = try XCTUnwrap(
            NativeTcpConnection(
                host: "127.0.0.1", port: sink.port, parameters: makeTcpNwParameters(nil).native))
        let connection = SendErrorInjectingConnection(base: native, failingSend: failing)
        let milestones = Milestones()
        connection.stateUpdateHandler = { if case .ready = $0 { milestones.reach("ready") } }
        let terminal = Locked<Error?>(nil)
        let pump = NwTcpConnectionWritePump(
            connection: connection, queue: queue, onDrained: {},
            onTerminal: { error in
                terminal.withLock { $0 = error }
                milestones.reach("terminal")
            },
            writePolicy: TcpWritePumpPolicy(maxPendingBytes: chunk * chunks))
        defer {
            pump.cancel()
            native.cancelAndDetach()
            queue.sync {}
        }
        connection.start(queue: queue)
        guard milestones.expect("ready", timeout: 10) else { return }
        // A reset that beats the accept would leave the peer with no connection at all.
        pollUntil("peer never accepted", timeout: 10) { sink.accepted }
        // Enqueue on the writer queue so no send completes before every chunk is accepted.
        let statuses = queue.sync {
            (0..<chunks).map {
                pump.enqueue(stream.subdata(in: $0 * chunk..<($0 + 1) * chunk))
            }
        }
        XCTAssertEqual(statuses, [RamaTcpDeliverStatusBridge](repeating: .accepted, count: chunks))
        pump.closeWhenDrained { milestones.reach("drained") }

        // The peer may never see the reset that ends the writer, so stop at whichever
        // comes first and then let the expected prefix arrive.
        let sent = (failing + 1) * chunk
        pollUntil("writer neither ended nor drained", timeout: 20) {
            sink.isDone || milestones.count("terminal") > 0
        }
        pollUntil("peer missing sent bytes", timeout: 10) { sink.isDone || sink.count >= sent }
        _ = sink.waitUntilDone(timeout: 1)
        let received = sink.received
        XCTAssertLessThanOrEqual(received.count, stream.count, "the peer received extra bytes")
        XCTAssertEqual(
            received, stream.prefix(received.count),
            "the peer received bytes out of stream order (a chunk was sent twice)")
        XCTAssertGreaterThanOrEqual(received.count, sent)
        guard milestones.expect("terminal", timeout: 10) else { return }
        guard case .posix(.ENOBUFS)? = terminal.withLock({ $0 }) as? NWError else {
            return XCTFail("the send error must end the writer")
        }
    }
}

/// Calls through to the real connection, then reports `ENOBUFS` for one send whose
/// content the stack already took.
private final class SendErrorInjectingConnection: NwConnectionLike, @unchecked Sendable {
    let base: NativeTcpConnection
    private let failingSend: Int
    private let sends = Locked(0)

    init(base: NativeTcpConnection, failingSend: Int) {
        self.base = base
        self.failingSend = failingSend
    }

    var state: NWConnection.State { base.state }
    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? {
        get { base.stateUpdateHandler }
        set { base.stateUpdateHandler = newValue }
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
        guard content != nil, case .contentProcessed(let done) = completion else {
            base.send(
                content: content, contentContext: contentContext, isComplete: isComplete,
                completion: completion)
            return
        }
        let index = sends.withLock { value in
            defer { value += 1 }
            return value
        }
        let inject = index == failingSend
        base.send(
            content: content, contentContext: contentContext, isComplete: isComplete,
            completion: .contentProcessed { error in
                done(inject && error == nil ? NWError.posix(.ENOBUFS) : error)
            })
    }

    func receive(
        minimumIncompleteLength: Int, maximumLength: Int,
        completion:
            @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        base.receive(
            minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength,
            completion: completion)
    }

    func requestTcpEstablishmentReport(
        queue: DispatchQueue, completion: @escaping @Sendable (TcpEstablishmentReport?) -> Void
    ) {
        base.requestTcpEstablishmentReport(queue: queue, completion: completion)
    }
}

/// Loopback sink that accepts one connection and records its stream until EOF or
/// an error. The listener binds 127.0.0.1 and picks its own port unless one is given.
final class RecordingSink: @unchecked Sendable {
    var port: UInt16 { listener.port?.rawValue ?? 0 }
    private let listener: NWListener
    private let queue = DispatchQueue(label: "rama.test.recording-sink")
    private let capture: Bool
    private let callbacks = DispatchGroup()
    private let finished = DispatchSemaphore(value: 0)
    // Queue-confined.
    private var connection: NWConnection?
    private var stopping = false
    private var bytes = Data()
    private var digest = SHA256()
    private var total = 0
    private var endError: NWError?
    private var done = false

    init(capture: Bool = false, port fixedPort: UInt16? = nil) throws {
        self.capture = capture
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(
            host: .ipv4(.loopback),
            port: fixedPort.flatMap(NWEndpoint.Port.init(rawValue:)) ?? .any)
        listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        callbacks.enter()
        listener.stateUpdateHandler = { [callbacks] state in
            switch state {
            case .ready: ready.signal()
            case .cancelled: callbacks.leave()
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self, !self.stopping, self.connection == nil else {
                connection.cancel()
                return
            }
            self.connection = connection
            // A reset can fail the connection without completing the pending receive.
            connection.stateUpdateHandler = { [weak self] state in
                guard let self, case .failed(let error) = state else { return }
                if self.endError == nil { self.endError = error }
                self.done = true
                self.finished.signal()
            }
            connection.start(queue: self.queue)
            self.read(connection)
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, listener.port != nil else {
            listener.cancel()
            throw PeerError("listener did not become ready")
        }
    }

    private func read(_ connection: NWConnection) {
        callbacks.enter()
        connection.receive(minimumIncompleteLength: 1, maximumLength: 256 * 1024) {
            [self] data, _, complete, error in
            defer { callbacks.leave() }
            guard !stopping else { return }
            if let data {
                total += data.count
                digest.update(data: data)
                if capture { bytes.append(data) }
            }
            if complete || error != nil {
                if endError == nil { endError = error }
                done = true
                finished.signal()
            } else {
                read(connection)
            }
        }
    }

    /// False if the stream did not end within `timeout`.
    func waitUntilDone(timeout: TimeInterval) -> Bool {
        finished.wait(timeout: .now() + timeout) == .success
    }

    var accepted: Bool { queue.sync { connection != nil } }
    var isDone: Bool { queue.sync { done } }
    var received: Data { queue.sync { bytes } }
    var count: Int { queue.sync { total } }
    var sha256: Data { queue.sync { Data(digest.finalize()) } }
    var error: NWError? { queue.sync { endError } }

    func stop(file: StaticString = #filePath, line: UInt = #line) {
        queue.sync {
            stopping = true
            listener.cancel()
            connection?.cancel()
        }
        XCTAssertEqual(
            callbacks.wait(timeout: .now() + 5), .success, "sink callbacks did not drain",
            file: file, line: line)
    }
}
