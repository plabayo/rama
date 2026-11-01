import CryptoKit
import Darwin
import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Production promoted pumps over `NativeTcpConnection` against a loopback TCP
/// peer. The NE flow is synthetic and promotion signals are injected, so this
/// covers neither the Rust promotion handshake, a signed provider, content
/// filters nor TLS.
final class PromotedNativeUploadIntegrityTests: XCTestCase {
    private let writerCap = 262_144

    // MARK: - Upload integrity

    func testOddSizedUploadWithCarryoverAndBoundedWriter() throws {
        let milestones = Milestones()
        let total = 32 * 1024 * 1024 + 19
        // Larger than the writer cap and not aligned to the 64 KiB slice size.
        let carryoverCount = 393_233
        let received = Locked<(count: Int, digest: Data)?>(nil)
        let peer = try ScriptedPeer(milestones: milestones) { peer in
            var digest = SHA256()
            let count = try peer.readToEnd(into: &digest, chunk: 32_749, pacingMicros: 100)
            let finalized = Data(digest.finalize())
            received.withLock { $0 = (count, finalized) }
            try peer.send(finalized)
            try peer.shutdownWrite()
            milestones.reach("peer done")
        }
        defer { peer.stop() }

        let flow = UploadPatternFlow(total: total, start: carryoverCount)
        let harness = try NativeForwarderHarness(
            port: peer.port, flow: flow, milestones: milestones, cap: writerCap)
        defer { harness.cleanup() }
        guard milestones.expect("ready", timeout: 10) else { return }

        harness.client.markOpened()
        autoreleasepool {
            harness.forwarder.acceptClientCarryover(
                UploadPattern.payload(offset: 0, count: carryoverCount))
        }
        harness.startForwarding()
        guard milestones.expect("terminal", "peer done", timeout: 90) else { return }

        let expected = UploadPattern.digest(offset: 0, count: total)
        let peerResult = try XCTUnwrap(received.withLock { $0 })
        XCTAssertEqual(peerResult.count, total)
        XCTAssertEqual(peerResult.digest, expected)
        XCTAssertEqual(flow.response.withLock { $0 }, expected)
        XCTAssertGreaterThan(flow.reads.withLock { $0 }, 100)
        XCTAssertEqual(milestones.count("client write closed"), 1)
        XCTAssertEqual(harness.terminals.withLock { $0 }, 1)
        // Carryover above the cap must meet `.paused` writer admission and be replayed;
        // kernel socket backpressure depends on peer pacing and is not asserted.
        XCTAssertGreaterThan(harness.pauseChecks.withLock { $0 }, 0)
    }

    // MARK: - Early server half-close

    func testEarlyServerHalfCloseKeepsUploadFlowing() throws {
        let milestones = Milestones()
        let response = Data("HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n".utf8)
        let firstPhase = [1, 4095, 65537, 131_073, 7]
        let secondPhase = [65536, 17, 262_145, 14, 393_233, 3]
        let firstCount = firstPhase.reduce(0, +)
        let total = firstCount + secondPhase.reduce(0, +)
        let received = Locked<(count: Int, digest: Data)?>(nil)
        let peer = try ScriptedPeer(milestones: milestones) { peer in
            var digest = SHA256()
            try peer.readExactly(firstCount, into: &digest)
            try peer.send(response)
            try peer.shutdownWrite()
            let rest = try peer.readToEnd(into: &digest)
            received.withLock { $0 = (firstCount + rest, Data(digest.finalize())) }
            milestones.reach("peer done")
        }
        defer { peer.stop() }

        let flow = MockTcpFlow()
        let harness = try NativeForwarderHarness(
            port: peer.port, flow: flow, milestones: milestones, cap: writerCap,
            closeClientWrite: { flow.closeWriteWithError($0) })
        defer { harness.cleanup() }
        guard milestones.expect("ready", timeout: 10) else { return }
        harness.client.markOpened()
        harness.startForwarding()

        var offset = 0
        for size in firstPhase {
            guard waitForClientRead(flow, milestones) else { return }
            flow.completeRead(data: UploadPattern.data(offset: offset, count: size), error: nil)
            offset += size
        }
        // The forwarder closes the client write half only after it received the
        // server FIN and drained the response.
        guard milestones.expect("client write closed", timeout: 20) else { return }
        XCTAssertEqual(flow.writes.reduce(into: Data()) { $0.append($1) }, response)
        XCTAssertNil(flow.lastCloseWriteError)
        XCTAssertEqual(harness.queue.sync { harness.forwarder.s2cPhase }, .finished)
        XCTAssertEqual(harness.queue.sync { harness.forwarder.c2sPhase }, .active)
        XCTAssertEqual(harness.terminals.withLock { $0 }, 0)

        for size in secondPhase {
            guard waitForClientRead(flow, milestones) else { return }
            flow.completeRead(data: UploadPattern.data(offset: offset, count: size), error: nil)
            offset += size
        }
        guard waitForClientRead(flow, milestones) else { return }
        flow.completeRead(data: nil, error: nil)
        guard milestones.expect("terminal", "peer done", timeout: 30) else { return }

        let peerResult = try XCTUnwrap(received.withLock { $0 })
        XCTAssertEqual(peerResult.count, total)
        XCTAssertEqual(peerResult.digest, UploadPattern.digest(offset: 0, count: total))
        XCTAssertEqual(flow.writes.reduce(into: Data()) { $0.append($1) }, response)
        XCTAssertEqual(flow.closeWriteCallCount, 1)
        XCTAssertEqual(harness.terminals.withLock { $0 }, 1)
        XCTAssertEqual(
            milestones.order.filter { $0 == "client write closed" || $0 == "terminal" },
            ["client write closed", "terminal"])
    }
}

// MARK: - Fixtures

extension XCTestCase {
    /// Waits for the forwarder's next `readData`, failing early on a recorded failure.
    func waitForClientRead(
        _ flow: MockTcpFlow, _ milestones: Milestones,
        file: StaticString = #filePath, line: UInt = #line
    ) -> Bool {
        let deadline = Date().addingTimeInterval(20)
        while flow.pendingReadCount == 0 && milestones.failures.isEmpty && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.002)
        }
        let failures = milestones.failures
        guard failures.isEmpty else {
            XCTFail(failures.joined(separator: "\n"), file: file, line: line)
            return false
        }
        guard flow.pendingReadCount > 0 else {
            XCTFail("forwarder issued no client read", file: file, line: line)
            return false
        }
        return true
    }
}

/// Callbacks and the peer only record; the test thread asserts. Late callbacks
/// therefore cannot fail a later test.
final class Milestones: @unchecked Sendable {
    private let condition = NSCondition()
    private var counts: [String: Int] = [:]
    private var reached: [String] = []
    private var failed: [String] = []

    func reach(_ name: String) {
        condition.lock()
        counts[name, default: 0] += 1
        reached.append(name)
        condition.broadcast()
        condition.unlock()
    }

    func fail(_ message: String) {
        condition.lock()
        failed.append(message)
        condition.broadcast()
        condition.unlock()
    }

    func count(_ name: String) -> Int {
        condition.lock()
        defer { condition.unlock() }
        return counts[name, default: 0]
    }

    var order: [String] {
        condition.lock()
        defer { condition.unlock() }
        return reached
    }

    var failures: [String] {
        condition.lock()
        defer { condition.unlock() }
        return failed
    }

    /// False on the first failure or at the deadline. Never asserts.
    func waitFor(_ names: [String], timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        condition.lock()
        defer { condition.unlock() }
        while failed.isEmpty && !names.allSatisfy({ counts[$0, default: 0] > 0 }) {
            if !condition.wait(until: deadline) { break }
        }
        return failed.isEmpty && names.allSatisfy { counts[$0, default: 0] > 0 }
    }

    /// Test-thread variant of `waitFor` that reports why it returned false.
    func expect(
        _ names: String..., timeout: TimeInterval,
        file: StaticString = #filePath, line: UInt = #line
    ) -> Bool {
        if waitFor(names, timeout: timeout) { return true }
        let failures = self.failures
        if failures.isEmpty {
            let missing = names.filter { count($0) == 0 }
            XCTFail("timed out waiting for \(missing); reached \(order)", file: file, line: line)
        } else {
            XCTFail(
                "\(failures.joined(separator: "\n")); reached \(order)", file: file, line: line)
        }
        return false
    }
}

final class ForwarderRef: @unchecked Sendable {
    weak var value: TcpDirectForwarder?
}

/// Promoted forwarder and both production writers over a `NativeTcpConnection`.
/// Every abnormal callback is recorded as a failure so the test stops early.
private final class NativeForwarderHarness {
    let queue = DispatchQueue(label: "rama.test.native-upload", autoreleaseFrequency: .workItem)
    let connection: NativeTcpConnection
    let budget = WriterMemoryBudget()
    let client: TcpClientWritePump
    let egress: NwTcpConnectionWritePump
    let forwarder: TcpDirectForwarder
    let terminals = Locked(0)
    /// Calls to the forwarder's pause scheduler, made only after a writer returned `.paused`.
    let pauseChecks = Locked(0)

    init(
        port: UInt16, flow: any TcpFlowReadable & TcpFlowWritable, milestones: Milestones,
        cap: Int, closeClientWrite: @escaping (Error?) -> Void = { _ in }
    ) throws {
        guard
            let connection = NativeTcpConnection(
                host: "127.0.0.1", port: port, parameters: makeTcpNwParameters(nil).native)
        else { throw PeerError("NativeTcpConnection could not be constructed") }
        self.connection = connection
        let queue = queue
        let terminals = terminals
        let pauseChecks = pauseChecks
        let forwarderRef = ForwarderRef()
        let policy = TcpWritePumpPolicy(maxPendingBytes: cap)
        client = TcpClientWritePump(
            flow: flow, queue: queue, logger: { _ in },
            onTerminalError: { milestones.fail("client writer: \($0)") },
            onDrained: { forwarderRef.value?.onClientPumpDrained() },
            writerMemoryBudget: budget, writePolicy: policy)
        egress = NwTcpConnectionWritePump(
            connection: connection, queue: queue,
            onDrained: { forwarderRef.value?.onEgressPumpDrained() },
            onTerminal: { milestones.fail("egress writer: \($0)") },
            onFinComplete: { error in
                if let error {
                    milestones.fail("egress FIN: \(error)")
                } else {
                    milestones.reach("egress FIN sent")
                }
            },
            writerMemoryBudget: budget, writePolicy: policy)
        forwarder = TcpDirectForwarder(
            flow: flow, connection: connection, clientWritePump: client,
            egressWritePump: egress, writerMemoryBudget: budget, queue: queue,
            logger: { _ in }, drainStallDeadline: .seconds(30),
            onDrainStall: { milestones.fail("drain stalled") },
            onReadError: { milestones.fail("read: \($0)") },
            writeChunkLimit: cap,
            closeClientWrite: { error in
                closeClientWrite(error)
                if let error {
                    milestones.fail("client write closed with \(error)")
                } else {
                    milestones.reach("client write closed")
                }
            },
            pauseScheduler: { delayMs, work in
                pauseChecks.withLock { $0 += 1 }
                queue.asyncAfter(deadline: .now() + .milliseconds(delayMs), execute: work)
            },
            onTerminal: {
                terminals.withLock { $0 += 1 }
                milestones.reach("terminal")
            })
        forwarderRef.value = forwarder
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: milestones.reach("ready")
            case .waiting(let error): milestones.fail("egress waiting: \(error)")
            case .failed(.posix(.ENETDOWN))
            where milestones.count("egress FIN sent") > 0
                && milestones.count("peer write closed") > 0:
                // Network.framework reports this once both FINs are exchanged.
                milestones.reach("closed both ways")
            case .failed(let error): milestones.fail("egress failed: \(error)")
            default: break
            }
        }
        connection.start(queue: queue)
    }

    func startForwarding() {
        forwarder.markRustC2SDone()
        forwarder.markRustS2CDone()
        forwarder.markClientReadDrained()
        forwarder.markEgressReadDrained()
    }

    /// Bounded: the queue barrier runs after every already-queued callback, and
    /// the forwarder ignores later ones once cancelled.
    func cleanup(file: StaticString = #filePath, line: UInt = #line) {
        let terminalsBefore = terminals.withLock { $0 }
        forwarder.cancel()
        client.cancel()
        egress.cancel()
        connection.cancelAndDetach()
        queue.sync {}
        XCTAssertEqual(
            terminals.withLock { $0 }, max(terminalsBefore, 1),
            "terminal must fire exactly once", file: file, line: line)
        let deadline = Date().addingTimeInterval(5)
        while budget.snapshot().retainedBytes != 0 && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertEqual(budget.snapshot().retainedBytes, 0, file: file, line: line)
    }
}

/// Position-keyed stream: any dropped, duplicated or reordered byte changes
/// the digest.
enum UploadPattern {
    static func fill(_ bytes: UnsafeMutablePointer<UInt8>, offset: Int, count: Int) {
        var index = 0
        while index < count {
            let position = offset + index
            // SplitMix64 of the absolute 8-byte word index.
            var x = UInt64(position >> 3) &+ 0x9e37_79b9_7f4a_7c15
            x = (x ^ (x >> 30)) &* 0xbf58_476d_1ce4_e5b9
            x = (x ^ (x >> 27)) &* 0x94d0_49bb_1331_11eb
            x ^= x >> 31
            var lane = position & 7
            while lane < 8 && index < count {
                bytes[index] = UInt8(truncatingIfNeeded: x >> UInt64(lane * 8))
                lane += 1
                index += 1
            }
        }
    }

    static func data(offset: Int, count: Int) -> Data {
        var data = Data(count: count)
        data.withUnsafeMutableBytes {
            fill($0.bindMemory(to: UInt8.self).baseAddress!, offset: offset, count: count)
        }
        return data
    }

    /// A nonzero-index slice of a no-copy root that is fully initialized before
    /// `Data` sees it and poisoned when its last owner releases it.
    static func payload(offset: Int, count: Int) -> Data {
        let prefix = 37
        let suffix = 11
        let size = prefix + count + suffix
        let allocation = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 16)
        let bytes = allocation.initializeMemory(as: UInt8.self, repeating: 0xA5, count: size)
        fill(bytes + prefix, offset: offset, count: count)
        let root = Data(
            bytesNoCopy: allocation, count: size,
            deallocator: .custom { pointer, size in
                pointer.initializeMemory(as: UInt8.self, repeating: 0xEE, count: size)
                pointer.deallocate()
            })
        return root[prefix..<(prefix + count)]
    }

    static func digest(offset: Int, count: Int) -> Data {
        let window = 1 << 20
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: window)
        defer { buffer.deallocate() }
        var digest = SHA256()
        var done = 0
        while done < count {
            let step = min(window, count - done)
            fill(buffer, offset: offset + done, count: step)
            digest.update(bufferPointer: UnsafeRawBufferPointer(start: buffer, count: step))
            done += step
        }
        return Data(digest.finalize())
    }
}

/// NE-like reader: asynchronous callbacks with varied, unaligned chunk sizes.
private final class UploadPatternFlow: TcpFlowReadable, TcpFlowWritable, @unchecked Sendable {
    let response = Locked(Data())
    let reads = Locked(0)
    private let source = DispatchQueue(
        label: "rama.test.upload-source", autoreleaseFrequency: .workItem)
    private let total: Int
    private var offset: Int
    private var chunkIndex = 0
    private let sizes = [1, 7, 14, 15, 17, 4095, 16385, 65535, 65536, 65537, 131_073, 393_233]

    init(total: Int, start: Int) {
        self.total = total
        offset = start
    }

    func readData(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        source.async {
            self.reads.withLock { $0 += 1 }
            guard self.offset < self.total else {
                completionHandler(nil, nil)
                return
            }
            let count = min(
                self.sizes[self.chunkIndex % self.sizes.count], self.total - self.offset)
            let payload = UploadPattern.payload(offset: self.offset, count: count)
            self.offset += count
            self.chunkIndex += 1
            completionHandler(payload, nil)
        }
    }

    func write(
        _ data: Data, withCompletionHandler completion: @escaping @Sendable (Error?) -> Void
    ) {
        response.withLock { $0.append(data) }
        completion(nil)
    }
}

struct PeerError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
    static func posix(_ operation: String, _ code: Int32 = errno) -> PeerError {
        PeerError("\(operation): \(String(cString: strerror(code)))")
    }
}

/// Loopback-only peer whose own listener picks the ephemeral port. Its script
/// runs on a dedicated thread with blocking I/O in short timeout slices, so
/// `stop` always ends it within a bounded time.
final class ScriptedPeer: @unchecked Sendable {
    let port: UInt16
    private let listener: Int32
    private let socket = Locked<Int32>(-1)
    private let stopping = Locked(false)
    private let exited = DispatchSemaphore(value: 0)
    private let operationTimeout: TimeInterval = 30
    private let milestones: Milestones

    init(milestones: Milestones, script: @escaping @Sendable (ScriptedPeer) throws -> Void) throws {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw PeerError.posix("socket") }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                Darwin.bind(fd, raw, length) == 0 && Darwin.listen(fd, 1) == 0
                    && Darwin.getsockname(fd, raw, &length) == 0
            }
        }
        guard bound else {
            let error = PeerError.posix("listen")
            Darwin.close(fd)
            throw error
        }
        listener = fd
        port = UInt16(bigEndian: address.sin_port)
        self.milestones = milestones
        let thread = Thread { [self] in
            defer { exited.signal() }
            do {
                try accept()
                try script(self)
            } catch {
                if !stopping.withLock({ $0 }) { milestones.fail("peer: \(error)") }
            }
        }
        thread.start()
    }

    private func accept() throws {
        var poller = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        let deadline = Date().addingTimeInterval(10)
        while Darwin.poll(&poller, 1, 100) <= 0 {
            if stopping.withLock({ $0 }) { throw PeerError("stopped before accept") }
            if Date() > deadline { throw PeerError("no connection within 10 s") }
        }
        let fd = Darwin.accept(listener, nil, nil)
        guard fd >= 0 else { throw PeerError.posix("accept") }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var slice = timeval(tv_sec: 0, tv_usec: 100_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &slice, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &slice, socklen_t(MemoryLayout<timeval>.size))
        socket.withLock { $0 = fd }
    }

    private var fd: Int32 { socket.withLock { $0 } }

    /// Retries a timed-out slice until the operation deadline or `stop`.
    private func retry(_ operation: String, deadline: Date) throws {
        let code = errno
        guard code == EAGAIN || code == EINTR else { throw PeerError.posix(operation, code) }
        if stopping.withLock({ $0 }) { throw PeerError("\(operation): stopped") }
        if Date() > deadline { throw PeerError("\(operation): timed out") }
    }

    func readExactly(_ count: Int, into digest: inout SHA256) throws {
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: 65536, alignment: 1)
        defer { buffer.deallocate() }
        let deadline = Date().addingTimeInterval(operationTimeout)
        var remaining = count
        while remaining > 0 {
            let n = Darwin.recv(fd, buffer.baseAddress, min(buffer.count, remaining), 0)
            if n > 0 {
                digest.update(bufferPointer: UnsafeRawBufferPointer(rebasing: buffer[0..<n]))
                remaining -= n
            } else if n == 0 {
                throw PeerError("EOF with \(remaining) of \(count) bytes missing")
            } else {
                try retry("recv", deadline: deadline)
            }
        }
    }

    /// Returns the byte count read before the client's FIN.
    func readToEnd(
        into digest: inout SHA256, chunk: Int = 65536, pacingMicros: useconds_t = 0
    ) throws -> Int {
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: chunk, alignment: 1)
        defer { buffer.deallocate() }
        let deadline = Date().addingTimeInterval(operationTimeout * 3)
        var count = 0
        while true {
            let n = Darwin.recv(fd, buffer.baseAddress, chunk, 0)
            if n > 0 {
                digest.update(bufferPointer: UnsafeRawBufferPointer(rebasing: buffer[0..<n]))
                count += n
                if pacingMicros > 0 { usleep(pacingMicros) }
            } else if n == 0 {
                return count
            } else {
                try retry("recv", deadline: deadline)
            }
        }
    }

    func send(_ data: Data) throws {
        let deadline = Date().addingTimeInterval(operationTimeout)
        try data.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = Darwin.send(fd, raw.baseAddress! + sent, raw.count - sent, 0)
                if n >= 0 {
                    sent += n
                } else {
                    try retry("send", deadline: deadline)
                }
            }
        }
    }

    func shutdownWrite() throws {
        milestones.reach("peer write closed")
        guard Darwin.shutdown(fd, SHUT_WR) == 0 else { throw PeerError.posix("shutdown") }
    }

    /// Abortive close. Loopback does not reset while sent bytes are still queued,
    /// so wait until the kernel has handed them over.
    func reset() throws {
        let deadline = Date().addingTimeInterval(5)
        var queued: Int32 = 1
        var length = socklen_t(MemoryLayout<Int32>.size)
        while Darwin.getsockopt(fd, SOL_SOCKET, SO_NWRITE, &queued, &length) == 0, queued > 0 {
            if Date() > deadline { throw PeerError("\(queued) bytes still queued before reset") }
            usleep(1_000)
        }
        var linger = Darwin.linger(l_onoff: 1, l_linger: 0)
        let fd = self.fd
        guard
            setsockopt(
                fd, SOL_SOCKET, SO_LINGER, &linger, socklen_t(MemoryLayout<Darwin.linger>.size))
                == 0
        else { throw PeerError.posix("SO_LINGER") }
        socket.withLock { socket in
            Darwin.close(socket)
            socket = -1
        }
    }

    func stop(file: StaticString = #filePath, line: UInt = #line) {
        stopping.withLock { $0 = true }
        socket.withLock { if $0 >= 0 { Darwin.shutdown($0, SHUT_RDWR) } }
        let ended = exited.wait(timeout: .now() + 5) == .success
        XCTAssertTrue(ended, "peer thread did not stop", file: file, line: line)
        socket.withLock { socket in
            if socket >= 0 { Darwin.close(socket) }
            socket = -1
        }
        Darwin.close(listener)
    }
}
