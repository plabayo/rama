import CryptoKit
import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// How long does an egress send read the caller's memory? A loopback peer
/// stops reading until the stack holds sends it cannot complete. Then every
/// root still waiting for its completion is overwritten, and every root is
/// overwritten again inside its completion. The peer reports, per chunk,
/// which version reached the wire.
final class NativeSendExposureTests: XCTestCase {
    private static let chunk = 64 * 1024
    private static let chunks = 256
    /// Peer digest granularity, so a chunk the stack read in parts shows where it changed.
    private static let block = 1024

    func testNativeConnectionReadsCallerMemoryPastItsCompletion() throws {
        let seen = try exposure(native: true)
        // The native send reads the caller's memory until the stack has written the
        // bytes to the socket, and that can finish after the send completion fired.
        XCTAssertGreaterThan(seen.afterReturn, 0, "\(seen)")
        XCTAssertGreaterThan(seen.chunksWithCompletionBytes, 0, "\(seen)")
    }

    func testSwiftConnectionCopiesBeforeSendReturns() throws {
        let seen = try exposure(native: false)
        // NWConnection copies the content while `send` runs.
        XCTAssertEqual(seen.original, Self.chunks, "\(seen)")
    }

    /// Per-chunk counts by the version the peer received, plus each mixed chunk's
    /// blocks in wire order: `o` original, `r` written after return, `c` in completion.
    private struct Exposure: CustomStringConvertible {
        var completedBeforeResume = 0
        var original = 0
        var afterReturn = 0
        var afterCompletion = 0
        var mixed: [(chunk: Int, blocks: String)] = []
        var chunksWithCompletionBytes = 0
        var description: String {
            let detail = mixed.map { "\($0.chunk):\(Self.runs($0.blocks))" }
            return "completed_before_resume=\(completedBeforeResume) original=\(original) "
                + "after_return=\(afterReturn) after_completion=\(afterCompletion) "
                + "chunks_with_completion_bytes=\(chunksWithCompletionBytes) mixed=\(detail)"
        }

        private static func runs(_ blocks: String) -> String {
            var out = ""
            var previous: Character?
            var count = 0
            for block in blocks {
                if block == previous {
                    count += 1
                } else {
                    if let previous { out += "\(previous)x\(count) " }
                    previous = block
                    count = 1
                }
            }
            if let previous { out += "\(previous)x\(count)" }
            return out
        }
    }

    private func exposure(native: Bool) throws -> Exposure {
        let chunk = Self.chunk
        let chunks = Self.chunks
        let milestones = Milestones()
        let digests = Locked<[Data]>([])
        let peer = try ScriptedPeer(milestones: milestones) { peer in
            guard milestones.waitFor(["resume"], timeout: 30) else { return }
            for _ in 0..<(chunks * chunk / Self.block) {
                var digest = SHA256()
                try peer.readExactly(Self.block, into: &digest)
                let value = Data(digest.finalize())
                digests.withLock { $0.append(value) }
            }
            var rest = SHA256()
            guard try peer.readToEnd(into: &rest) == 0 else { throw PeerError("extra bytes") }
            milestones.reach("peer done")
        }
        defer { peer.stop() }

        let queue = DispatchQueue(label: "rama.test.send-exposure")
        let send: (Data?, Bool, @escaping @Sendable (Error?) -> Void) -> Void
        let cancel: () -> Void
        if native {
            let connection = try XCTUnwrap(
                NativeTcpConnection(
                    host: "127.0.0.1", port: peer.port,
                    parameters: makeTcpNwParameters(nil).native))
            connection.stateUpdateHandler = { if case .ready = $0 { milestones.reach("ready") } }
            connection.start(queue: queue)
            send = { data, final, done in
                connection.send(
                    content: data, contentContext: final ? .finalMessage : .defaultMessage,
                    isComplete: true, completion: .contentProcessed { done($0) })
            }
            cancel = { connection.cancelAndDetach() }
        } else {
            let connection = NWConnection(
                host: "127.0.0.1", port: NWEndpoint.Port(rawValue: peer.port)!, using: .tcp)
            connection.stateUpdateHandler = { if case .ready = $0 { milestones.reach("ready") } }
            connection.start(queue: queue)
            send = { data, final, done in
                connection.send(
                    content: data, contentContext: final ? .finalMessage : .defaultMessage,
                    isComplete: true, completion: .contentProcessed { done($0) })
            }
            cancel = {
                connection.stateUpdateHandler = nil
                connection.cancel()
            }
        }
        defer {
            cancel()
            queue.sync {}
        }
        guard milestones.expect("ready", timeout: 10) else { return Exposure() }

        // Every root stays alive until the test ends, so each overwrite hits live memory.
        let budget = WriterMemoryBudget()
        var slices: [TcpPayloadSlice] = []
        var roots: [UInt] = []
        for index in 0..<chunks {
            let root = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
            UploadPattern.fill(root, offset: index * chunk, count: chunk)
            let data = Data(
                bytesNoCopy: root, count: chunk,
                deallocator: .custom { pointer, _ in pointer.deallocate() })
            XCTAssertTrue(budget.tryReserve(bytes: chunk))
            slices.append(budget.makePregrantedWriterPayload(data))
            roots.append(UInt(bitPattern: root))
        }
        let completed = Locked([Bool](repeating: false, count: chunks))
        let failures = Locked(0)
        queue.sync {
            for index in 0..<chunks {
                let root = roots[index]
                send(slices[index].data, false) { error in
                    UnsafeMutablePointer<UInt8>(bitPattern: root)!
                        .update(repeating: 0xC3, count: chunk)
                    completed.withLock { $0[index] = true }
                    if error != nil { failures.withLock { $0 += 1 } }
                }
            }
            send(nil, true) { _ in }
        }

        // The stack holds the rest once completions stop while sends are outstanding.
        var completedBeforeResume = 0
        var lastChange = Date()
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            let count = completed.withLock { $0.filter { $0 }.count }
            if count != completedBeforeResume {
                completedBeforeResume = count
                lastChange = Date()
            }
            if count == chunks || (count > 0 && Date().timeIntervalSince(lastChange) > 0.2) {
                break
            }
            Thread.sleep(forTimeInterval: 0.005)
        }
        completedBeforeResume = queue.sync {
            let done = completed.withLock { $0 }
            for index in 0..<chunks where !done[index] {
                UnsafeMutablePointer<UInt8>(bitPattern: roots[index])!
                    .update(repeating: 0x5A, count: chunk)
            }
            return done.filter { $0 }.count
        }
        milestones.reach("resume")
        guard milestones.expect("peer done", timeout: 30) else { return Exposure() }
        XCTAssertEqual(failures.withLock { $0 }, 0)
        withExtendedLifetime(slices) {}

        var result = Exposure(completedBeforeResume: completedBeforeResume)
        let afterReturn = Data(SHA256.hash(data: Data(repeating: 0x5A, count: Self.block)))
        let afterCompletion = Data(SHA256.hash(data: Data(repeating: 0xC3, count: Self.block)))
        let blocks = digests.withLock { $0 }
        let perChunk = chunk / Self.block
        for index in 0..<chunks {
            var kinds = ""
            for block in 0..<perChunk {
                let offset = index * chunk + block * Self.block
                let digest = blocks[index * perChunk + block]
                if digest == UploadPattern.digest(offset: offset, count: Self.block) {
                    kinds.append("o")
                } else if digest == afterReturn {
                    kinds.append("r")
                } else if digest == afterCompletion {
                    kinds.append("c")
                } else {
                    kinds.append("?")
                }
            }
            if kinds.contains("c") { result.chunksWithCompletionBytes += 1 }
            switch Set(kinds) {
            case ["o"]: result.original += 1
            case ["r"]: result.afterReturn += 1
            case ["c"]: result.afterCompletion += 1
            default: result.mixed.append((index, kinds))
            }
        }
        print("send exposure native=\(native) \(result)")
        return result
    }
}
