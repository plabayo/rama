import CryptoKit
import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Opt-in: bulk uploads over a loopback port shaped with packet loss and delay by
/// `scripts/lossy_link_tests.sh` (needs root). Every chunk root is poisoned when its
/// storage is released, so a retransmission read from released memory would change
/// the digest the peer computes.
final class LossyLinkTransferTests: XCTestCase {
    private enum RootWrite {
        /// Poisoned only when the last reference is released.
        case onRelease
        /// Also overwritten inside the send completion.
        case inCompletion
    }

    private struct Setup {
        let port: UInt16
        let bytes: Int
    }

    private func setup() throws -> Setup {
        let env = ProcessInfo.processInfo.environment
        guard env["RAMA_NE_LOSSY_LINK_TESTS"] == "1" else {
            throw XCTSkip("lossy-link harness only: just test-lossy-link")
        }
        let port = env["RAMA_NE_LOSSY_LINK_PORT"].flatMap(UInt16.init) ?? 47_391
        let bytes = env["RAMA_NE_LOSSY_LINK_BYTES"].flatMap(Int.init) ?? 64 * 1024 * 1024
        return Setup(port: port, bytes: bytes)
    }

    func testNativeConnectionDeliversIntactStreamOverLossyLink() throws {
        let run = try transfer(native: true, rootWrite: .onRelease)
        run.report("native")
        XCTAssertTrue(run.completed, "native stream did not complete")
        XCTAssertEqual(run.count, run.expectedCount)
        XCTAssertTrue(run.prefixIntact, "native stream changed on the wire")
    }

    func testSwiftConnectionDeliversIntactStreamOverLossyLink() throws {
        let run = try transfer(native: false, rootWrite: .onRelease)
        run.report("swift")
        XCTAssertTrue(run.completed, "NWConnection stream did not complete")
        XCTAssertEqual(run.count, run.expectedCount)
        XCTAssertTrue(run.prefixIntact, "NWConnection stream changed on the wire")
    }

    func testSwiftConnectionIgnoresRootWritesAfterCompletion() throws {
        let run = try transfer(native: false, rootWrite: .inCompletion)
        run.report("swift in-completion writes")
        XCTAssertTrue(run.completed)
        XCTAssertTrue(run.prefixIntact)
    }

    /// Characterisation, no pass/fail on the outcome: records whether the native
    /// path completes and what reaches the peer when root bytes are written after
    /// completion on a lossy link (the loopback exposure tests show it reads them).
    func testNativeConnectionRootWritesAfterCompletion() throws {
        let run = try transfer(native: true, rootWrite: .inCompletion)
        run.report("native in-completion writes")
    }

    private struct Run {
        let completed: Bool
        let count: Int
        let expectedCount: Int
        /// The bytes the peer received equal the first `count` bytes sent.
        let prefixIntact: Bool
        let seconds: Double

        func report(_ name: String) {
            print(
                "lossy link \(name): completed=\(completed) received=\(count)/\(expectedCount)"
                    + " prefix_intact=\(prefixIntact) seconds=\(String(format: "%.1f", seconds))")
        }
    }

    private func transfer(native: Bool, rootWrite: RootWrite) throws -> Run {
        let setup = try setup()
        let chunk = 64 * 1024
        let chunks = (setup.bytes + chunk - 1) / chunk
        let total = chunks * chunk
        let sink = try RecordingSink(port: setup.port)
        defer { sink.stop() }

        let queue = DispatchQueue(label: "rama.test.lossy-link")
        let milestones = Milestones()
        let send: (Data?, Bool, @escaping @Sendable (Error?) -> Void) -> Void
        let cancel: () -> Void
        if native {
            let connection = try XCTUnwrap(
                NativeTcpConnection(
                    host: "127.0.0.1", port: setup.port,
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
                host: "127.0.0.1", port: NWEndpoint.Port(rawValue: setup.port)!, using: .tcp)
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
        guard milestones.expect("ready", timeout: 30) else {
            return Run(
                completed: false, count: 0, expectedCount: total, prefixIntact: true, seconds: 0)
        }

        let budget = WriterMemoryBudget()
        let failures = Locked(0)
        let next = Locked(0)
        // At most this many sends are outstanding; each completion issues the next one.
        let window = 32
        @Sendable func issue() {
            let index = next.withLock { value -> Int? in
                guard value < chunks else { return nil }
                defer { value += 1 }
                return value
            }
            guard let index else {
                if next.withLock({ $0 }) == chunks {
                    next.withLock { $0 += 1 }
                    send(nil, true) { _ in milestones.reach("fin sent") }
                }
                return
            }
            let root = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
            UploadPattern.fill(root, offset: index * chunk, count: chunk)
            let data = Data(
                bytesNoCopy: root, count: chunk,
                deallocator: .custom { pointer, count in
                    pointer.assumingMemoryBound(to: UInt8.self)
                        .update(repeating: 0xEE, count: count)
                    pointer.deallocate()
                })
            guard budget.tryReserve(bytes: chunk) else {
                failures.withLock { $0 += 1 }
                return
            }
            let slice = budget.makePregrantedWriterPayload(data)
            let address = UInt(bitPattern: root)
            send(slice.data, false) { error in
                if error != nil { failures.withLock { $0 += 1 } }
                if rootWrite == .inCompletion {
                    UnsafeMutablePointer<UInt8>(bitPattern: address)!
                        .update(repeating: 0xC3, count: chunk)
                }
                withExtendedLifetime(slice) {}
                issue()
            }
        }
        let started = Date()
        queue.sync {
            for _ in 0..<window { issue() }
        }
        let timeout = 60 + Double(total) / 1_000_000
        let completed = sink.waitUntilDone(timeout: timeout)
        let seconds = Date().timeIntervalSince(started)
        // Stop the sender so the received count and digest no longer move.
        cancel()
        queue.sync {}
        let count = sink.count
        let prefixIntact = sink.sha256 == UploadPattern.digest(offset: 0, count: count)
        if completed {
            XCTAssertEqual(failures.withLock { $0 }, 0)
            XCTAssertNil(sink.error)
        }
        return Run(
            completed: completed, count: count, expectedCount: total, prefixIntact: prefixIntact,
            seconds: seconds)
    }
}
