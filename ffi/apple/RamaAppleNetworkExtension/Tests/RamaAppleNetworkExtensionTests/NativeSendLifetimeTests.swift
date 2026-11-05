import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

final class NativeSendLifetimeTests: XCTestCase {
    func testNativeSendDoesNotPinCompletedRootsInCallerAutoreleasePool() throws {
        let sink = try RecordingSink()
        defer { sink.stop() }
        let queue = DispatchQueue(label: "rama.test.native-pool", autoreleaseFrequency: .workItem)
        let connection = try XCTUnwrap(NativeTcpConnection(
            host: "127.0.0.1", port: sink.port, parameters: makeTcpNwParameters(nil).native))
        let ready = DispatchSemaphore(value: 0)
        connection.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        connection.start(queue: queue)
        defer { connection.cancelAndDetach(); queue.sync {} }
        XCTAssertEqual(ready.wait(timeout: .now() + 10), .success)
        let budget = WriterMemoryBudget()
        let sendErrors = Locked<[String]>([])
        // Transfer more than the aggregate budget inside one caller pool.
        let count = 320
        let rootSize = 256 * 1024
        autoreleasepool {
            for _ in 0..<count {
                Self.sendRoot(connection, budget: budget, bytes: rootSize, errors: sendErrors)
            }
            connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                            completion: .contentProcessed { error in
                if let error { sendErrors.withLock { $0.append("\(error)") } }
            })
            XCTAssertTrue(sink.waitUntilDone(timeout: 10))
            XCTAssertEqual(sink.count, count * rootSize)
            connection.cancelAndDetach()
            queue.sync {}
            let deadline = Date().addingTimeInterval(2)
            while budget.snapshot().retainedBytes > 0 && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.005)
            }
            print("NATIVE_POOL before_drain=\(budget.snapshot().retainedBytes)")
            XCTAssertEqual(budget.snapshot().retainedBytes, 0,
                           "completed transport roots must not depend on the caller's pool draining")
        }
        print("NATIVE_POOL after_drain=\(budget.snapshot().retainedBytes)")
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        XCTAssertTrue(sendErrors.withLock { $0.isEmpty })
    }

    // Deliberately no inner pool: simulate a busy dispatch batch or a caller
    // doing many sends within one pool. Network.framework still owns each view
    // through its dispatch_data destructor after the send completion.
    private static func sendRoot(_ connection: NativeTcpConnection, budget: WriterMemoryBudget,
                                 bytes: Int, errors: Locked<[String]>) {
        guard var cursor = budget.makeTcpTransitCursor(Data(repeating: 0xA7, count: bytes)) else {
            return XCTFail("root admission failed")
        }
        while !cursor.isEmpty {
            let view = cursor.prefix(maxBytes: bytes / 2)
            let sent = DispatchSemaphore(value: 0)
            connection.send(content: view.data, contentContext: .defaultMessage, isComplete: true,
                            completion: .contentProcessed { error in
                if let error { errors.withLock { $0.append("\(error)") } }
                sent.signal()
            })
            XCTAssertEqual(sent.wait(timeout: .now() + 10), .success)
            cursor.advance(by: view.count)
        }
    }
}
