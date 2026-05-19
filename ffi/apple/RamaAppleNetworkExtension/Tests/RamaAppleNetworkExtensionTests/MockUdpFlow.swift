import Foundation

import NetworkExtension

@testable import RamaAppleNetworkExtension

/// Test double for `UdpFlowLike`. Mirror of `MockTcpFlow` for the
/// datagram path: captures read / write / open / close calls and
/// lets the test fire any pending completion at any time.
final class MockUdpFlow: UdpFlowLike, @unchecked Sendable {
    typealias ReadCompletion = @Sendable ([Data]?, [NWEndpoint]?, Error?) -> Void
    typealias WriteCompletion = @Sendable (Error?) -> Void
    typealias OpenCompletion = @Sendable (Error?) -> Void

    struct WrittenBatch {
        let datagrams: [Data]
        let sentBy: [NWEndpoint]
        let completion: WriteCompletion
    }

    private let lock = NSLock()
    private var _pendingReads: [ReadCompletion] = []
    private var _writtenBatches: [WrittenBatch] = []
    private var _pendingOpenCompletion: OpenCompletion?
    private var _openLocalEndpoint: NWHostEndpoint??
    private var _closeReadErrors: [Error?] = []
    private var _closeWriteErrors: [Error?] = []
    private var _applyMetadataCount: Int = 0

    // MARK: - UdpFlowLike

    func readDatagrams(
        completionHandler: @escaping @Sendable ([Data]?, [NWEndpoint]?, Error?) -> Void
    ) {
        lock.lock()
        _pendingReads.append(completionHandler)
        lock.unlock()
    }

    func writeDatagrams(
        _ datagrams: [Data],
        sentBy remoteEndpoints: [NWEndpoint],
        completionHandler: @escaping @Sendable (Error?) -> Void
    ) {
        lock.lock()
        _writtenBatches.append(
            WrittenBatch(datagrams: datagrams, sentBy: remoteEndpoints, completion: completionHandler)
        )
        lock.unlock()
    }

    func open(
        withLocalEndpoint localEndpoint: NWHostEndpoint?,
        completionHandler: @escaping @Sendable (Error?) -> Void
    ) {
        lock.lock()
        _pendingOpenCompletion = completionHandler
        _openLocalEndpoint = .some(localEndpoint)
        lock.unlock()
    }

    func closeReadWithError(_ error: Error?) {
        lock.lock()
        _closeReadErrors.append(error)
        lock.unlock()
    }

    func closeWriteWithError(_ error: Error?) {
        lock.lock()
        _closeWriteErrors.append(error)
        lock.unlock()
    }

    func applyMetadata(to params: NWParameters) {
        lock.lock()
        _applyMetadataCount += 1
        lock.unlock()
    }

    // MARK: - Driving

    @discardableResult
    func completeOpen(error: Error? = nil) -> Bool {
        lock.lock()
        guard let cb = _pendingOpenCompletion else {
            lock.unlock()
            return false
        }
        _pendingOpenCompletion = nil
        lock.unlock()
        cb(error)
        return true
    }

    @discardableResult
    func completePendingRead(
        datagrams: [Data]? = nil,
        endpoints: [NWEndpoint]? = nil,
        error: Error? = nil
    ) -> Bool {
        lock.lock()
        guard !_pendingReads.isEmpty else {
            lock.unlock()
            return false
        }
        let cb = _pendingReads.removeFirst()
        lock.unlock()
        cb(datagrams, endpoints, error)
        return true
    }

    @discardableResult
    func completePendingWrite(error: Error? = nil) -> Bool {
        lock.lock()
        guard !_writtenBatches.isEmpty else {
            lock.unlock()
            return false
        }
        let batch = _writtenBatches.removeFirst()
        lock.unlock()
        batch.completion(error)
        return true
    }

    // MARK: - Inspection

    var pendingReadCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _pendingReads.count
    }

    var writtenBatches: [WrittenBatch] {
        lock.lock(); defer { lock.unlock() }
        return _writtenBatches
    }

    var openWasInvoked: Bool {
        lock.lock(); defer { lock.unlock() }
        return _pendingOpenCompletion != nil || _openLocalEndpoint != nil
    }

    var closeReadCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _closeReadErrors.count
    }

    var closeWriteCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _closeWriteErrors.count
    }

    var applyMetadataCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _applyMetadataCount
    }
}
