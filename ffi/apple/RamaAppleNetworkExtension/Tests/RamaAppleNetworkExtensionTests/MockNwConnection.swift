import Foundation
import Network

@testable import RamaAppleNetworkExtension

/// Test double for `NwConnectionLike`. Used by every test that drives the
/// per-flow state machine without bringing up a real socket. Three groups
/// of capabilities:
///
/// 1. Inspection — `sentChunks`, `cancelCount`, `startInvocations`,
///    `pendingReceives` let assertions check what the system-under-test
///    did to the connection.
/// 2. Driving — `transition(to:)`, `completePendingReceive(...)` let the
///    test simulate Network.framework state changes and inbound bytes /
///    EOF / errors.
/// 3. Send completion — the most recent `send` completion can be invoked
///    via `completePendingSend(...)` so write-path tests can simulate
///    backpressure or NWConnection-level send failures.
///
/// All inspection and driving methods are safe to call from any thread.
final class MockNwConnection: NwConnectionLike, @unchecked Sendable {
    typealias SendCompletion = (NWError?) -> Void
    typealias ReceiveCompletion =
        @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void

    struct SentChunk {
        let content: Data?
        let isComplete: Bool
        let contentContext: NWConnection.ContentContext
    }

    private let lock = NSLock()
    private var _state: NWConnection.State = .preparing
    private var _stateUpdateHandler: ((NWConnection.State) -> Void)?
    private var _sentChunks: [SentChunk] = []
    private var _pendingSendCompletions: [SendCompletion] = []
    private var _pendingReceiveCompletions: [ReceiveCompletion] = []
    private var _cancelCount: Int = 0
    private var _startInvocations: [DispatchQueue] = []

    // MARK: - NwConnectionLike

    var state: NWConnection.State {
        lock.lock()
        defer { lock.unlock() }
        return _state
    }

    var stateUpdateHandler: ((NWConnection.State) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _stateUpdateHandler
        }
        set {
            lock.lock()
            _stateUpdateHandler = newValue
            lock.unlock()
        }
    }

    func start(queue: DispatchQueue) {
        lock.lock()
        _startInvocations.append(queue)
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        _cancelCount += 1
        lock.unlock()
    }

    func send(
        content: Data?,
        contentContext: NWConnection.ContentContext,
        isComplete: Bool,
        completion: NWConnection.SendCompletion
    ) {
        lock.lock()
        _sentChunks.append(
            SentChunk(content: content, isComplete: isComplete, contentContext: contentContext)
        )
        // Capture the inner callback so a test can simulate either an
        // immediate success or an NWConnection-level send error. The
        // SendCompletion enum carries the callback only for
        // `.contentProcessed(_)`; idempotent sends record nothing.
        switch completion {
        case .contentProcessed(let cb):
            _pendingSendCompletions.append(cb)
        default:
            break
        }
        lock.unlock()
    }

    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping ReceiveCompletion
    ) {
        lock.lock()
        _pendingReceiveCompletions.append(completion)
        lock.unlock()
    }

    // MARK: - Test driving

    /// Force the connection to the given state and fire the
    /// `stateUpdateHandler` synchronously on the caller's thread.
    /// Production code always sees state changes via the handler, so
    /// tests should call this rather than mutating `_state` directly.
    ///
    /// On `.cancelled` the handler is fired and then released —
    /// mirrors `NWConnection`'s real behavior of dropping the handler
    /// once the connection has reached its terminal state, which is
    /// what lets the connection (and everything its handler
    /// captured) deallocate. Without this a test that asserts ARC
    /// cleanup races against the mock pinning the handler graph.
    func transition(to newState: NWConnection.State) {
        lock.lock()
        _state = newState
        let handler = _stateUpdateHandler
        lock.unlock()
        handler?(newState)
        if case .cancelled = newState {
            lock.lock()
            _stateUpdateHandler = nil
            _pendingSendCompletions.removeAll()
            _pendingReceiveCompletions.removeAll()
            lock.unlock()
        }
    }

    /// Convenience: cancel the connection and clear the handler so
    /// the captured graph can deallocate. Used by tests that drive
    /// the lifecycle externally without going through the state
    /// machine's natural `.cancelled` transition.
    func simulateCancelled() {
        transition(to: .cancelled)
    }

    /// Pop and invoke the oldest pending send completion. Returns
    /// `false` when no send is outstanding (i.e. the system-under-test
    /// never issued a `send`).
    @discardableResult
    func completePendingSend(error: NWError? = nil) -> Bool {
        lock.lock()
        guard !_pendingSendCompletions.isEmpty else {
            lock.unlock()
            return false
        }
        let cb = _pendingSendCompletions.removeFirst()
        lock.unlock()
        cb(error)
        return true
    }

    /// Pop and invoke the oldest pending receive completion. Returns
    /// `false` when no receive is outstanding.
    @discardableResult
    func completePendingReceive(
        data: Data? = nil,
        isComplete: Bool = false,
        error: NWError? = nil
    ) -> Bool {
        lock.lock()
        guard !_pendingReceiveCompletions.isEmpty else {
            lock.unlock()
            return false
        }
        let cb = _pendingReceiveCompletions.removeFirst()
        lock.unlock()
        cb(data, nil, isComplete, error)
        return true
    }

    // MARK: - Inspection

    var sentChunks: [SentChunk] {
        lock.lock()
        defer { lock.unlock() }
        return _sentChunks
    }

    var cancelCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _cancelCount
    }

    var startInvocations: [DispatchQueue] {
        lock.lock()
        defer { lock.unlock() }
        return _startInvocations
    }

    var pendingReceiveCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _pendingReceiveCompletions.count
    }

    var pendingSendCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _pendingSendCompletions.count
    }
}
