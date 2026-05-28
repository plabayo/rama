import Foundation
import Network
import NetworkExtension

final class TcpClientWritePump: @unchecked Sendable {
    private let core: TcpWritePumpCore
    private let logger: (FlowLogMessage) -> Void
    private let onTerminalError: (Error) -> Void

    // Queue-only state.
    private var wasEverOpened = false
    private var onDrainedClose: ((Bool) -> Void)?

    init(
        flow: TcpFlowWritable,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        onTerminalError: @escaping (Error) -> Void,
        onDrained: @escaping () -> Void
    ) {
        self.logger = logger
        self.onTerminalError = onTerminalError
        let core = TcpWritePumpCore(
            queue: queue,
            initialLifecycle: .pending,
            onDrained: onDrained,
            doWrite: { data, completion in flow.write(data, withCompletionHandler: completion) },
            logHwm: { hwm in
                logger(FlowLogMessage(
                    level: .trace,
                    text: "tcp client write pump pendingBytes hwm=\(hwm) cap=\(writePumpMaxPendingBytes)"
                ))
            }
        )
        self.core = core
        core.delegate = self
    }


    func markOpened() {
        core.queue.async { [weak self] in
            guard let self else { return }
            if self.core.isClosed() { return }
            self.wasEverOpened = true
            self.core.markOpen()
        }
    }

    func failOpen(_ error: Error) {
        core.queue.async { [weak self] in
            guard let self else { return }
            self.core.terminateLocked(with: error)
        }
    }

    /// Enqueue a chunk for delivery via the underlying flow's write.
    ///
    /// Returns synchronously with:
    ///   - `.accepted` — chunk queued; Rust may keep producing.
    ///   - `.paused` — byte budget reached; wait for `signalServerDrain`.
    ///   - `.closed` — pump is tearing down; no further drain will fire.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge {
        core.enqueue(data)
    }

    func closeWhenDrained(_ onDrainedClose: @escaping (_ wasOpened: Bool) -> Void) {
        core.queue.async { [weak self] in
            guard let self else { return }
            if self.core.isClosed() {
                onDrainedClose(self.wasEverOpened)
                return
            }
            self.onDrainedClose = onDrainedClose
            self.core.beginDraining()
        }
    }

    /// External-cancel entry point. Sets the closed flag synchronously so
    /// any pending retry's flush short-circuits immediately, then schedules
    /// queue-side cleanup.  If a `closeWhenDrained` completion was
    /// registered it fires with `wasOpened = false` so the dispatcher's
    /// teardown chain always resolves.
    func cancel() {
        let coreCleanup = core.prepareCancel()
        core.queue.async { [weak self] in
            guard let self else { return }
            coreCleanup()
            let completion = self.onDrainedClose
            let wasOpened = self.wasEverOpened
            self.onDrainedClose = nil
            completion?(wasOpened)
        }
    }

    #if DEBUG
        /// Test-only. Schedules a block on the core queue to snapshot
        /// the post-cancel invariants
        ///   `closed ⇒ pending empty ∧ retrying nil ∧ pendingBytes 0`.
        /// The callback fires on the core queue and is therefore
        /// strictly ordered after any blocks scheduled before this
        /// call — including cancel's cleanup and any write completion
        /// the test enqueued via `MockTcpFlow.completeNextWrite()`.
        func testCoreInvariantSnapshot(
            _ completion: @escaping (_ pendingEmpty: Bool, _ retryingNil: Bool, _ pendingBytes: Int) -> Void
        ) {
            core.queue.async { [weak self] in
                guard let self else {
                    completion(true, true, 0)
                    return
                }
                let snap = self.core.testInvariantSnapshot()
                completion(snap.pendingEmpty, snap.retryingNil, snap.pendingBytes)
            }
        }
    #endif
}

extension TcpClientWritePump: TcpWritePumpCoreDelegate {
    internal func pumpCore(_ core: TcpWritePumpCore, didTerminateWith error: Error) {
        logger(classifyFlowCallbackError(error, operation: "tcp flow.write", isClosing: true))
        onTerminalError(error)
        let completion = onDrainedClose
        onDrainedClose = nil
        completion?(wasEverOpened)
    }

    internal func pumpCoreDidFinishDraining(_ core: TcpWritePumpCore) {
        let completion = onDrainedClose
        onDrainedClose = nil
        completion?(wasEverOpened)
    }
}

/// Queue-confined phase for `UdpClientWritePump`.  Replaces the former
/// `writing: Bool`, `closed: Bool`, and `opened: Bool` triple.
