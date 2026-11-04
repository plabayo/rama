/// SystemPathMonitor.swift
///
/// Imports only `Network` (not `NetworkExtension`) so `NWPathMonitor` / `NWPath`
/// resolve to the Network.framework types; see `NwConnectionFactory.swift`.

import Foundation
import Network

/// Reports whether the system currently has a usable network path, so the
/// core can tell "this flow's path died" apart from "the whole machine is
/// offline for a moment" (Wi-Fi re-associating after wake, 802.1X, DHCP).
///
/// One monitor per provider instance: an `NWPathMonitor` cannot be restarted
/// after `cancel()`, and the system path is independent of engine lifecycles.
final class SystemPathMonitor: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "rama.tproxy.system-path")
    private let started = Locked(false)

    /// Idempotent. `onUpdate` runs on the monitor's private queue, first with
    /// the current status and then on every change.
    func start(onUpdate: @escaping @Sendable (_ satisfied: Bool) -> Void) {
        let first = started.withLock { started -> Bool in
            defer { started = true }
            return !started
        }
        guard first else { return }
        monitor.pathUpdateHandler = { path in
            onUpdate(path.status == .satisfied)
        }
        monitor.start(queue: queue)
    }

    deinit {
        monitor.cancel()
    }
}
