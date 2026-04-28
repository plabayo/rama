import Foundation
import NetworkExtension

/// Errors thrown by the async helpers on `NETransparentProxyManager`.
public enum RamaNetworkExtensionError: Error, CustomStringConvertible {
    /// Connection reached `.invalid` while waiting; caller usually has
    /// to recreate the manager.
    case invalidConnection
    case connectTimedOut
    case disconnectTimedOut

    public var description: String {
        switch self {
        case .invalidConnection:
            return "RamaNetworkExtensionError: connection is invalid"
        case .connectTimedOut:
            return "RamaNetworkExtensionError: provider failed to reach connected state in time"
        case .disconnectTimedOut:
            return "RamaNetworkExtensionError: provider failed to reach disconnected state in time"
        }
    }
}

extension NETransparentProxyManager {
    /// `true` while `.connected` / `.connecting` / `.reasserting`.
    public var isActive: Bool {
        switch connection.status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    /// Poll until `.connected`. Throws on `.invalid` or timeout.
    public func waitUntilConnected(
        timeout: TimeInterval = 20,
        pollInterval: TimeInterval = 0.25
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            switch connection.status {
            case .connected:
                return
            case .invalid:
                throw RamaNetworkExtensionError.invalidConnection
            default:
                break
            }
            if Date() >= deadline {
                throw RamaNetworkExtensionError.connectTimedOut
            }
            try await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
        }
    }

    /// Poll until `.disconnected` / `.invalid`. Throws on timeout.
    public func waitUntilDisconnected(
        timeout: TimeInterval = 10,
        pollInterval: TimeInterval = 0.25
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            switch connection.status {
            case .disconnected, .invalid:
                return
            default:
                break
            }
            if Date() >= deadline {
                throw RamaNetworkExtensionError.disconnectTimedOut
            }
            try await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
        }
    }

    /// `startVPNTunnel()` + `waitUntilConnected`.
    public func startAndWaitUntilConnected(
        timeout: TimeInterval = 20,
        pollInterval: TimeInterval = 0.25
    ) async throws {
        try connection.startVPNTunnel()
        try await waitUntilConnected(timeout: timeout, pollInterval: pollInterval)
    }
}
