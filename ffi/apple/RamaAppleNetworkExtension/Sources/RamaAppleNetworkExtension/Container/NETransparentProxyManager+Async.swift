import Foundation
import NetworkExtension

/// Errors thrown by the async helpers on `NETransparentProxyManager`.
public enum RamaNetworkExtensionError: Error, CustomStringConvertible {
    /// The connection reached `.invalid` while we were waiting for it
    /// to come up. The caller usually needs to recreate the manager.
    case invalidConnection
    /// `waitUntilConnected` exceeded its timeout without seeing
    /// `.connected`.
    case connectTimedOut
    /// `waitUntilDisconnected` exceeded its timeout without seeing
    /// `.disconnected` / `.invalid`.
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
    /// `true` while the connection is `.connected`, `.connecting`, or
    /// `.reasserting`. Useful as a quick "should we auto-start?" probe.
    public var isActive: Bool {
        switch connection.status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    /// Poll the connection until it reaches `.connected` or the timeout
    /// elapses.
    ///
    /// Throws ``RamaNetworkExtensionError/invalidConnection`` if the
    /// connection enters `.invalid`, or
    /// ``RamaNetworkExtensionError/connectTimedOut`` on timeout.
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

    /// Poll the connection until it reaches `.disconnected` /
    /// `.invalid`, or the timeout elapses.
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

    /// Convenience: call `startVPNTunnel()` and `await` the connection
    /// reaching `.connected`. Throws if the start fails or the tunnel
    /// doesn't come up in time.
    public func startAndWaitUntilConnected(
        timeout: TimeInterval = 20,
        pollInterval: TimeInterval = 0.25
    ) async throws {
        try connection.startVPNTunnel()
        try await waitUntilConnected(timeout: timeout, pollInterval: pollInterval)
    }
}
