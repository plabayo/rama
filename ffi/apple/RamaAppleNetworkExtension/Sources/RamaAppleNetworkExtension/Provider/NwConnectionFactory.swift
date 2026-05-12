/// NwConnectionFactory.swift
///
/// This file intentionally imports only `Network` (not `NetworkExtension`) so that
/// the bare `NWEndpoint` name unambiguously refers to `Network.NWEndpoint` (the
/// Swift enum).  Files that also import `NetworkExtension` would see two candidates
/// for `NWEndpoint` — the deprecated ObjC class from NetworkExtension and the Swift
/// enum from Network — causing a compile-time ambiguity.
///
/// Keeping NWConnection creation here avoids that conflict.

import Foundation
import Network

/// Create an `NWConnection` to the given host/port using the supplied parameters.
///
/// Returns `nil` when the port is invalid (`NWEndpoint.Port(rawValue:)` rejects 0).
/// Callers must surface that as a connect failure rather than silently substituting
/// a default port — connecting to the wrong destination is worse than not connecting.
func makeNwConnection(host: String, port: UInt16, using params: NWParameters) -> NWConnection? {
    guard let port = NWEndpoint.Port(rawValue: port) else {
        return nil
    }
    return NWConnection(host: NWEndpoint.Host(host), port: port, using: params)
}
