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
/// The port falls back to `80` if `rawValue` produces `nil` (port 0 is invalid for
/// `NWEndpoint.Port`).
func makeNwConnection(host: String, port: UInt16, using params: NWParameters) -> NWConnection {
    NWConnection(
        host: NWEndpoint.Host(host),
        port: NWEndpoint.Port(rawValue: port) ?? 80,
        using: params
    )
}
