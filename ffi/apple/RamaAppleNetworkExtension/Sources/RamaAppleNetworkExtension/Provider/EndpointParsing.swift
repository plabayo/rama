import Darwin
import Foundation

/// Best-effort prefix-length derivation from a network text. Returns
/// `32` for a literal IPv4 address, `128` for IPv6, `nil` otherwise
/// (hostname, malformed input). Lifted out of the provider as a free
/// function so it can be exercised directly by unit tests without
/// going through the full handler-config → engine path.
func inferredHostPrefix(_ text: String) -> Int? {
    var v4 = in_addr()
    if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
        return 32
    }
    var v6 = in6_addr()
    if text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
        return 128
    }
    return nil
}

/// Parse the variety of endpoint string shapes that
/// `NEAppProxyFlow.metaData` and friends hand us:
///
/// * `host:port` — IPv4 or hostname
/// * `[host]:port` — IPv6 with the canonical bracketed form
/// * `2a02:…:1.53` — IPv6 in the legacy NetworkExtension representation
///   where the port is appended with a dot rather than a colon
///
/// Returns `nil` for inputs that don't have an obvious port suffix.
/// Pure string surgery, no `Network`-framework types — kept here so
/// tests don't need to construct real endpoint objects.
func parseEndpointString(_ raw: String) -> (host: String, port: UInt16)? {
    // IPv6 endpoint descriptions may be formatted as:
    // - 2a02:...:1.53
    // - [2a02:...:1]:53
    // while IPv4/domain typically use host:port.

    if raw.hasPrefix("["), let closeIdx = raw.lastIndex(of: "]") {
        let host = String(raw[raw.index(after: raw.startIndex)..<closeIdx])
        let tail = raw[raw.index(after: closeIdx)...]
        if tail.first == ":" {
            let portText = String(tail.dropFirst())
            if let port = UInt16(portText), !host.isEmpty {
                return (host, port)
            }
        }
    }

    if let idx = raw.lastIndex(of: ":") {
        let hostPart = String(raw[..<idx]).trimmingCharacters(
            in: CharacterSet(charactersIn: "[]"))
        let portPart = String(raw[raw.index(after: idx)...])
        if let port = UInt16(portPart), !hostPart.isEmpty {
            return (hostPart, port)
        }
    }

    if let idx = raw.lastIndex(of: ".") {
        let hostPart = String(raw[..<idx]).trimmingCharacters(
            in: CharacterSet(charactersIn: "[]"))
        let portPart = String(raw[raw.index(after: idx)...])
        if hostPart.contains(":"), let port = UInt16(portPart), !hostPart.isEmpty {
            return (hostPart, port)
        }
    }

    return nil
}
