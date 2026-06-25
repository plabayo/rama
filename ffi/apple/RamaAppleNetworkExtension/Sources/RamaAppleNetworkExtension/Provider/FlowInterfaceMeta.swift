import Foundation
import Network
import NetworkExtension

// Egress-interface + remote-hostname extraction lives in its own file because
// it needs `import Network` (for the `nw_interface_*` C API). Importing Network
// into a file that also uses NetworkExtension's deprecated `NWEndpoint` class
// (e.g. the UDP datagram path in RamaTransparentProxyProvider) makes the bare
// `NWEndpoint` name ambiguous — recent SDKs surface `Network.NWEndpoint`
// through NetworkExtension's namespace, so even `NetworkExtension.NWEndpoint`
// no longer disambiguates. Isolating this code avoids touching that existing
// path; this file never references `NWEndpoint`.

/// Extracts egress-interface facts (name / type / index), the bound flag, and
/// the remote hostname from a flow. Supplements `sourceAppMeta`; every field is
/// optional and only populated when the OS exposes it for the flow. The
/// package's macOS 12 deployment target covers all the APIs used here
/// (`networkInterface` 10.15.4+, `remoteHostname` 11.0+, `isBound` 11.1+), so no
/// `#available` guards are required.
func flowInterfaceMeta(_ flow: NEAppProxyFlow?) -> (
    interfaceName: String?, interfaceType: UInt8?, interfaceIndex: UInt32?,
    isBound: Bool?, remoteHostname: String?
) {
    guard let flow else { return (nil, nil, nil, nil, nil) }
    var interfaceName: String?
    var interfaceType: UInt8?
    var interfaceIndex: UInt32?
    if let iface = flow.networkInterface {
        // The nw_interface_t reference is only valid in this scope, so read its
        // name/type/index immediately and copy out owned values.
        interfaceName = String(cString: nw_interface_get_name(iface))
        interfaceType = ramaInterfaceTypeRaw(nw_interface_get_type(iface))
        let idx = nw_interface_get_index(iface)
        interfaceIndex = idx != 0 ? idx : nil  // 0 == invalid per if_nametoindex
    }
    let hostname = flow.remoteHostname
    return (
        interfaceName, interfaceType, interfaceIndex, flow.isBound,
        (hostname?.isEmpty == false) ? hostname : nil
    )
}

/// Maps an `nw_interface_type_t` (read off a flow's egress `networkInterface`)
/// to the `NwInterfaceType` discriminant the Rust side decodes via
/// `interface_type_from_u8`. Returns `nil` for unknown types so Rust fails safe
/// to "interface type unknown".
///
/// IMPORTANT: Apple's `nw_interface_type_t` raw values
/// (`other`=0, `wifi`=1, `cellular`=2, `wired`=3, `loopback`=4 — stable ABI
/// since macOS 10.14) intentionally DIFFER from rama's `NwInterfaceType`
/// discriminants (`Cellular`=0, `Loopback`=1, `Other`=2, `Wifi`=3, `Wired`=4),
/// so the raw value must NOT be passed through unmapped. Switching on
/// `.rawValue` keeps this correct regardless of how the C enum imports.
private func ramaInterfaceTypeRaw(_ type: nw_interface_type_t) -> UInt8? {
    switch type.rawValue {
    case 0: return 2  // nw other    -> NwInterfaceType.Other
    case 1: return 3  // nw wifi     -> NwInterfaceType.Wifi
    case 2: return 0  // nw cellular -> NwInterfaceType.Cellular
    case 3: return 4  // nw wired    -> NwInterfaceType.Wired
    case 4: return 1  // nw loopback -> NwInterfaceType.Loopback
    default: return nil
    }
}
