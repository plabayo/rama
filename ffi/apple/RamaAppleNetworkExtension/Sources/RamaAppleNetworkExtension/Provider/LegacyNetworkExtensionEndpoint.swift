import NetworkExtension

/// Disambiguates NetworkExtension's pre-macOS-15 endpoint class in source
/// files that must also import Network's modern `NWEndpoint` enum.
public typealias RamaLegacyNetworkExtensionEndpoint = NWEndpoint
