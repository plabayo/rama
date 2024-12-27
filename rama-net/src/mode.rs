#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Enum representing the IP modes that can be used by the DNS resolver.
pub enum IPModes {
    #[default]
    Dual,
    SingleIpV4,
    SingleIpV6,
    DualPreferIpV4
}

//DNS Resolver
#[derive(Clone)]
pub struct DnsResolveIpMode<D>{
    pub resolver: D,
    pub mode: IPModes
}

impl<D> DnsResolveIpMode<D>{
    pub fn new(resolver:D, mode: IPModes) -> Self {
        Self { resolver, mode}
    }

    /// checks if IPv4 is supported in current mode
    pub fn ipv4_supported(&self) -> bool {
        matches!(self.mode, IPModes::Dual | IPModes::SingleIpV4 | IPModes::DualPreferIpV4)
    }

    /// checks if IPv6 is supported in current mode
    pub fn ipv6_supported(&self) -> bool {
        matches!(self.mode, IPModes::Dual | IPModes::SingleIpV6)
    }
}

pub struct ConnectIpMode<C>{
    pub connector: C,
    pub ip_mode: IPModes
}

impl<C>ConnectIpMode<C>{
    pub fn new(connector: C, ip_mode: IPModes) -> Self {
        Self {connector, ip_mode}
    }
}