//! Enumeration of the host's local network interfaces.
//!
//! See [`interfaces`] and [`local_addresses`].

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _};
use rama_utils::macros::serde_str::impl_serde_str;
use rama_utils::str::{eq_ignore_ascii_kebab_case, smol_str::SmolStr};

use crate::address::ip::{IpScopes, ip_scope, ipnet::IpNet};

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod unix;

#[cfg(target_os = "windows")]
mod windows;

bitflags::bitflags! {
    /// Status and capability flags of a local network [`Interface`].
    ///
    /// Mapped from `IFF_*` on unix platforms and from the adapter's
    /// operational status and type on windows; per-flag notes below call out
    /// where the platforms differ.
    ///
    /// # String format
    ///
    /// [`InterfaceFlags`] round-trips (`Display`/`FromStr`/serde) through a
    /// comma-separated list of kebab-case flag names, e.g. `"up,running"`.
    /// Parsing is allocation-free and lenient: ASCII case-insensitive, `_`
    /// equals `-`, and `|` is also accepted as separator. An empty string
    /// parses as the empty set.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct InterfaceFlags: u8 {
        /// Interface is administratively up.
        ///
        /// On windows this is set together with [`InterfaceFlags::RUNNING`]
        /// when the adapter's operational status is up; the two states are
        /// not reported separately there.
        const UP = 1 << 0;
        /// Interface is operationally running (e.g. carrier present).
        const RUNNING = 1 << 1;
        /// Loopback interface.
        const LOOPBACK = 1 << 2;
        /// Point-to-point link (tunnels, PPP).
        const POINT_TO_POINT = 1 << 3;
        /// Broadcast-capable link. Never set on windows.
        const BROADCAST = 1 << 4;
        /// Multicast-capable link.
        const MULTICAST = 1 << 5;
    }
}

/// canonical kebab-case name of every flag, in bit order
const FLAG_NAMES: &[(&str, InterfaceFlags)] = &[
    ("up", InterfaceFlags::UP),
    ("running", InterfaceFlags::RUNNING),
    ("loopback", InterfaceFlags::LOOPBACK),
    ("point-to-point", InterfaceFlags::POINT_TO_POINT),
    ("broadcast", InterfaceFlags::BROADCAST),
    ("multicast", InterfaceFlags::MULTICAST),
];

impl fmt::Display for InterfaceFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (name, flag) in FLAG_NAMES {
            if self.contains(*flag) {
                if !first {
                    f.write_str(",")?;
                }
                first = false;
                f.write_str(name)?;
            }
        }
        Ok(())
    }
}

impl FromStr for InterfaceFlags {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut flags = Self::empty();
        for token in s.split([',', '|']) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            flags |= FLAG_NAMES
                .iter()
                .find_map(|(name, flag)| {
                    eq_ignore_ascii_kebab_case(token.as_bytes(), name.as_bytes()).then_some(*flag)
                })
                .ok_or_else(|| {
                    BoxError::from_static_str("unknown interface flag")
                        .context_str_field("flag", token)
                })?;
        }
        Ok(flags)
    }
}

impl_serde_str!(display InterfaceFlags);

/// Link-layer (MAC) address of an [`Interface`].
///
/// # String format
///
/// Round-trips (`Display`/`FromStr`/serde) through lowercase colon-separated
/// hex groups, e.g. `"aa:bb:cc:dd:ee:ff"`; parsing also accepts `-` as
/// separator and uppercase hex, allocation-free.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HardwareAddress {
    bytes: [u8; Self::MAX_LEN],
    len: u8,
}

impl HardwareAddress {
    const MAX_LEN: usize = 8;

    /// `None` for empty, oversized (> 8 bytes) or all-zero input:
    /// none of those identify actual hardware.
    fn try_new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > Self::MAX_LEN || bytes.iter().all(|b| *b == 0) {
            return None;
        }
        let len = u8::try_from(bytes.len()).ok()?;
        let mut buf = [0u8; Self::MAX_LEN];
        buf.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self { bytes: buf, len })
    }

    /// The raw address bytes (6 for an ethernet-style MAC).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }
}

impl TryFrom<&[u8]> for HardwareAddress {
    type Error = BoxError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_new(bytes).ok_or_else(|| {
            BoxError::from_static_str("hardware address must be 1..=8 bytes and not all-zero")
        })
    }
}

impl FromStr for HardwareAddress {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::MAX_LEN];
        let mut len = 0usize;
        for group in s.split([':', '-']) {
            if group.len() != 2 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(BoxError::from_static_str(
                    "hardware address groups must be exactly two hex digits",
                ));
            }
            let Some(slot) = bytes.get_mut(len) else {
                return Err(BoxError::from_static_str(
                    "hardware address is too long (max 8 bytes)",
                ));
            };
            *slot = u8::from_str_radix(group, 16).context("parse hardware address hex group")?;
            len += 1;
        }
        bytes.get(..len).and_then(Self::try_new).ok_or_else(|| {
            BoxError::from_static_str("hardware address must be 1..=8 bytes and not all-zero")
        })
    }
}

impl TryFrom<&str> for HardwareAddress {
    type Error = BoxError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl_serde_str!(display HardwareAddress);

impl fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.as_bytes().iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for HardwareAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HardwareAddress({self})")
    }
}

/// One IP address assigned to a local network [`Interface`].
///
/// # String format
///
/// Round-trips (`Display`/`FromStr`/serde) as `"address[%zone][/prefix]"`,
/// e.g. `"192.168.1.7/24"` or `"fe80::1%3/64"`; the (numeric) zone is only
/// valid for IPv6 addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceAddress {
    address: IpAddr,
    prefix_len: Option<u8>,
    scope_id: Option<u32>,
}

impl InterfaceAddress {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "windows",
        test
    ))]
    fn new(address: IpAddr, prefix_len: Option<u8>, scope_id: Option<u32>) -> Self {
        let max = if address.is_ipv4() { 32 } else { 128 };
        Self {
            address,
            prefix_len: prefix_len.filter(|prefix| *prefix <= max),
            scope_id: scope_id.filter(|id| *id != 0 && address.is_ipv6()),
        }
    }

    /// The address itself.
    #[must_use]
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// Prefix length of the network the address sits in, when the platform
    /// reported a (contiguous, non-zero) netmask or on-link prefix.
    #[must_use]
    pub fn prefix_len(&self) -> Option<u8> {
        self.prefix_len
    }

    /// Zone (scope id) of a scoped IPv6 address (e.g. link-local),
    /// when the platform reported one.
    ///
    /// Not to be confused with the special-use classification of
    /// [`IpScopes`]; this is the RFC 4007 zone index, as also found in
    /// [`std::net::SocketAddrV6::scope_id`].
    #[must_use]
    pub fn scope_id(&self) -> Option<u32> {
        self.scope_id
    }

    /// Address and prefix as an (un-truncated) [`IpNet`].
    ///
    /// Use [`IpNet::trunc`] on the result to get the network address itself.
    #[must_use]
    pub fn ip_net(&self) -> Option<IpNet> {
        IpNet::new(self.address, self.prefix_len?).ok()
    }
}

impl fmt::Display for InterfaceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.address.fmt(f)?;
        if let Some(zone) = self.scope_id {
            write!(f, "%{zone}")?;
        }
        if let Some(prefix) = self.prefix_len {
            write!(f, "/{prefix}")?;
        }
        Ok(())
    }
}

impl FromStr for InterfaceAddress {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (s, prefix_len) = match s.split_once('/') {
            Some((s, prefix)) => (
                s,
                Some(
                    prefix
                        .parse::<u8>()
                        .context("parse interface address prefix length")?,
                ),
            ),
            None => (s, None),
        };
        let (s, scope_id) = match s.split_once('%') {
            Some((s, zone)) => (
                s,
                Some(
                    zone.parse::<u32>()
                        .context("parse interface address zone (scope id)")?,
                ),
            ),
            None => (s, None),
        };
        let address: IpAddr = s.parse().context("parse interface ip address")?;

        if scope_id.is_some() && address.is_ipv4() {
            return Err(BoxError::from_static_str(
                "a zone (scope id) is only valid for an ipv6 interface address",
            )
            .context_field("address", address));
        }
        let max = if address.is_ipv4() { 32 } else { 128 };
        if let Some(prefix) = prefix_len
            && prefix > max
        {
            return Err(
                BoxError::from_static_str("interface address prefix length out of range")
                    .context_field("prefix", prefix)
                    .context_field("address", address),
            );
        }

        Ok(Self {
            address,
            prefix_len,
            scope_id: scope_id.filter(|id| *id != 0),
        })
    }
}

impl_serde_str!(display InterfaceAddress);

/// A network interface of the local host, as enumerated by [`interfaces`].
#[derive(Clone, Debug)]
pub struct Interface {
    name: SmolStr,
    index: Option<u32>,
    flags: InterfaceFlags,
    hw_address: Option<HardwareAddress>,
    description: Option<SmolStr>,
    addresses: Vec<InterfaceAddress>,
}

impl Interface {
    /// OS name of the interface: the kernel name on unix platforms (`eth0`,
    /// `en0`), the adapter's friendly name on windows (`Ethernet 1`).
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// OS interface index, when known.
    ///
    /// On windows this is the IPv4 interface index, falling back to the IPv6
    /// one — the two are distinct numbering spaces there. For the zone of a
    /// scoped IPv6 address use [`InterfaceAddress::scope_id`] instead.
    #[must_use]
    pub fn index(&self) -> Option<u32> {
        self.index
    }

    /// Status and capability flags of this interface.
    #[must_use]
    pub fn flags(&self) -> InterfaceFlags {
        self.flags
    }

    /// Whether the interface is up, administratively and operationally.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.flags
            .contains(InterfaceFlags::UP | InterfaceFlags::RUNNING)
    }

    /// Link-layer (MAC) address, when one is reported.
    #[must_use]
    pub fn hardware_address(&self) -> Option<&HardwareAddress> {
        self.hw_address.as_ref()
    }

    /// Human-readable adapter description. Only reported on windows.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The IP addresses assigned to this interface, in OS order.
    #[must_use]
    pub fn addresses(&self) -> &[InterfaceAddress] {
        &self.addresses
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
    )]
    /// This interface's name as a [`DeviceName`], usable with
    /// [`SocketOptions::device`] to bind a socket to it.
    ///
    /// `None` when the kernel name does not pass [`DeviceName`] validation.
    ///
    /// [`DeviceName`]: super::DeviceName
    /// [`SocketOptions::device`]: super::SocketOptions::device
    #[must_use]
    pub fn device_name(&self) -> Option<super::DeviceName> {
        super::DeviceName::try_from(self.name.as_str()).ok()
    }
}

/// Enumerate the host's network interfaces and their assigned addresses.
///
/// Interfaces and addresses are returned in the order the operating system
/// reports them; no ordering is guaranteed beyond that. Scoped IPv6 addresses
/// (e.g. link-local) carry their zone via [`InterfaceAddress::scope_id`].
///
/// Supported on linux, android, apple platforms and windows; any other
/// platform errors with [`io::ErrorKind::Unsupported`]. The call performs a
/// cheap but blocking system call; hot async paths may want to wrap it in a
/// blocking task.
#[inline(always)]
pub fn interfaces() -> io::Result<Vec<Interface>> {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        unix::interfaces()
    }

    #[cfg(target_os = "windows")]
    {
        windows::interfaces()
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "windows"
    )))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "network interface enumeration is not supported on this platform",
        ))
    }
}

/// Every address assigned to an interface that is up (administratively and
/// operationally), filtered to the given [`IpScopes`], deduplicated, in the
/// order the platform reported them.
///
/// See [`interfaces`] for platform support; scope classification is
/// [`ip_scope`]'s.
pub fn local_addresses(scopes: IpScopes) -> io::Result<Vec<IpAddr>> {
    Ok(collect_local_addresses(&interfaces()?, scopes))
}

/// The address the OS would send from to reach `destination`, without
/// sending anything: connecting a UDP socket only sets the peer.
///
/// This answers what routing would choose, where [`local_addresses`] answers
/// what exists. `None` when no route is available, or when the socket
/// reports an unspecified address.
pub fn route_source_address(destination: std::net::SocketAddr) -> Option<IpAddr> {
    let bind: std::net::SocketAddr = if destination.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };

    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(destination).ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_unspecified()).then_some(address)
}

fn collect_local_addresses(interfaces: &[Interface], scopes: IpScopes) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for interface in interfaces {
        if !interface.is_up() {
            continue;
        }
        for address in interface.addresses() {
            let ip = address.address();
            if scopes.intersects(ip_scope(ip)) && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn interface(name: &str, flags: InterfaceFlags, addresses: &[IpAddr]) -> Interface {
        Interface {
            name: SmolStr::new(name),
            index: None,
            flags,
            hw_address: None,
            description: None,
            addresses: addresses
                .iter()
                .map(|addr| InterfaceAddress::new(*addr, None, None))
                .collect(),
        }
    }

    const UP: InterfaceFlags = InterfaceFlags::UP.union(InterfaceFlags::RUNNING);

    #[test]
    fn collect_skips_interfaces_that_are_not_up() {
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 7).into();
        let ifaces = [
            interface("down0", InterfaceFlags::UP, &[ip]),
            interface("off0", InterfaceFlags::empty(), &[ip]),
        ];
        assert!(collect_local_addresses(&ifaces, IpScopes::all()).is_empty());
    }

    #[test]
    fn collect_filters_by_scope() {
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        let private: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let global: IpAddr = Ipv4Addr::new(1, 1, 1, 1).into();
        let ifaces = [interface("eth0", UP, &[loopback, private, global])];

        assert_eq!(
            collect_local_addresses(&ifaces, IpScopes::GLOBAL),
            vec![global]
        );
        assert_eq!(
            collect_local_addresses(&ifaces, IpScopes::LOOPBACK | IpScopes::PRIVATE),
            vec![loopback, private]
        );
    }

    #[test]
    fn collect_dedupes_preserving_first_seen_order() {
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let b: IpAddr = Ipv6Addr::LOCALHOST.into();
        let ifaces = [
            interface("eth0", UP, &[a, b]),
            interface("eth1", UP, &[b, a]),
        ];
        assert_eq!(
            collect_local_addresses(&ifaces, IpScopes::all()),
            vec![a, b]
        );
    }

    #[test]
    fn hardware_address_validation_and_display() {
        let _ = HardwareAddress::try_from(&[][..]).unwrap_err();
        let _ = HardwareAddress::try_from(&[0u8; 6][..]).unwrap_err();
        let _ = HardwareAddress::try_from(&[1u8; 9][..]).unwrap_err();

        let mac = HardwareAddress::try_from(&[0xaa, 0xbb, 0xcc, 0x0d, 0xee, 0xff][..]).unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:0d:ee:ff");
        assert_eq!(mac.as_bytes(), &[0xaa, 0xbb, 0xcc, 0x0d, 0xee, 0xff]);
    }

    #[test]
    fn interface_address_prefix_and_display() {
        let addr = InterfaceAddress::new(Ipv4Addr::new(192, 168, 1, 7).into(), Some(24), None);
        assert_eq!(addr.prefix_len(), Some(24));
        assert_eq!(addr.to_string(), "192.168.1.7/24");
        let net = addr.ip_net().unwrap();
        assert!(net.contains(&addr.address()));
        assert_eq!(net.trunc().to_string(), "192.168.1.0/24");

        // out-of-range prefix is dropped
        let addr = InterfaceAddress::new(Ipv4Addr::new(192, 168, 1, 7).into(), Some(33), None);
        assert_eq!(addr.prefix_len(), None);
        assert!(addr.ip_net().is_none());
        assert_eq!(addr.to_string(), "192.168.1.7");
    }

    #[test]
    fn interface_address_scope_id() {
        let link_local: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
        let addr = InterfaceAddress::new(link_local, Some(64), Some(3));
        assert_eq!(addr.scope_id(), Some(3));
        assert_eq!(addr.to_string(), "fe80::1%3/64");
        assert_eq!(addr.to_string().parse::<InterfaceAddress>().unwrap(), addr);

        // a zero zone means "no zone", and ipv4 addresses never carry one
        assert_eq!(
            InterfaceAddress::new(link_local, None, Some(0)).scope_id(),
            None
        );
        assert_eq!(
            InterfaceAddress::new(Ipv4Addr::new(10, 0, 0, 1).into(), None, Some(3)).scope_id(),
            None
        );
    }

    #[test]
    fn interface_getters() {
        let mac: HardwareAddress = "aa:bb:cc:0d:ee:ff".parse().unwrap();
        let addr: InterfaceAddress = "192.168.1.7/24".parse().unwrap();
        let iface = Interface {
            name: SmolStr::new("eth0"),
            index: Some(3),
            flags: UP | InterfaceFlags::MULTICAST,
            hw_address: Some(mac),
            description: Some(SmolStr::new("some adapter")),
            addresses: vec![addr],
        };

        assert_eq!(iface.name(), "eth0");
        assert_eq!(iface.index(), Some(3));
        assert_eq!(iface.flags(), UP | InterfaceFlags::MULTICAST);
        assert!(iface.is_up());
        assert_eq!(iface.hardware_address(), Some(&mac));
        assert_eq!(iface.description(), Some("some adapter"));
        assert_eq!(iface.addresses(), &[addr]);

        let down = Interface {
            flags: InterfaceFlags::UP,
            ..iface
        };
        assert!(!down.is_up());
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[test]
    fn interface_device_name() {
        let mut iface = Interface {
            name: SmolStr::new("eth0"),
            index: None,
            flags: InterfaceFlags::empty(),
            hw_address: None,
            description: None,
            addresses: Vec::new(),
        };
        assert_eq!(
            iface.device_name().map(|name| name.as_str().to_owned()),
            Some("eth0".to_owned())
        );

        // kernel names that fail DeviceName validation yield None
        iface.name = SmolStr::new("6in4-wan");
        assert!(iface.device_name().is_none());
    }

    #[test]
    fn hardware_address_boundaries_and_debug() {
        // 8 bytes is the maximum and is valid
        let mac = HardwareAddress::try_from(&[1u8; 8][..]).unwrap();
        assert_eq!(mac.as_bytes(), &[1u8; 8]);
        assert_eq!(mac.to_string().parse::<HardwareAddress>().unwrap(), mac);

        let mac: HardwareAddress = "aa:bb:cc:0d:ee:ff".parse().unwrap();
        assert_eq!(format!("{mac:?}"), "HardwareAddress(aa:bb:cc:0d:ee:ff)");
    }

    #[test]
    fn interface_address_parse_boundary_prefixes() {
        assert_eq!(
            "1.2.3.4/32"
                .parse::<InterfaceAddress>()
                .unwrap()
                .prefix_len(),
            Some(32)
        );
        assert_eq!(
            "::1/128".parse::<InterfaceAddress>().unwrap().prefix_len(),
            Some(128)
        );
    }

    #[test]
    fn interface_flags_display_from_str_roundtrip() {
        for (name, flag) in FLAG_NAMES {
            assert_eq!(flag.to_string(), *name);
            assert_eq!(name.parse::<InterfaceFlags>().unwrap(), *flag);
        }

        let flags = InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::POINT_TO_POINT;
        assert_eq!(flags.to_string(), "up,running,point-to-point");
        assert_eq!(flags.to_string().parse::<InterfaceFlags>().unwrap(), flags);

        assert_eq!(
            "UP|POINT_TO_POINT".parse::<InterfaceFlags>().unwrap(),
            InterfaceFlags::UP | InterfaceFlags::POINT_TO_POINT
        );
        assert_eq!(
            "".parse::<InterfaceFlags>().unwrap(),
            InterfaceFlags::empty()
        );
        let err = "bogus".parse::<InterfaceFlags>().unwrap_err();
        assert!(err.to_string().contains("bogus"), "err: {err}");
    }

    #[test]
    fn hardware_address_from_str() {
        let mac: HardwareAddress = "aa:bb:cc:0d:ee:ff".parse().unwrap();
        assert_eq!(mac.as_bytes(), &[0xaa, 0xbb, 0xcc, 0x0d, 0xee, 0xff]);
        assert_eq!(mac.to_string().parse::<HardwareAddress>().unwrap(), mac);

        // windows-style separator and uppercase hex
        assert_eq!("AA-BB-CC-0D-EE-FF".parse::<HardwareAddress>().unwrap(), mac);

        let _ = "".parse::<HardwareAddress>().unwrap_err();
        let _ = "aa:b:cc".parse::<HardwareAddress>().unwrap_err();
        let _ = "aa:+f:cc".parse::<HardwareAddress>().unwrap_err();
        let _ = "00:00:00:00:00:00".parse::<HardwareAddress>().unwrap_err();
        let _ = "aa:bb:cc:dd:ee:ff:00:11:22"
            .parse::<HardwareAddress>()
            .unwrap_err();
    }

    #[test]
    fn interface_address_from_str() {
        let addr: InterfaceAddress = "192.168.1.7/24".parse().unwrap();
        assert_eq!(addr.address(), IpAddr::from(Ipv4Addr::new(192, 168, 1, 7)));
        assert_eq!(addr.prefix_len(), Some(24));
        assert_eq!(addr.to_string().parse::<InterfaceAddress>().unwrap(), addr);

        let addr: InterfaceAddress = "fe80::1".parse().unwrap();
        assert_eq!(addr.prefix_len(), None);

        let addr: InterfaceAddress = "fe80::1%3/64".parse().unwrap();
        assert_eq!(addr.scope_id(), Some(3));
        assert_eq!(addr.prefix_len(), Some(64));
        let addr: InterfaceAddress = "fe80::1%0".parse().unwrap();
        assert_eq!(addr.scope_id(), None);

        let _ = "192.168.1.7/33".parse::<InterfaceAddress>().unwrap_err();
        let _ = "192.168.1.7/x".parse::<InterfaceAddress>().unwrap_err();
        let _ = "192.168.1.7%3".parse::<InterfaceAddress>().unwrap_err();
        let _ = "fe80::1%x".parse::<InterfaceAddress>().unwrap_err();
        let _ = "not-an-ip".parse::<InterfaceAddress>().unwrap_err();
    }

    #[test]
    fn serde_string_roundtrips() {
        let flags = InterfaceFlags::UP | InterfaceFlags::MULTICAST;
        let json = serde_json::to_string(&flags).unwrap();
        assert_eq!(json, "\"up,multicast\"");
        assert_eq!(
            serde_json::from_str::<InterfaceFlags>(&json).unwrap(),
            flags
        );

        let mac: HardwareAddress = "aa:bb:cc:0d:ee:ff".parse().unwrap();
        let json = serde_json::to_string(&mac).unwrap();
        assert_eq!(json, "\"aa:bb:cc:0d:ee:ff\"");
        assert_eq!(serde_json::from_str::<HardwareAddress>(&json).unwrap(), mac);

        let addr: InterfaceAddress = "10.0.0.1/8".parse().unwrap();
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, "\"10.0.0.1/8\"");
        assert_eq!(
            serde_json::from_str::<InterfaceAddress>(&json).unwrap(),
            addr
        );

        let addr: InterfaceAddress = "fe80::1%3/64".parse().unwrap();
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, "\"fe80::1%3/64\"");
        assert_eq!(
            serde_json::from_str::<InterfaceAddress>(&json).unwrap(),
            addr
        );
    }

    // live enumeration hits real OS calls: not available under miri
    #[cfg(all(
        any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "windows"
        ),
        not(miri)
    ))]
    mod live {
        use super::*;

        #[test]
        fn enumerates_loopback() {
            let ifaces = interfaces().unwrap();
            assert!(!ifaces.is_empty());
            assert!(
                ifaces
                    .iter()
                    .any(|i| i.flags().contains(InterfaceFlags::LOOPBACK))
            );
            // a loopback address of either family; single-family hosts
            // (e.g. ipv6-disabled) are valid configurations
            assert!(
                ifaces
                    .iter()
                    .flat_map(Interface::addresses)
                    .any(|a| a.address().is_loopback())
            );
            assert!(ifaces.iter().any(Interface::is_up));
        }

        #[test]
        fn local_addresses_scope_invariants() {
            let all = local_addresses(IpScopes::all()).unwrap();
            let global = local_addresses(IpScopes::GLOBAL).unwrap();

            assert!(all.iter().any(|ip| ip.is_loopback()));
            for ip in &global {
                assert!(all.contains(ip));
                assert!(
                    !ip_scope(*ip).intersects(IpScopes::LOOPBACK | IpScopes::LINK_LOCAL),
                    "global result contains non-global address: {ip}"
                );
            }
            // deduplicated
            for (i, ip) in all.iter().enumerate() {
                assert!(!all[..i].contains(ip), "duplicate address: {ip}");
            }
        }
    }

    #[test]
    fn route_source_address_answers_for_loopback() {
        // loopback always has a route, so this cannot depend on the network
        let source = route_source_address((std::net::Ipv4Addr::LOCALHOST, 53).into());
        assert_eq!(source, Some(std::net::Ipv4Addr::LOCALHOST.into()));

        // and it never reports the address it bound to
        if let Some(source) = route_source_address((std::net::Ipv6Addr::LOCALHOST, 53).into()) {
            assert!(!source.is_unspecified(), "{source}");
            assert!(source.is_ipv6(), "{source}");
        }
    }
}
