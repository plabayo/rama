use crate::address::{SocketAddress, parse_utils::try_to_parse_str_to_ip};
use rama_core::error::{ErrorContext, OpaqueError};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
    sync::Arc,
};

/// The interface to bind a [`Socket`] to.
///
/// [`Socket`]: super::core::Socket
#[derive(Debug, Clone)]
pub enum Interface {
    /// Bind to a [`Socket`] address (ip + port), the most common choice
    ///
    /// [`Socket`]: super::core::Socket
    Address(SocketAddress),
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
    )]
    /// Bind to a network device interface name, using IPv4/TCP.
    ///
    /// Use [`SocketOptions`] if you want more finegrained control,
    /// or make a raw [`Socket`] yourself.
    ///
    /// [`Socket`]: super::core::Socket
    Device(DeviceName),
    /// Bind to a socket with the following options.
    Socket(Arc<SocketOptions>),
}

impl Interface {
    /// creates a new [`Interface`] from a [`SocketAddress`]
    pub fn new_address(addr: impl Into<SocketAddress>) -> Self {
        Self::Address(addr.into())
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
)]
pub use device::DeviceName;

use super::SocketOptions;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
mod device {
    use super::*;
    use smol_str::SmolStr;

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    /// Name of a (network) interface device name, e.g. `eth0`.
    pub struct DeviceName(SmolStr);

    impl DeviceName {
        /// Create a new [`DeviceName`].
        #[must_use]
        pub const fn new(name: &'static str) -> Self {
            if !is_valid(name.as_bytes()) {
                panic!("static str is not a valid (interface) device name");
            }
            Self(SmolStr::new_static(name))
        }

        /// Return a reference to `self` as a byte slice.
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            self.0.as_bytes()
        }

        /// Return a reference to `self` as a string slice.
        #[must_use]
        pub fn as_str(&self) -> &str {
            self.0.as_str()
        }
    }

    impl fmt::Display for DeviceName {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl FromStr for DeviceName {
        type Err = OpaqueError;

        #[inline]
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::try_from(s)
        }
    }

    impl TryFrom<String> for DeviceName {
        type Error = OpaqueError;

        #[inline]
        fn try_from(s: String) -> Result<Self, Self::Error> {
            s.as_str().try_into()
        }
    }

    impl TryFrom<&String> for DeviceName {
        type Error = OpaqueError;

        #[inline]
        fn try_from(value: &String) -> Result<Self, Self::Error> {
            value.as_str().try_into()
        }
    }

    impl TryFrom<&str> for DeviceName {
        type Error = OpaqueError;

        fn try_from(s: &str) -> Result<Self, Self::Error> {
            if is_valid(s.as_bytes()) {
                return Ok(Self(SmolStr::from(s)));
            }

            Err(OpaqueError::from_display("invalid (interface) device name"))
        }
    }

    impl TryFrom<Vec<u8>> for DeviceName {
        type Error = OpaqueError;

        fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
            Self::try_from(bytes.as_slice())
        }
    }

    impl TryFrom<&[u8]> for DeviceName {
        type Error = OpaqueError;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            let s =
                std::str::from_utf8(bytes).context("parse (interface) device name from bytes")?;
            s.try_into()
        }
    }

    impl serde::Serialize for DeviceName {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let name = self.as_str();
            name.serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for DeviceName {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
            s.parse().map_err(serde::de::Error::custom)
        }
    }

    impl Interface {
        #[must_use]
        pub const fn new_device(name: &'static str) -> Self {
            let name = DeviceName::new(name);
            Self::Device(name)
        }
    }

    pub(super) const fn is_valid(s: &[u8]) -> bool {
        if s.is_empty() || s.len() > DEVICE_MAX_LEN {
            false
        } else {
            let mut i = 0;
            if DEVICE_FIRST_CHARS[s[0] as usize] == 0 {
                return false;
            }
            while i < s.len() {
                if DEVICE_CHARS[s[i] as usize] == 0 {
                    return false;
                }
                i += 1;
            }
            true
        }
    }

    /// The maximum length of a device name.
    const DEVICE_MAX_LEN: usize = 15;

    #[rustfmt::skip]
    /// Valid byte values for a device name.
    const DEVICE_CHARS: [u8; 256] = [
        //  0      1      2      3      4      5      6      7      8      9
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //   x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  1x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  2x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  3x
            0,     0,     0,     0,     0,  b'-',  b'.',     0,  b'0',  b'1', //  4x
         b'2',  b'3',  b'4',  b'5',  b'6',  b'7',  b'8',  b'9',  b':',     0, //  5x
            0,     0,     0,     0,     0,  b'A',  b'B',  b'C',  b'D',  b'E', //  6x
         b'F',  b'G',  b'H',  b'I',  b'J',  b'K',  b'L',  b'M',  b'N',  b'O', //  7x
         b'P',  b'Q',  b'R',  b'S',  b'T',  b'U',  b'V',  b'W',  b'X',  b'Y', //  8x
         b'Z',     0,     0,     0,     0,  b'_',     0,  b'a',  b'b',  b'c', //  9x
         b'd',  b'e',  b'f',  b'g',  b'h',  b'i',  b'j',  b'k',  b'l',  b'm', // 10x
         b'n',  b'o',  b'p',  b'q',  b'r',  b's',  b't',  b'u',  b'v',  b'w', // 11x
         b'x',  b'y',  b'z',     0,     0,     0,     0,     0,     0,     0, // 12x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 13x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 14x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 15x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 16x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 17x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 18x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 19x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 20x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 21x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 22x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 23x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 24x
            0,     0,     0,     0,     0,     0                              // 25x
    ];

    #[rustfmt::skip]
    const DEVICE_FIRST_CHARS: [u8; 256] = [
        //  0      1      2      3      4      5      6      7      8      9
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //   x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  1x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  2x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  3x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  4x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  5x
            0,     0,     0,     0,     0,     b'A',  b'B',  b'C',  b'D',  b'E', //  6x
            b'F',  b'G',  b'H',  b'I',  b'J',  b'K',  b'L',  b'M',  b'N',  b'O', //  7x
            b'P',  b'Q',  b'R',  b'S',  b'T',  b'U',  b'V',  b'W',  b'X',  b'Y', //  8x
            b'Z',     0,     0,     0,     0,     0,     0,  b'a',  b'b',  b'c', //  9x
            b'd',  b'e',  b'f',  b'g',  b'h',  b'i',  b'j',  b'k',  b'l',  b'm', // 10x
            b'n',  b'o',  b'p',  b'q',  b'r',  b's',  b't',  b'u',  b'v',  b'w', // 11x
            b'x',  b'y',  b'z',     0,     0,     0,     0,     0,     0,  0,    // 12x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 13x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 14x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 15x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 16x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 17x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 18x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 19x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 20x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 21x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 22x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 23x
            0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 24x
            0,     0,     0,     0,     0,     0                                 // 25x
    ];
}

impl Interface {
    /// creates a new local ipv4 [`Interface`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::socket::Interface;
    ///
    /// let interface = Interface::local_ipv4(8080);
    /// assert_eq!("127.0.0.1:8080", interface.to_string());
    /// ```
    #[inline]
    #[must_use]
    pub const fn local_ipv4(port: u16) -> Self {
        Self::Address(SocketAddress::local_ipv4(port))
    }

    /// creates a new local ipv6 [`Interface`] for the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::socket::Interface;
    ///
    /// let interface = Interface::local_ipv6(8080);
    /// assert_eq!("[::1]:8080", interface.to_string());
    /// ```
    #[inline]
    #[must_use]
    pub const fn local_ipv6(port: u16) -> Self {
        Self::Address(SocketAddress::local_ipv6(port))
    }

    /// creates a new default ipv4 [`Interface`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::socket::Interface;
    ///
    /// let interface = Interface::default_ipv4(8080);
    /// assert_eq!("0.0.0.0:8080", interface.to_string());
    /// ```
    #[inline]
    #[must_use]
    pub const fn default_ipv4(port: u16) -> Self {
        Self::Address(SocketAddress::default_ipv4(port))
    }

    /// creates a new default ipv6 [`Interface`] for the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::socket::Interface;
    ///
    /// let interface = Interface::default_ipv6(8080);
    /// assert_eq!("[::]:8080", interface.to_string());
    /// ```
    #[must_use]
    pub const fn default_ipv6(port: u16) -> Self {
        Self::Address(SocketAddress::default_ipv6(port))
    }

    /// creates a new broadcast ipv4 [`Interface`] for the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::socket::Interface;
    ///
    /// let interface = Interface::broadcast_ipv4(8080);
    /// assert_eq!("255.255.255.255:8080", interface.to_string());
    /// ```
    #[must_use]
    pub const fn broadcast_ipv4(port: u16) -> Self {
        Self::Address(SocketAddress::broadcast_ipv4(port))
    }
}

impl From<SocketAddress> for Interface {
    #[inline]
    fn from(addr: SocketAddress) -> Self {
        Self::Address(addr)
    }
}

impl From<&SocketAddress> for Interface {
    #[inline]
    fn from(addr: &SocketAddress) -> Self {
        Self::Address(*addr)
    }
}

impl From<SocketAddr> for Interface {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        Self::Address(addr.into())
    }
}

impl From<&SocketAddr> for Interface {
    #[inline]
    fn from(addr: &SocketAddr) -> Self {
        Self::Address(addr.into())
    }
}

impl From<SocketAddrV4> for Interface {
    #[inline]
    fn from(addr: SocketAddrV4) -> Self {
        Self::Address(addr.into())
    }
}

impl From<SocketAddrV6> for Interface {
    #[inline]
    fn from(addr: SocketAddrV6) -> Self {
        Self::Address(addr.into())
    }
}

impl From<(IpAddr, u16)> for Interface {
    #[inline]
    fn from(twin: (IpAddr, u16)) -> Self {
        Self::Address(twin.into())
    }
}

impl From<(Ipv4Addr, u16)> for Interface {
    #[inline]
    fn from(twin: (Ipv4Addr, u16)) -> Self {
        Self::Address(twin.into())
    }
}

impl From<([u8; 4], u16)> for Interface {
    #[inline]
    fn from(twin: ([u8; 4], u16)) -> Self {
        Self::Address(twin.into())
    }
}

impl From<(Ipv6Addr, u16)> for Interface {
    #[inline]
    fn from(twin: (Ipv6Addr, u16)) -> Self {
        Self::Address(twin.into())
    }
}

impl From<([u8; 16], u16)> for Interface {
    #[inline]
    fn from(twin: ([u8; 16], u16)) -> Self {
        Self::Address(twin.into())
    }
}

impl From<SocketOptions> for Interface {
    #[inline]
    fn from(value: SocketOptions) -> Self {
        Self::Socket(Arc::new(value))
    }
}

impl From<Arc<SocketOptions>> for Interface {
    #[inline]
    fn from(value: Arc<SocketOptions>) -> Self {
        Self::Socket(value)
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(socket_address) => write!(f, "{socket_address}"),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            Self::Device(name) => write!(f, "{name}"),
            Self::Socket(opts) => write!(f, "{opts:?}"),
        }
    }
}

impl FromStr for Interface {
    type Err = OpaqueError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for Interface {
    type Error = OpaqueError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&String> for Interface {
    type Error = OpaqueError;

    #[inline]
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for Interface {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (ip_addr, port) = match crate::address::parse_utils::split_port_from_str(s) {
            Ok(t) => t,
            Err(err) => {
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                if let Ok(name) = DeviceName::try_from(s) {
                    return Ok(Self::Device(name));
                }

                return Err(err);
            }
        };

        if let Some(ip_addr) = try_to_parse_str_to_ip(ip_addr) {
            match ip_addr {
                IpAddr::V6(_) if !s.starts_with('[') => Err(OpaqueError::from_display(
                    "missing brackets for IPv6 address with port",
                )),
                _ => Ok(Self::new_address((ip_addr, port))),
            }
        } else {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            if let Ok(name) = DeviceName::try_from(s) {
                return Ok(Self::Device(name));
            }

            Err(OpaqueError::from_display("invalid bind interface"))
        }
    }
}

impl TryFrom<Vec<u8>> for Interface {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for Interface {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse bind interface from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for Interface {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let interface = self.to_string();
        interface.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Interface {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[allow(clippy::large_enum_variant)]
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Variants {
            Str(String),
            Opts(SocketOptions),
        }

        match Variants::deserialize(deserializer)? {
            Variants::Str(s) => s.parse().map_err(serde::de::Error::custom),
            Variants::Opts(opts) => Ok(Self::Socket(Arc::new(opts))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_eq_socket_address(s: &str, bind_address: Interface, ip_addr: &str, port: u16) {
        match bind_address {
            Interface::Address(socket_address) => {
                assert_eq!(
                    socket_address.ip_addr().to_string(),
                    ip_addr,
                    "parsing: {s}",
                );
                assert_eq!(socket_address.port(), port, "parsing: {s}");
            }
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            Interface::Device(name) => panic!("unexpected device name '{name}': parsing '{s}'"),
            Interface::Socket(opts) => {
                panic!("unexpected socket options '{opts:?}': parsing '{s}'")
            }
        }
    }

    #[test]
    fn test_parse_valid_socket_address() {
        for (s, (expected_ip_addr, expected_port)) in [
            ("[::1]:80", ("::1", 80)),
            ("127.0.0.1:80", ("127.0.0.1", 80)),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                ("2001:db8:3333:4444:5555:6666:7777:8888", 80),
            ),
        ] {
            let msg = format!("parsing '{s}'");

            assert_eq_socket_address(s, s.parse().expect(&msg), expected_ip_addr, expected_port);
            assert_eq_socket_address(
                s,
                s.try_into().expect(&msg),
                expected_ip_addr,
                expected_port,
            );
            assert_eq_socket_address(
                s,
                s.to_owned().try_into().expect(&msg),
                expected_ip_addr,
                expected_port,
            );
            assert_eq_socket_address(
                s,
                s.as_bytes().try_into().expect(&msg),
                expected_ip_addr,
                expected_port,
            );
            assert_eq_socket_address(
                s,
                s.as_bytes().to_vec().try_into().expect(&msg),
                expected_ip_addr,
                expected_port,
            );
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn assert_eq_device_name(s: &str, bind_address: Interface) {
        match bind_address {
            Interface::Address(socket_address) => {
                panic!("unexpected socket address '{socket_address}: parsing '{s}")
            }
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            Interface::Device(name) => assert_eq!(s, name.as_str()),
            Interface::Socket(opts) => {
                panic!("unexpected socket options '{opts:?}': parsing '{s}'")
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[test]
    fn test_parse_valid_device_name() {
        for s in [
            "eth0",
            "eth0.100",
            "br-lan",
            "ens192",
            "veth_abcd1234",
            "lo",
        ] {
            let msg = format!("parsing '{s}'");

            assert_eq_device_name(s, s.parse().expect(&msg));
            assert_eq_device_name(s, s.try_into().expect(&msg));
            assert_eq_device_name(s, s.to_owned().try_into().expect(&msg));
            assert_eq_device_name(s, s.as_bytes().try_into().expect(&msg));
            assert_eq_device_name(s, s.as_bytes().to_vec().try_into().expect(&msg));
        }
    }

    #[test]
    fn test_parse_invalid() {
        for s in [
            "",
            "-",
            ".",
            ":",
            ":80",
            "-.",
            ".-",
            "::1",
            "127.0.0.1",
            "[::1]",
            "2001:db8:3333:4444:5555:6666:7777:8888",
            "[2001:db8:3333:4444:5555:6666:7777:8888]",
            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            "example.com",
            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            "example.com:",
            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            "example.com:-1",
            "example.com:999999",
            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            "example.com:80",
            #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
            "example:com",
            "[127.0.0.1]:80",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
            "eth#0",
            "eth#0",
            "abcdefghijklmnopqrstuvwxyz",
            "GigabitEthernet0/1",
            "ge-0/0/0",
        ] {
            let msg = format!("parsing '{s}'");
            assert!(s.parse::<Interface>().is_err(), "{msg}");
            assert!(Interface::try_from(s).is_err(), "{msg}");
            assert!(Interface::try_from(s.to_owned()).is_err(), "{msg}");
            assert!(Interface::try_from(s.as_bytes()).is_err(), "{msg}");
            assert!(Interface::try_from(s.as_bytes().to_vec()).is_err(), "{msg}");
        }
    }

    #[test]
    fn test_parse_display_address() {
        for (s, expected) in [("[::1]:80", "[::1]:80"), ("127.0.0.1:80", "127.0.0.1:80")] {
            let msg = format!("parsing '{s}'");
            let bind_address: Interface = s.parse().expect(&msg);
            assert_eq!(bind_address.to_string(), expected, "{msg}");
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[test]
    fn test_parse_display_device_name() {
        for s in [
            "eth0",
            "eth0.100",
            "br-lan",
            "ens192",
            "veth_abcd1234",
            "lo",
        ] {
            let msg = format!("parsing '{s}'");
            let bind_address: Interface = s.parse().expect(&msg);
            assert_eq!(bind_address.to_string(), s, "{msg}");
        }
    }
}
