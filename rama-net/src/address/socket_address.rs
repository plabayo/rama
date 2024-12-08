use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// An [`IpAddr`] with an associated port
pub struct SocketAddress {
    ip_addr: IpAddr,
    port: u16,
}

impl SocketAddress {
    /// creates a new [`SocketAddress`]
    pub const fn new(ip_addr: IpAddr, port: u16) -> Self {
        SocketAddress { ip_addr, port }
    }
    /// Gets the [`IpAddr`] reference.
    pub fn host(&self) -> &IpAddr {
        &self.ip_addr
    }

    /// Consumes the [`SocketAddress`] and returns the [`IpAddr`].
    pub fn into_host(self) -> IpAddr {
        self.ip_addr
    }

    /// Gets the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Consume self into its parts: `(ip_addr, port)`
    pub fn into_parts(self) -> (IpAddr, u16) {
        (self.ip_addr, self.port)
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(addr: SocketAddr) -> Self {
        SocketAddress {
            ip_addr: addr.ip(),
            port: addr.port(),
        }
    }
}

impl From<&SocketAddr> for SocketAddress {
    fn from(addr: &SocketAddr) -> Self {
        SocketAddress {
            ip_addr: addr.ip(),
            port: addr.port(),
        }
    }
}

impl From<SocketAddress> for SocketAddr {
    fn from(addr: SocketAddress) -> Self {
        SocketAddr {
            ip: addr.ip_addr,
            port: addr.port,
        }
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ip_addr {
            IpAddr::V4(ip) => write!(f, "{}:{}", ip, self.port),
            IpAddr::V6(ip) => write!(f, "[{}]:{}", ip, self.port),
        }
    }
}

impl serde::Serialize for SocketAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SocketAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}
