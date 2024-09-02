//! Models for storing IP v4 and v6 addresses and ports.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The source and destination IPv4 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct IPv4 {
    /// The source IPv4 address.
    pub source_address: Ipv4Addr,
    /// The source TCP/UDP port.
    pub source_port: u16,
    /// The destination IPv4 address.
    pub destination_address: Ipv4Addr,
    /// The destination TCP/UDP port.
    pub destination_port: u16,
}

impl IPv4 {
    /// Create a new IPv4 addresses.
    pub fn new<T: Into<Ipv4Addr>>(
        source_address: T,
        destination_address: T,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        IPv4 {
            source_address: source_address.into(),
            source_port,
            destination_address: destination_address.into(),
            destination_port,
        }
    }
}
/// The source and destination IPv6 addresses and TCP ports of a header.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct IPv6 {
    /// The source IPv6 address.
    pub source_address: Ipv6Addr,
    /// The source TCP/UDP port.
    pub source_port: u16,
    /// The destination IPv6 address.
    pub destination_address: Ipv6Addr,
    /// The destination TCP/UDP port.
    pub destination_port: u16,
}

impl IPv6 {
    /// Create a new IPv6 addresses.
    pub fn new<T: Into<Ipv6Addr>>(
        source_address: T,
        destination_address: T,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        IPv6 {
            source_address: source_address.into(),
            source_port,
            destination_address: destination_address.into(),
            destination_port,
        }
    }
}
