use crate::net::forwarded::ObfuscatedString;
use std::net::IpAddr;

pub enum NodeName {
    Unknown,
    Ip(IpAddr),
    ObfNode(ObfuscatedString),
}
