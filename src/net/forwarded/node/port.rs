use crate::net::forwarded::ObfuscatedString;

pub enum NodePort {
    Port(u16),
    ObfPort(ObfuscatedString),
}
