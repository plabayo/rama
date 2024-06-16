//! rama support for the "Forwarded HTTP Extension"
//!
//! RFC: <https://datatracker.ietf.org/doc/html/rfc7239>

use super::{address::Authority, Protocol};
use std::net::IpAddr;

mod obfuscated;
#[doc(inline)]
pub use obfuscated::ObfuscatedString;

mod node;
#[doc(inline)]
pub use node::{Node, NodeName, NodePort};

mod entry;
#[doc(inline)]
pub use entry::ForwardedEntry;

pub struct Forwarded {
    entries: Vec<ForwardedEntry>,
}
