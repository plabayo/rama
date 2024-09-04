//! HaProxy Protocol Client support
//!
//! <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>

mod layer;
#[doc(inline)]
pub use layer::{protocol, version, HaProxyLayer, HaProxyService};
