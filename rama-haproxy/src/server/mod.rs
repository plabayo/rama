//! HaProxy Protocol Server support
//!
//! See the vendored specification at
//! `rama-haproxy/specifications/proxy-protocol.txt`
//! (upstream: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>).

mod layer;
#[doc(inline)]
pub use layer::{
    HaProxyCommand, HaProxyLayer, HaProxyService, HaProxyStrictness, HaProxyTlv, HaProxyTlvs,
};
