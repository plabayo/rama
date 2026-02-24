//! Apple Network Extension support for rama.
//!
//! Official Apple documentation about the
//! Network Extension Framework can be consulted at:
//! <https://developer.apple.com/documentation/networkextension>.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg(target_vendor = "apple")]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

mod engine;
#[doc(hidden)]
pub mod ffi;
mod stream;
mod types;
mod udp;

pub use engine::{
    TransparentProxyEngine, TransparentProxyEngineBuilder, TransparentProxyTcpSession,
    TransparentProxyUdpSession,
};
#[doc(hidden)]
pub use ffi::{
    RamaBytesOwned, RamaBytesView, bytes_free, bytes_owned_from_vec, bytes_view_as_slice,
};
pub use stream::TcpFlow;
pub use types::{TransparentProxyConfig, TransparentProxyMeta};
pub use udp::UdpFlow;
