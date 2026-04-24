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

#[doc(hidden)]
pub mod ffi;

#[doc(hidden)]
#[macro_use]
mod macros;

pub mod app_protected_storage;
pub mod process;
pub mod secure_enclave;
pub mod tproxy;

mod tcp;
mod udp;

pub use self::{tcp::TcpFlow, udp::UdpFlow};
pub use crate::__transparent_proxy_ffi as transparent_proxy_ffi;

#[doc(hidden)]
pub use rama_core::bytes::Bytes as __RamaBytes;
#[doc(hidden)]
pub use rama_core::telemetry::tracing as __tracing;
