//! Apple XPC support for rama.
//!
//! Official Apple documentation:
//!
//! - XPC overview: <https://developer.apple.com/documentation/xpc>
//! - Creating XPC services:
//!   <https://developer.apple.com/documentation/xpc/creating_xpc_services>
//! - XPC connections:
//!   <https://developer.apple.com/documentation/xpc/xpc-connections?language=objc>
//! - XPC updates:
//!   <https://developer.apple.com/documentation/updates/xpc>
//!
//! This crate uses bindgen-generated `libXPC` bindings as its low-level core.
//! It then layers small Rust wrappers on top so that Rama applications can use
//! XPC in a more ergonomic, service-oriented style.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg(target_vendor = "apple")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

#[doc(hidden)]
pub mod ffi;

mod block;
mod client;
mod connection;
mod connector;
mod error;
mod listener;
mod message;
mod object;
mod peer;
mod util;

pub use client::XpcClientConfig;
pub use connection::{ReceivedXpcMessage, XpcConnection, XpcEvent};
pub use connector::XpcConnector;
pub use error::{XpcConnectionError, XpcError};
pub use listener::{XpcListener, XpcListenerConfig};
pub use message::XpcMessage;
pub use peer::PeerSecurityRequirement;
