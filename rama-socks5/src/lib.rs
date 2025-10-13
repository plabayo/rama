//! SOCKS5 support for Rama.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! # Socks5
//!
//! - If you need a socks5 server your best starting point is probably the [`Socks5Acceptor`];
//! - The [`Socks5Client`] is a low level connector that can be used to build client-side socks5-ready connectors;
//!
//! Feel free to use the [`proto`] module directly if you wish to implement your own
//! socks5 client/server logic using these protocol building blocks.
//!
//! # Socks4
//!
//! This library explicitly offers no support for the pre-RFC socks4.
//! Reasons being that socks4 is only used in what is now considered legacy software,
//! and that it offers certain security risks for the little it offers.
//!
//! All proxy vendors have by now also moved to socks5.
//!
//! That said, in case you have a particular need for socks4,
//! know that we do have a rough idea how we could offer backwards-compatible
//! support for socks4 (and socks4a), backed by the fact
//! that socks5 is a superset of socks4.
//!
//! Open a feature request at <https://github.com/plabayo/rama/issues>
//! in case you want this support with sufficient motivation on why you
//! have a strong need for this feature. Ideally this request
//! also comes with the ability to contribute it yourself,
//! be it with free and constructive mentorship from our end.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub mod proto;

pub mod client;
pub use client::Socks5Client;
pub use client::{Socks5ProxyConnector, Socks5ProxyConnectorLayer};

pub mod server;
pub use server::Socks5Acceptor;

mod auth;
pub use auth::Socks5Auth;
