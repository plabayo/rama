//! Internet Content Adaptation Protocol (ICAP) support for Rama.
//!
//! The crate is layered so applications can use only the level they need:
//!
//! - [`codec`] and [`proto`] provide allocation-free, `no_std` wire syntax;
//! - [`message`] owns encoded messages;
//! - [`client`] and [`server`] stream ICAP transactions through Rama I/O;
//! - [`http`] adds typed HTTP messages and the HTTP adaptation layer.
//!
//! The default build contains the protocol and codec only. Enable `std` for
//! client/server I/O, or `http` for typed HTTP adaptation (`http` implies
//! `std`). Live connections use compatible parsing by default; strict parser
//! policies remain available through [`io::ConnectionOptions`].
//!
//! See the complete HTTP(S) proxy and embedded ICAP server in Rama's
//! [`http_icap_proxy` example][example].
//!
//! [example]: https://github.com/plabayo/rama/blob/main/examples/src/http_icap_proxy.rs
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - GitHub: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

mod byte_sets;

pub mod codec;
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub mod http;
pub mod proto;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod client;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod io;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod message;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod server;
