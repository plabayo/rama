//! Rama network types and utilities.
//!
//! Protocols such as tcp, http, tls, etc are not explicitly implemented here,
//! see the relevant `rama` crates for this.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod address;
pub mod asn;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod client;
pub mod client_ip;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod conn;
pub mod extensions;
pub mod forwarded;
pub mod input_ext;
pub mod ip;
pub mod mode;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod proxy;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod rate;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod stream;
#[cfg(any(test, feature = "test-utils"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-utils")))]
pub mod test_utils;
pub mod uri;
pub mod user;

pub(crate) mod byte_sets;
pub(crate) mod normalize;
pub(crate) mod proto;
pub(crate) mod std;

#[cfg(test)]
pub(crate) mod test_hash;
#[doc(inline)]
pub use client_ip::ClientIp;
#[doc(inline)]
pub use input_ext::{
    AuthorityInputExt, PathInputExt, ProtocolInputExt, TransportProtocolInputExt, UriInputExt,
};
#[cfg(feature = "std")]
#[doc(inline)]
pub use input_ext::{ConnectorTargetInputExt, ConnectorTransportProtocolInputExt};
#[cfg(feature = "std")]
#[doc(inline)]
pub use input_ext::{HttpVersionInputExt, TargetHttpVersionInputExt};
#[doc(inline)]
pub use proto::Protocol;

pub mod tls;
pub mod transport;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod http;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod socket;

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

#[doc(hidden)]
pub mod __private {
    pub use ::rama_utils as utils;
}

#[cfg(feature = "inspect")]
#[cfg_attr(docsrs, doc(cfg(feature = "inspect")))]
pub mod inspect;
