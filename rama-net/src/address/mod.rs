//! network address types and utilities
//!
//! This module provides the common language to work with
//! the different kind of formats that network addresses
//! come in, and are used as the building stone for
//! other parts of Rama that have to work with "addresses",
//! regardless if they are domains or IPs, or have ports explicitly
//! specified or not.

pub mod ip;

mod host;
#[doc(inline)]
pub use host::Host;

mod domain;
#[doc(inline)]
pub use domain::{AsDomainRef, Domain, IntoDomain};

mod authority;
#[doc(inline)]
pub use authority::Authority;

mod socket_address;
#[doc(inline)]
pub use socket_address::SocketAddress;

mod proxy;

pub(crate) mod parse_utils;

#[doc(inline)]
pub use proxy::ProxyAddress;

mod domain_address;
#[doc(inline)]
pub use domain_address::DomainAddress;

mod domain_trie;
#[doc(inline)]
pub use domain_trie::{DomainParentMatch, DomainTrie};
