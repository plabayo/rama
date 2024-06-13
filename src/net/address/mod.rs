//! network address types and utilities
//!
//! This module provides the common language to work with
//! the different kind of formats that network addresses
//! come in, and are used as the building stone for
//! other parts of Rama that have to work with "addresses",
//! regardless if they are domains or IPs, or have ports explicitly
//! specified or not.

mod host;
#[doc(inline)]
pub use host::Host;

mod domain;
#[doc(inline)]
pub use domain::Domain;

mod authority;
#[doc(inline)]
pub use authority::Authority;

mod proxy;
#[doc(inline)]
pub use proxy::ProxyAddress;
