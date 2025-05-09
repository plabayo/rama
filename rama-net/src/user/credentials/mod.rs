//! user credential utilities

mod basic;

#[cfg(feature = "http")]
#[doc(inline)]
pub use basic::{BASIC_SCHEME, Basic};

mod bearer;

#[cfg(feature = "http")]
#[doc(inline)]
pub use bearer::{BEARER_SCHEME, Bearer};

mod proxy;
#[doc(inline)]
pub use proxy::ProxyCredential;
