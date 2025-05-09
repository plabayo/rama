//! user credential utilities

mod basic;

#[doc(inline)]
pub use basic::{BASIC_SCHEME, Basic};

mod bearer;

#[doc(inline)]
pub use bearer::{BEARER_SCHEME, Bearer};

mod proxy;
#[doc(inline)]
pub use proxy::ProxyCredential;
