//! user credential utilities

mod basic;

#[cfg(feature = "http")]
#[doc(inline)]
pub use basic::BASIC_SCHEME;

#[doc(inline)]
pub use basic::Basic;

mod bearer;

#[cfg(feature = "http")]
#[doc(inline)]
pub use bearer::BEARER_SCHEME;

#[doc(inline)]
pub use bearer::Bearer;

mod proxy;
#[doc(inline)]
pub use proxy::ProxyCredential;
