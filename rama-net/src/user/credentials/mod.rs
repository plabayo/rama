//! user credential utilities

mod basic;

#[doc(inline)]
pub use basic::{Basic, basic};

mod bearer;

#[doc(inline)]
pub use bearer::{Bearer, bearer};

mod raw;
#[doc(inline)]
pub use raw::{RawToken, raw_token};

mod proxy;
#[doc(inline)]
pub use proxy::{DpiProxyCredential, ProxyCredential};
