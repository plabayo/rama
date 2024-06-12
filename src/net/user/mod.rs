//! types and utilities for network users
//!
//! Users can be humans or bots.

mod id;
#[doc(inline)]
pub use id::UserId;

mod credentials;
#[doc(inline)]
pub use credentials::{Basic, Bearer, ProxyCredential};
