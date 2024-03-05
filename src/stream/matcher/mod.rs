//! [`service::Matcher`]s implementations to match on [`Socket`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: crate::service::Matcher
//! [`Socket`]: crate::stream::Socket
//! [`service::matcher` module]: crate::service::matcher

mod socket;
#[doc(inline)]
pub use socket::SocketAddressFilter;
