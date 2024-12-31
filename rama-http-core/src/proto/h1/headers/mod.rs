//! types and functionality to preserve
//! http1* header casing and order.
//!
//! This is especially important for proxies and clients...
//! because out there... are wild servers that care
//! about header casing for reasons... You can think
//! of that what you want, but they do and we have to deal with it.

mod name;
pub use name::Http1HeaderName;

pub(crate) mod original;

mod map;
pub use map::Http1HeaderMap;
