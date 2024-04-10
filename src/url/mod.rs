//! re-export of `url` crate + extras on top of it

pub use url::*;

mod scheme;
pub use scheme::Scheme;
