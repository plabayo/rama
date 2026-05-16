//! utilities crate for rama
//!
//! `rama-utils` contains utilities used by `rama`,
//! not really being part of one of the other crates, or used
//! by plenty of other crates.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[doc(hidden)]
#[macro_use]
pub mod macros;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod include_dir;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod backoff;

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod time;

pub mod bytes;
pub mod collections;
pub mod info;
pub mod latency;
pub mod octets;
pub mod rng;
pub mod str;

mod std;

#[doc(hidden)]
pub mod test_helpers;

pub mod thirdparty {
    //! Thirdparty utilities.
    //!
    //! These are external dependencies which are used throughout
    //! the rama ecosystem and which are stable enough
    //! to be re-exported here for your utility.

    pub use ::regex;
    pub use ::wildcard;
}
