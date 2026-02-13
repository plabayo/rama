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
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

#[doc(hidden)]
#[macro_use]
pub mod macros;

pub mod include_dir;

pub mod backoff;
pub mod collections;
pub mod info;
pub mod latency;
pub mod octets;
pub mod rng;
pub mod str;
pub mod time;

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
