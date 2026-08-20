//! Internet Content Adaptation Protocol (ICAP) support for Rama.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - GitHub: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

/// The ICAP protocol version implemented by this crate.
pub const VERSION: &str = "ICAP/1.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_identity() {
        assert_eq!(VERSION, "ICAP/1.0");
    }
}
