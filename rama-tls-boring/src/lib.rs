//! TLS implementations for Rama using boring ssl.
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
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub struct RamaTlsRustlsCrateMarker;

pub mod client;
pub mod server;

pub mod keylog;
pub mod type_conversion;

pub mod types {
    //! common tls types
    #[doc(inline)]
    pub use ::rama_net::tls::{
        ApplicationProtocol, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
        ProtocolVersion, SecureTransport, SignatureScheme, SupportedGroup, TlsTunnel, client,
    };
}

pub mod core {
    //! Re-export of the [`rama-boring`] crate.
    //!
    //! [`rama-boring`]: https://docs.rs/rama-boring

    #[doc(inline)]
    pub use rama_boring::*;

    pub mod tokio {
        //! Full Re-export of the [`rama-boring-tokio`] crate.
        //!
        //! [`rama-boring-tokio`]: https://docs.rs/rama-boring-tokio
        #[doc(inline)]
        pub use rama_boring_tokio::*;
    }
}
