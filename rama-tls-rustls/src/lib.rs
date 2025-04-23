//! TLS implementations for Rama using rustls.
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

pub mod client;
pub mod server;
pub mod verify;

pub mod key_log;

mod type_conversion;

use rama_utils::macros::enums::rama_from_into_traits;
rama_from_into_traits!();

pub mod types {
    //! common tls types
    #[doc(inline)]
    pub use ::rama_net::tls::{
        ApplicationProtocol, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
        ProtocolVersion, SecureTransport, SignatureScheme, SupportedGroup, TlsTunnel, client,
    };
}

pub mod dep {
    //! Dependencies for rama rustls modules.
    //!
    //! Exported for your convenience.

    pub mod pki_types {
        //! Re-export of the [`pki-types`] crate.
        //!
        //! [`pki-types`]: https://docs.rs/rustls-pki-types

        #[doc(inline)]
        pub use rustls_pki_types::*;
    }

    pub mod pemfile {
        //! Re-export of the [`rustls-pemfile`] crate.
        //!
        //! A basic parser for .pem files containing cryptographic keys and certificates.
        //!
        //! [`rustls-pemfile`]: https://docs.rs/rustls-pemfile
        #[doc(inline)]
        pub use rustls_pemfile::*;
    }

    pub mod native_certs {
        //! Re-export of the [`rustls-native-certs`] crate.
        //!
        //! rustls-native-certs allows rustls to use the platform's native certificate
        //! store when operating as a TLS client.
        //!
        //! [`rustls-native-certs`]: https://docs.rs/rustls-native-certs
        #[doc(inline)]
        pub use rustls_native_certs::*;
    }

    pub mod rcgen {
        //! Re-export of the [`rcgen`] crate.
        //!
        //! [`rcgen`]: https://docs.rs/rcgen

        #[doc(inline)]
        pub use rcgen::*;
    }

    pub mod rustls {
        //! Re-export of the [`rustls`] and  [`tokio-rustls`] crates.
        //!
        //! To facilitate the use of `rustls` types in API's such as [`TlsAcceptorLayer`].
        //!
        //! [`rustls`]: https://docs.rs/rustls
        //! [`tokio-rustls`]: https://docs.rs/tokio-rustls
        //! [`TlsAcceptorLayer`]: crate::rustls::server::TlsAcceptorLayer

        #[doc(inline)]
        pub use rustls::*;

        pub mod client {
            //! Re-export of client module of the [`rustls`] and [`tokio-rustls`] crates.
            //!
            //! [`rustls`]: https://docs.rs/rustls
            //! [`tokio-rustls`]: https://docs.rs/tokio-rustls

            #[doc(inline)]
            pub use rustls::client::*;
            #[doc(inline)]
            pub use tokio_rustls::client::TlsStream;
        }

        pub mod server {
            //! Re-export of server module of the [`rustls`] and [`tokio-rustls`] crates.
            //!
            //! [`rustls`]: https://docs.rs/rustls
            //! [`tokio-rustls`]: https://docs.rs/tokio-rustls

            #[doc(inline)]
            pub use rustls::server::*;
            #[doc(inline)]
            pub use tokio_rustls::server::TlsStream;
        }
    }

    pub mod tokio_rustls {
        //! Full Re-export of the [`tokio-rustls`] crate.
        //!
        //! [`tokio-rustls`]: https://docs.rs/tokio-rustls
        #[doc(inline)]
        pub use tokio_rustls::*;
    }

    pub mod webpki_roots {
        //! Re-export of the [`webpki-roots`] crate.
        //!
        //! This crate provides a function to load the Mozilla root CA store.
        //!
        //! [`webpki-roots`]: https://docs.rs/webpki-roots
        #[doc(inline)]
        pub use webpki_roots::*;
    }
}
