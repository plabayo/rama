//! rustls based TLS support for rama.

pub mod client;
pub mod server;
pub mod verify;

mod key_log;

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
