//! TLS module for Rama.

pub mod server;

pub mod dep {
    //! Dependencies for rama tls modules.
    //!
    //! Exported for your convenience.

    pub mod pki_types {
        //! Re-export of the [`pki-types`] crate.
        //!
        //! [`pki-types`]: https://docs.rs/rustls-pki-types

        pub use pki_types::*;
    }

    pub mod rcgen {
        //! Re-export of the [`rcgen`] crate.
        //!
        //! [`rcgen`]: https://docs.rs/rcgen

        pub use rcgen::*;
    }

    pub mod rustls {
        //! Re-export of the `rustls` and `tokio-rustls` crates.
        //!
        //! To facilitate the use of `rustls` types in API's such as `TlsAcceptorLayer`.

        pub use rustls::*;

        pub mod client {
            //! Re-export of client module of the `rustls` and `tokio-rustls` crates.

            pub use rustls::client::*;
            pub use tokio_rustls::client::TlsStream;
        }

        pub mod server {
            //! Re-export of server module of the `rustls` and `tokio-rustls` crates.

            pub use rustls::server::*;
            pub use tokio_rustls::server::TlsStream;
        }
    }
}
