//! TLS module for Rama.

pub mod server;

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
