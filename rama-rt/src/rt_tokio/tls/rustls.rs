pub use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

pub mod client {
    pub use tokio_rustls::client::TlsStream;
}

pub mod server {
    pub use tokio_rustls::server::TlsStream;
}
