//! TLS client support for Rama.

mod connector;
#[doc(inline)]
pub use connector::{
    ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel, TlsConnector, TlsConnectorLayer,
};

mod config;
#[doc(inline)]
pub use config::{
    ModifyRustlsClientConfig, RustlsClientConfigExt, RustlsServerCertVerifier,
    RustlsTlsConnectorConfig,
};

mod connector_data;
pub(super) use connector_data::TlsConnectorData;

#[doc(inline)]
pub use connector_data::{client_root_certs, self_signed_client_auth};

mod tls_stream;
#[doc(inline)]
pub use tls_stream::TlsStream;

mod tls_stream_auto;
#[doc(inline)]
pub use tls_stream_auto::AutoTlsStream;

use crate::dep::tokio_rustls::client::TlsStream as RustlsTlsStream;
