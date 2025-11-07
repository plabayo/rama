//! TLS (Boring) client support for Rama.

#[cfg(feature = "compression")]
mod compress_certificate;

mod tls_stream_auto;
pub use tls_stream_auto::AutoTlsStream;

mod tls_stream;
pub use tls_stream::TlsStream;

pub use rama_boring_tokio::SslStream as BoringTlsStream;

mod connector;
#[doc(inline)]
pub use connector::{
    ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel, TlsConnector, TlsConnectorLayer,
    tls_connect,
};

mod connector_data;
#[doc(inline)]
pub use connector_data::{ConnectorConfigClientAuth, TlsConnectorData, TlsConnectorDataBuilder};

#[cfg(feature = "ua")]
mod emulate_ua;

#[cfg(feature = "ua")]
#[doc(inline)]
#[cfg_attr(docsrs, doc(cfg(feature = "ua")))]
pub use emulate_ua::{EmulateTlsProfileLayer, EmulateTlsProfileService};
