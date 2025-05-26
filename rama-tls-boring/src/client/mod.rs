//! TLS (Boring) client support for Rama.

#[cfg(feature = "compression")]
mod compress_certificate;

mod tls_stream_auto;
pub use tls_stream_auto::AutoTlsStream;

mod tls_stream;
pub use tls_stream::TlsStream;

mod connector;
#[doc(inline)]
pub use connector::{
    ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel, TlsConnector, TlsConnectorLayer,
    tls_connect,
};

mod connector_data;
#[doc(inline)]
pub use connector_data::{TlsConnectorData, TlsConnectorDataBuilder};

#[cfg(feature = "ua")]
mod emulate_ua;

#[cfg(feature = "ua")]
#[doc(inline)]
pub use emulate_ua::{EmulateTlsProfileLayer, EmulateTlsProfileService};
