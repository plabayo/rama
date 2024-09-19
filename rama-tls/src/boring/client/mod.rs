//! TLS client support for Rama.

mod http;
#[doc(inline)]
pub use http::{AutoTlsStream, HttpsConnector, HttpsConnectorLayer};

mod connector_data;
#[doc(inline)]
pub use connector_data::TlsConnectorData;
