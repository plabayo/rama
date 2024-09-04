//! TLS client support for Rama.

mod http;
#[doc(inline)]
pub use http::{AutoTlsStream, HttpsConnector, HttpsConnectorLayer};
