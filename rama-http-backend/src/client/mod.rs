//! Rama HTTP client module,

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer, http_connect, http2_eager_handshake};

pub mod proxy;
