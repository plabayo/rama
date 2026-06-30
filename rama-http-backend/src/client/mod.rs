//! Rama HTTP client module,

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer, http_connect, http2_eager_handshake};

mod bind_body;
#[doc(inline)]
pub use bind_body::{BindBodyToConn, BindBodyToConnLayer, BindBodyToConnector};

mod pool;
#[doc(inline)]
pub use pool::{BasicHttpConId, BasicHttpConnIdentifier, HttpPooledConnectorConfig};

pub mod proxy;
