//! Rama HTTP client module,

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod connect_request;
#[doc(inline)]
pub use connect_request::{HttpConnectRequestAdapter, HttpConnectRequestAdapterLayer};

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer, http_connect, http2_eager_handshake};

mod bind_body;
#[doc(inline)]
pub use bind_body::{BindBodyToConn, BindBodyToConnLayer, BindBodyToConnector};

mod pool;
#[doc(inline)]
pub use pool::{
    BasicHttpConId, BasicHttpConnIdentifier, HttpPooledConnector, HttpPooledConnectorConfig,
};

pub mod proxy;
