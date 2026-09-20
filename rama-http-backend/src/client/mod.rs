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
pub use pool::{HttpConnId, HttpConnIdentifier, HttpPooledConnector, HttpPooledConnectorConfig};

pub mod proxy;

mod h3;
#[doc(inline)]
pub use h3::{Http3Connector, Http3Policy, TlsPoolPolicy};

mod alt_svc;
#[doc(inline)]
pub use alt_svc::AltSvcCache;

mod h3_selection;
#[doc(inline)]
pub use h3_selection::{AltSvcConnection, Http3Selection, Http3SelectionConnector};
