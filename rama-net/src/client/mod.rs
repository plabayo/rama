//! generic client net logic

mod conn;
#[doc(inline)]
pub use conn::{ConnectorService, EstablishedClientConnection};

mod pool;
#[doc(inline)]
pub use pool::{
    ConnStoreFiFoReuseLruDrop, LeasedConnection, Pool, PoolStorage, PooledConnector,
    PooledConnectorLayer, ReqToConnID,
};
