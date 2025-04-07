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

mod either_conn;
#[doc(inline)]
pub use either_conn::{
    EitherConn, EitherConn3, EitherConn3Connected, EitherConn4, EitherConn4Connected, EitherConn5,
    EitherConn5Connected, EitherConn6, EitherConn6Connected, EitherConn7, EitherConn7Connected,
    EitherConn8, EitherConn8Connected, EitherConn9, EitherConn9Connected, EitherConnConnected,
};
