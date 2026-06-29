//! generic client net logic

mod conn;
#[doc(inline)]
pub use conn::{BoxedConnectorService, ConnectorService, EstablishedClientConnection};

mod connector;
#[doc(inline)]
pub use connector::{AddressCandidates, ConnectorTarget, ConnectorTargetStream, race_connect};

mod graceful;
#[doc(inline)]
pub use graceful::GracefulConnectorService;

pub mod pool;

mod either_conn;
#[doc(inline)]
pub use either_conn::{
    EitherConn, EitherConn3, EitherConn3Connected, EitherConn4, EitherConn4Connected, EitherConn5,
    EitherConn5Connected, EitherConn6, EitherConn6Connected, EitherConn7, EitherConn7Connected,
    EitherConn8, EitherConn8Connected, EitherConn9, EitherConn9Connected, EitherConnConnected,
};

mod request;
#[doc(inline)]
pub use request::Request;
