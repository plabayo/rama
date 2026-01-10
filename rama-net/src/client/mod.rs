//! generic client net logic

mod conn;
#[doc(inline)]
pub use conn::{BoxedConnectorService, ConnectorService, EstablishedClientConnection};

pub mod pool;

mod either_conn;
#[doc(inline)]
pub use either_conn::{
    EitherConn, EitherConn3, EitherConn3Connected, EitherConn4, EitherConn4Connected, EitherConn5,
    EitherConn5Connected, EitherConn6, EitherConn6Connected, EitherConn7, EitherConn7Connected,
    EitherConn8, EitherConn8Connected, EitherConn9, EitherConn9Connected, EitherConnConnected,
};

use crate::address::HostWithPort;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Target [`HostWithPort`] which if found in extensions
/// is to be used by a connector such as a TCPConnector instead
/// of the requested address, unless a proxy is requested in
/// which case a proxy is to be used instead.
pub struct ConnectorTarget(pub HostWithPort);
