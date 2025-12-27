mod add_origin;
use self::add_origin::AddOrigin;

mod user_agent;
use self::user_agent::UserAgent;

mod reconnect;
use self::reconnect::Reconnect;

mod connection;
pub(super) use self::connection::Connection;

mod connector;
pub(crate) use self::connector::Connector;

// TODO[TLS]
// #[cfg(feature = "_tls-any")]
// mod tls;
// #[cfg(feature = "_tls-any")]
// pub(super) use self::tls::TlsConnector;
