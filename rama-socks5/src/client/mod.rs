mod core;
pub use core::Client as Socks5Client;

pub mod bind;
pub mod udp;

mod proxy_connector;
mod proxy_error;

#[doc(inline)]
pub use proxy_connector::{Socks5ConnectProxyConnector, Socks5ConnectProxyConnectorLayer};
#[doc(inline)]
pub use proxy_error::Socks5ProxyError;
