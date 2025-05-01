mod core;
pub use core::Client as Socks5Client;

pub mod bind;

mod proxy_connector;
mod proxy_error;

#[doc(inline)]
pub use proxy_connector::{Socks5ProxyConnector, Socks5ProxyConnectorLayer};
#[doc(inline)]
pub use proxy_error::Socks5ProxyError;
