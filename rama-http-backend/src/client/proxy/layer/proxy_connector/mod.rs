mod connector;
// internal usage only
use connector::InnerHttpProxyConnector;
use rama_http_types::Version;

#[derive(Debug, Clone, Copy)]
pub(super) enum HttpProxyVersionPolicy {
    Automatic { connect_fallback: Option<Version> },
    Fixed(Version),
}

impl HttpProxyVersionPolicy {
    pub(super) const fn connect_version(self) -> Option<Version> {
        match self {
            Self::Automatic { connect_fallback } => connect_fallback,
            Self::Fixed(version) => Some(version),
        }
    }

    pub(super) const fn forward_version(self, target: Option<Version>) -> Option<Version> {
        match self {
            Self::Automatic { .. } => target,
            Self::Fixed(version) => Some(version),
        }
    }
}

mod proxy_error;
#[doc(inline)]
pub use proxy_error::HttpProxyError;

mod layer;
#[doc(inline)]
pub use layer::HttpProxyConnectorLayer;

mod service;
#[doc(inline)]
pub use service::{
    HttpProxyConnectResponseHeaders, HttpProxyConnector, MaybeHttpProxiedConnection,
};
