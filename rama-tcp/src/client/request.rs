use rama_core::Context;
use rama_http_types::Version;
use rama_net::{
    Protocol,
    address::Authority,
    transport::{TransportContext, TransportProtocol, TryRefIntoTransportContext},
};
use std::convert::Infallible;

#[derive(Debug, Clone)]
/// A request to establish a Tcp Connection.
///
/// This can be used in case you operate on a layer below
/// an application layer such as Http.
pub struct Request {
    authority: Authority,
    protocol: Option<Protocol>,
    http_version: Option<Version>,
}

impl Request {
    /// Create a new Tcp [`Request`].
    #[must_use]
    pub const fn new(authority: Authority) -> Self {
        Self {
            authority,
            protocol: None,
            http_version: None,
        }
    }

    /// Attach an application protocol to this [`Request`]
    /// on which the established connection will operate.
    #[must_use]
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Set an application protocol to this [`Request`]
    /// on which the established connection will operate.
    pub fn set_protocol(&mut self, protocol: Protocol) -> &mut Self {
        self.protocol = Some(protocol);
        self
    }

    /// Return the application protocol on which the established
    /// connection will operate, if known.
    #[must_use]
    pub fn protocol(&self) -> Option<Protocol> {
        self.protocol.clone()
    }

    /// Attach an http version as a hint to the application layer.
    #[must_use]
    pub const fn with_http_version(mut self, version: Version) -> Self {
        self.http_version = Some(version);
        self
    }

    /// Set an http version as a hint to the application layer.
    pub fn set_http_version(&mut self, version: Version) -> &mut Self {
        self.http_version = Some(version);
        self
    }

    /// Return the http version hint, if defined
    #[must_use]
    pub fn http_version(&self) -> Option<Version> {
        self.http_version
    }

    /// (re)construct a Tcp [`Request`] from its [`Parts`].
    #[must_use]
    pub fn from_parts(parts: Parts) -> Self {
        Self {
            authority: parts.authority,
            protocol: parts.protocol,
            http_version: parts.http_version,
        }
    }

    /// View a reference to the target [`Authority`] of
    /// this Tcp [`Request`].
    #[must_use]
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Consume the Tcp [`Request`] into the [`Parts`] it is made of.
    #[must_use]
    pub fn into_parts(self) -> Parts {
        Parts {
            authority: self.authority,
            protocol: self.protocol,
            http_version: self.http_version,
        }
    }
}

impl From<&Request> for TransportContext {
    fn from(value: &Request) -> Self {
        Self {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol.clone(),
            http_version: value.http_version,
            authority: value.authority.clone(),
        }
    }
}

impl From<Request> for TransportContext {
    fn from(value: Request) -> Self {
        Self {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol,
            http_version: value.http_version,
            authority: value.authority,
        }
    }
}

impl From<Parts> for Request {
    #[inline]
    fn from(value: Parts) -> Self {
        Self::from_parts(value)
    }
}

#[derive(Debug, Clone)]
/// The parts that make up a Tcp [`Request`].
pub struct Parts {
    /// Authority to be used to make a connection to the server.
    pub authority: Authority,

    /// Application Protocol that will be operated on, if known.
    pub protocol: Option<Protocol>,

    /// Http version hint that application layer can use if possible.
    pub http_version: Option<Version>,
}

impl From<Request> for Parts {
    #[inline]
    fn from(value: Request) -> Self {
        value.into_parts()
    }
}

impl From<&Parts> for TransportContext {
    fn from(value: &Parts) -> Self {
        Self {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol.clone(),
            http_version: value.http_version,
            authority: value.authority.clone(),
        }
    }
}

impl From<Parts> for TransportContext {
    fn from(value: Parts) -> Self {
        Self {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol,
            http_version: value.http_version,
            authority: value.authority,
        }
    }
}

impl<State> TryRefIntoTransportContext<State> for Request {
    type Error = Infallible;

    fn try_ref_into_transport_ctx(
        &self,
        _ctx: &Context<State>,
    ) -> Result<TransportContext, Self::Error> {
        Ok(self.into())
    }
}

impl<State> TryRefIntoTransportContext<State> for Parts {
    type Error = Infallible;

    fn try_ref_into_transport_ctx(
        &self,
        _ctx: &Context<State>,
    ) -> Result<TransportContext, Self::Error> {
        Ok(self.into())
    }
}
