use std::convert::Infallible;

use crate::{
    net::{
        address::Authority,
        transport::{TransportContext, TransportProtocol, TryRefIntoTransportContext},
        Protocol,
    },
    service::Context,
};

#[derive(Debug, Clone)]
/// A request to establish a Tcp Connection.
///
/// This can be used in case you operate on a layer below
/// an application alyer such as Http.
pub struct Request {
    authority: Authority,
    protocol: Option<Protocol>,
}

impl Request {
    /// Create a new Tcp [`Request`].
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            protocol: None,
        }
    }

    /// Attach an application protocol to this [`Request`]
    /// on which the established connection will operate.
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
    pub fn protocol(&self) -> Option<Protocol> {
        self.protocol.clone()
    }

    /// (re)construct a Tcp [`Request`] from its [`Parts`].
    pub fn from_parts(parts: Parts) -> Self {
        Self {
            authority: parts.authority,
            protocol: parts.protocol,
        }
    }

    /// View a reference to the target [`Authority`] of
    /// this Tcp [`Request`].
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Consume the Tcp [`Request`] into the [`Parts`] it is made of.
    pub fn into_parts(self) -> Parts {
        Parts {
            authority: self.authority,
            protocol: self.protocol,
        }
    }
}

impl From<&Request> for TransportContext {
    fn from(value: &Request) -> Self {
        TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol.clone(),
            authority: value.authority.clone(),
        }
    }
}

impl From<Request> for TransportContext {
    fn from(value: Request) -> Self {
        TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol,
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
}

impl From<Request> for Parts {
    #[inline]
    fn from(value: Request) -> Self {
        value.into_parts()
    }
}

impl From<&Parts> for TransportContext {
    fn from(value: &Parts) -> Self {
        TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol.clone(),
            authority: value.authority.clone(),
        }
    }
}

impl From<Parts> for TransportContext {
    fn from(value: Parts) -> Self {
        TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol,
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
