use rama_core::{
    extensions::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
};
use rama_http_types::Version;
use rama_net::{
    Protocol,
    address::HostWithPort,
    transport::{TransportContext, TransportProtocol, TryRefIntoTransportContext},
};
use std::convert::Infallible;

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A request to establish a Tcp Connection.
///
/// This can be used in case you operate on a layer below
/// an application layer such as Http.
pub struct Request {
    pub authority: HostWithPort,
    pub protocol: Option<Protocol>,
    pub http_version: Option<Version>,
    pub extensions: Extensions,
}

impl Request {
    /// Create a new Tcp [`Request`] with default [`Extensions`].
    #[must_use]
    pub fn new(authority: HostWithPort) -> Self {
        Self {
            authority,
            protocol: None,
            http_version: None,
            extensions: Extensions::new(),
        }
    }

    /// Create a new Tcp [`Request`] with given [`Extensions`].
    #[must_use]
    pub const fn new_with_extensions(authority: HostWithPort, extensions: Extensions) -> Self {
        Self {
            authority,
            protocol: None,
            http_version: None,
            extensions,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the application protocol to this [`Request`]
        /// on which the established connection will operate.
        pub fn protocol(mut self, protocol: Option<Protocol>) -> Self {
            self.protocol = protocol;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the http version as a hint to the application layer.
        pub fn http_version(mut self, version: Option<Version>) -> Self {
            self.http_version = version;
            self
        }
    }
}

impl ExtensionsRef for Request {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl ExtensionsMut for Request {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

impl From<&Request> for TransportContext {
    fn from(value: &Request) -> Self {
        Self {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol.clone(),
            http_version: value.http_version,
            authority: value.authority.clone().into(),
        }
    }
}

impl From<Request> for TransportContext {
    fn from(value: Request) -> Self {
        Self {
            protocol: TransportProtocol::Tcp,
            app_protocol: value.protocol,
            http_version: value.http_version,
            authority: value.authority.into(),
        }
    }
}

impl TryRefIntoTransportContext for Request {
    type Error = Infallible;

    fn try_ref_into_transport_ctx(&self) -> Result<TransportContext, Self::Error> {
        Ok(self.into())
    }
}
