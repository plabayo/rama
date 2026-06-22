use crate::{
    AuthorityInputExt, Protocol, ProtocolInputExt, TransportProtocolInputExt,
    address::{HostWithOptPort, HostWithPort},
    transport::TransportProtocol,
};
use rama_core::{extensions::Extensions, extensions::ExtensionsRef};

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A request to establish a Transport (L4) Connection.
pub struct Request {
    pub authority: HostWithPort,
    pub extensions: Extensions,
    pub application_protocol: Option<Protocol>,
    pub transport_protocol: Option<TransportProtocol>,
}

impl Request {
    /// Create a new transport (L4) [`Request`] with default [`Extensions`].
    #[must_use]
    pub fn new(authority: HostWithPort) -> Self {
        Self {
            authority,
            extensions: Extensions::new(),
            application_protocol: None,
            transport_protocol: None,
        }
    }

    /// Create a new transport (L4) [`Request`] with given [`Extensions`].
    #[must_use]
    pub const fn new_with_extensions(authority: HostWithPort, extensions: Extensions) -> Self {
        Self {
            authority,
            extensions,
            application_protocol: None,
            transport_protocol: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the application [`Protocol`] to this [`Request`]
        /// requested for this connection.
        ///
        /// By default the flow context will define the used application protocol.
        pub fn application_protocol(mut self, protocol: Option<Protocol>) -> Self {
            self.application_protocol = protocol;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the [`TransportProtocol`] to this [`Request`]
        /// requested for this connection.
        ///
        /// By default it will defined by the flow receiver itself.
        pub fn transport_protocol(mut self, protocol: Option<TransportProtocol>) -> Self {
            self.transport_protocol = protocol;
            self
        }
    }
}

impl ExtensionsRef for Request {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AuthorityInputExt for Request {
    fn authority(&self) -> Option<HostWithOptPort> {
        Some(self.authority.clone().into())
    }
}

impl ProtocolInputExt for Request {
    fn protocol(&self) -> Option<&Protocol> {
        self.application_protocol.as_ref()
    }
}

impl TransportProtocolInputExt for Request {
    fn transport_protocol(&self) -> Option<TransportProtocol> {
        self.transport_protocol
    }
}
