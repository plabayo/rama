use crate::{
    AuthorityInputExt, Protocol, ProtocolInputExt, TransportProtocolInputExt,
    address::{HostWithOptPort, HostWithPort},
    transport::TransportProtocol,
};

use rama_core::{Fork, extensions::Extensions, extensions::ExtensionsRef};

#[cfg(feature = "http")]
use crate::{TargetHttpVersionInputExt, http::TargetHttpVersion, http::Version};

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A protocol-independent request to establish a client connection.
pub struct ConnectRequest {
    pub authority: HostWithPort,
    pub extensions: Extensions,
    pub application_protocol: Option<Protocol>,
    pub transport_protocol: Option<TransportProtocol>,
}

impl ConnectRequest {
    /// Create a new [`ConnectRequest`] with default [`Extensions`].
    #[must_use]
    pub fn new(authority: HostWithPort) -> Self {
        Self {
            authority,
            extensions: Extensions::new(),
            application_protocol: None,
            transport_protocol: None,
        }
    }

    /// Create a new [`ConnectRequest`] with given [`Extensions`].
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
        /// Define the application [`Protocol`] to this [`ConnectRequest`]
        /// requested for this connection.
        ///
        /// By default the flow context will define the used application protocol.
        pub fn application_protocol(mut self, protocol: Option<Protocol>) -> Self {
            self.application_protocol = protocol;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the [`TransportProtocol`] to this [`ConnectRequest`]
        /// requested for this connection.
        ///
        /// By default it will defined by the flow receiver itself.
        pub fn transport_protocol(mut self, protocol: Option<TransportProtocol>) -> Self {
            self.transport_protocol = protocol;
            self
        }
    }
}

impl Fork for ConnectRequest {
    fn fork(&self) -> Self {
        Self {
            authority: self.authority.clone(),
            extensions: self.extensions.fork(),
            application_protocol: self.application_protocol.clone(),
            transport_protocol: self.transport_protocol,
        }
    }
}

impl ExtensionsRef for ConnectRequest {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AuthorityInputExt for ConnectRequest {
    fn authority(&self) -> Option<HostWithOptPort> {
        Some(self.authority.clone().into())
    }
}

impl ProtocolInputExt for ConnectRequest {
    fn protocol(&self) -> Option<&Protocol> {
        self.application_protocol.as_ref()
    }
}

impl TransportProtocolInputExt for ConnectRequest {
    fn transport_protocol(&self) -> Option<TransportProtocol> {
        self.transport_protocol
    }
}

#[cfg(feature = "http")]
impl TargetHttpVersionInputExt for ConnectRequest {
    fn target_http_version(&self) -> Option<Version> {
        self.extensions
            .get_ref::<TargetHttpVersion>()
            .map(|target| target.0)
    }
}

#[cfg(test)]
mod tests {
    use rama_core::extensions::Extension;

    use super::*;

    #[derive(Debug, Extension)]
    struct AttemptMarker;

    #[test]
    fn fork_isolates_attempt_extensions() {
        let request = ConnectRequest::new(HostWithPort::example_domain_https());
        let attempt = request.fork();

        attempt.extensions.insert(AttemptMarker);

        assert!(!request.extensions.contains::<AttemptMarker>());
        assert!(attempt.extensions.contains::<AttemptMarker>());
    }

    #[cfg(feature = "http")]
    #[test]
    fn target_http_version_comes_from_extension() {
        let request = ConnectRequest::new(HostWithPort::example_domain_https());
        assert_eq!(request.target_http_version(), None);

        request
            .extensions
            .insert(TargetHttpVersion(Version::HTTP_2));

        assert_eq!(request.target_http_version(), Some(Version::HTTP_2));
    }
}
