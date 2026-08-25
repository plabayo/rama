use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions},
};
use rama_http_types::HeaderMap;
use rama_net::{
    Protocol,
    address::{HostWithOptPort, HostWithPort},
    client::ConnectRequest,
    transport::TransportProtocol,
    uri::{IntoUriInput, ParseError as UriParseError, Uri},
};
use rama_utils::macros::generate_set_and_with;

use crate::{
    client::options::{OptionsCachePartition, OptionsRequest, OptionsRequestError},
    codec::{
        Header, InvalidHeader, ParseError as IcapParseError, RequestLineSource, validate_icap_uri,
    },
    http::{ReplayLimits, headers::ForwardedIcapHeader},
    message::{BuildError, EncapsulatedParts, Request},
    proto::{Method, Preview, header},
};

/// Error constructing an ICAP service endpoint.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServiceEndpointError {
    /// The input is not a strict absolute URI.
    Uri(UriParseError),
    /// The URI does not satisfy ICAP service-target requirements.
    IcapUri(IcapParseError),
    /// The URI has no authority from which to derive a connector target.
    MissingAuthority,
}

impl fmt::Display for ServiceEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Uri(_) => "invalid ICAP service URI",
            Self::IcapUri(_) => "URI is not a valid ICAP service target",
            Self::MissingAuthority => "ICAP service URI has no authority",
        })
    }
}

impl std::error::Error for ServiceEndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Uri(error) => Some(error),
            Self::IcapUri(error) => Some(error),
            Self::MissingAuthority => None,
        }
    }
}

/// Error building an OPTIONS request for a service endpoint.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServiceEndpointRequestError {
    /// Additional endpoint headers contain a field managed by ICAP.
    ManagedHeader,
    /// A configured header is not valid ICAP syntax.
    Header(InvalidHeader),
    /// The owned ICAP request could not be encoded.
    Message(BuildError),
    /// The encoded request is not a valid discovery request.
    Options(OptionsRequestError),
    /// Concurrent lazy initialization completed without publishing a value.
    InitializationRace,
}

impl fmt::Display for ServiceEndpointRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ManagedHeader => "additional ICAP headers contain a managed field",
            Self::Header(_) => "invalid additional ICAP request header",
            Self::Message(_) => "invalid ICAP OPTIONS request",
            Self::Options(_) => "invalid ICAP OPTIONS discovery request",
            Self::InitializationRace => "OPTIONS request initialization did not publish a value",
        })
    }
}

impl std::error::Error for ServiceEndpointRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ManagedHeader | Self::InitializationRace => None,
            Self::Header(error) => Some(error),
            Self::Message(error) => Some(error),
            Self::Options(error) => Some(error),
        }
    }
}

impl From<InvalidHeader> for ServiceEndpointRequestError {
    fn from(error: InvalidHeader) -> Self {
        Self::Header(error)
    }
}

impl From<BuildError> for ServiceEndpointRequestError {
    fn from(error: BuildError) -> Self {
        Self::Message(error)
    }
}

impl From<OptionsRequestError> for ServiceEndpointRequestError {
    fn from(error: OptionsRequestError) -> Self {
        Self::Options(error)
    }
}

/// Configuration for one ICAP adaptation service URI.
#[derive(Clone)]
pub struct ServiceEndpoint {
    uri: Uri,
    authority: HostWithPort,
    host_header: Arc<str>,
    preview: Option<Preview>,
    allow_204: bool,
    allow_206: bool,
    allow_icap_trailers: bool,
    replay_limits: ReplayLimits,
    headers: HeaderMap,
    extensions: Extensions,
    options_partition: OptionsCachePartition,
    options_request: Arc<OnceLock<OptionsRequest>>,
}

impl fmt::Debug for ServiceEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceEndpoint")
            .field("uri", &self.uri)
            .field("authority", &self.authority)
            .field("preview", &self.preview)
            .field("allow_204", &self.allow_204)
            .field("allow_206", &self.allow_206)
            .field("allow_icap_trailers", &self.allow_icap_trailers)
            .field("replay_limits", &self.replay_limits)
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

impl ServiceEndpoint {
    /// Parse an absolute ICAP service URI and derive its connector target.
    pub fn new(uri: impl IntoUriInput) -> Result<Self, ServiceEndpointError> {
        let uri = Uri::parse_strict(uri).map_err(ServiceEndpointError::Uri)?;
        validate_icap_uri(&uri).map_err(ServiceEndpointError::IcapUri)?;
        let uri_authority = uri
            .authority()
            .ok_or(ServiceEndpointError::MissingAuthority)?;
        let host = HostWithOptPort {
            host: uri_authority.host().into_owned(),
            port: uri_authority.port(),
        }
        .canonicalize();
        let host_header: Arc<str> = Arc::from(host.to_string());
        let authority = host.into_host_with_port_or(Protocol::ICAP_DEFAULT_PORT);
        Ok(Self {
            uri,
            authority,
            host_header,
            preview: None,
            allow_204: false,
            allow_206: false,
            allow_icap_trailers: false,
            replay_limits: ReplayLimits::new(),
            headers: HeaderMap::new(),
            extensions: Extensions::new(),
            options_partition: OptionsCachePartition::new(),
            options_request: Arc::new(OnceLock::new()),
        })
    }

    /// Return the absolute ICAP service URI.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    pub(super) fn host_header(&self) -> &[u8] {
        self.host_header.as_bytes()
    }

    /// Return the ICAP server transport target.
    #[must_use]
    pub const fn authority(&self) -> &HostWithPort {
        &self.authority
    }

    /// Return additional ICAP request headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Return mutable additional ICAP request headers.
    ///
    /// Taking mutable access isolates subsequent OPTIONS cache entries from
    /// cloned endpoint configurations.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.options_partition = OptionsCachePartition::new();
        self.reset_options_request();
        &mut self.headers
    }

    generate_set_and_with! {
        /// Set the explicit OPTIONS cache identity for this endpoint.
        ///
        /// Use distinct partitions when the same URI can return different
        /// capabilities for different credentials or connector policy.
        pub fn options_cache_partition(
            mut self,
            partition: OptionsCachePartition,
        ) -> Self {
            self.options_partition = partition;
            self.reset_options_request();
            self
        }
    }

    /// Return the OPTIONS cache identity for this endpoint.
    #[must_use]
    pub const fn options_cache_partition(&self) -> &OptionsCachePartition {
        &self.options_partition
    }

    /// Return the latest connection extension of type `T`.
    #[must_use]
    pub fn connection_extension<T: Extension>(&self) -> Option<&T> {
        self.extensions.get_ref()
    }

    /// Insert a connection extension applied to later ICAP connections.
    ///
    /// Inserting isolates later OPTIONS discovery from clones of the previous
    /// endpoint configuration.
    pub fn insert_connection_extension<T: Extension>(&mut self, value: T) -> &T {
        self.options_partition = OptionsCachePartition::new();
        self.reset_options_request();
        self.extensions = self.extensions.fork();
        self.extensions.insert(value)
    }

    /// Insert a shared connection extension.
    ///
    /// Inserting isolates later OPTIONS discovery from clones of the previous
    /// endpoint configuration.
    pub fn insert_connection_extension_arc<T: Extension>(&mut self, value: Arc<T>) -> Arc<T> {
        self.options_partition = OptionsCachePartition::new();
        self.reset_options_request();
        self.extensions = self.extensions.fork();
        self.extensions.insert_arc(value)
    }

    generate_set_and_with! {
        /// Set the Preview limit used for entity-bearing messages.
        pub fn preview(mut self, preview: Option<Preview>) -> Self {
            self.preview = preview;
            self
        }
    }

    /// Return the configured Preview limit.
    #[must_use]
    pub const fn preview(&self) -> Option<Preview> {
        self.preview
    }

    generate_set_and_with! {
        /// Set whether to advertise support for 204 outside Preview.
        ///
        /// This requires retaining the complete original entity stream until
        /// the ICAP decision, so prefer Preview for large or unbounded bodies.
        pub fn allow_204(mut self, allow: bool) -> Self {
            self.allow_204 = allow;
            self.reset_options_request();
            self
        }
    }

    /// Return whether 204 is advertised outside Preview.
    #[must_use]
    pub const fn allows_204(&self) -> bool {
        self.allow_204
    }

    generate_set_and_with! {
        /// Set whether to advertise support for the 206 extension.
        ///
        /// Without OPTIONS discovery, enabling this is an explicit
        /// out-of-band trust decision. The partial-content draft recommends
        /// advertising 206 only after the service confirms it through
        /// OPTIONS.
        pub fn allow_206(mut self, allow: bool) -> Self {
            self.allow_206 = allow;
            self.reset_options_request();
            self
        }
    }

    /// Return whether the 206 extension is advertised.
    #[must_use]
    pub const fn allows_206(&self) -> bool {
        self.allow_206
    }

    generate_set_and_with! {
        /// Set whether requests offer negotiated outer ICAP response trailers.
        ///
        /// The HTTP adaptation layer consumes these fields as ICAP metadata
        /// and never exposes them as HTTP trailers. The default is `false`.
        pub fn allow_icap_trailers(mut self, allow: bool) -> Self {
            self.allow_icap_trailers = allow;
            self.reset_options_request();
            self
        }
    }

    /// Return whether outer ICAP response trailers are offered.
    #[must_use]
    pub const fn allows_icap_trailers(&self) -> bool {
        self.allow_icap_trailers
    }

    generate_set_and_with! {
        /// Set the in-memory bounds for original HTTP replay frames.
        pub const fn replay_limits(mut self, limits: ReplayLimits) -> Self {
            self.replay_limits = limits;
            self
        }
    }

    /// Return the original HTTP replay bounds.
    #[must_use]
    pub const fn replay_limits(&self) -> ReplayLimits {
        self.replay_limits
    }

    /// Build a standalone capability-discovery request for this service.
    pub fn options_request(&self) -> Result<OptionsRequest, ServiceEndpointRequestError> {
        if let Some(request) = self.options_request.get() {
            return Ok(request.clone());
        }
        let headers = self.try_request_headers_with_policy(
            &[],
            self.allow_204,
            self.allow_206,
            self.allow_icap_trailers,
        )?;
        let request = Request::new_from_source(
            RequestLineSource::prepared(Method::Options, &self.uri, self.host_header()),
            &headers,
            Some(EncapsulatedParts::null()),
        )?;
        let request = OptionsRequest::new_in_partition(
            self.options_connect_request(),
            request,
            self.options_partition.clone(),
        )?;
        match self.options_request.set(request.clone()) {
            Ok(()) => Ok(request),
            Err(_request) => self
                .options_request
                .get()
                .cloned()
                .ok_or(ServiceEndpointRequestError::InitializationRace),
        }
    }

    pub(super) fn adaptation_headers<'a>(
        &'a self,
        forwarded: &'a [ForwardedIcapHeader],
        allow_204: bool,
        allow_206: bool,
        allow_icap_trailers: bool,
    ) -> Result<Vec<Header<'a>>, BoxError> {
        self.try_request_headers_with_policy(forwarded, allow_204, allow_206, allow_icap_trailers)
            .map_err(|error| Box::new(error) as BoxError)
    }

    #[cfg(test)]
    pub(super) fn request_headers<'a>(
        &'a self,
        forwarded: &'a [ForwardedIcapHeader],
    ) -> Result<Vec<Header<'a>>, BoxError> {
        self.try_request_headers_with_policy(
            forwarded,
            self.allow_204,
            self.allow_206,
            self.allow_icap_trailers,
        )
        .map_err(|error| Box::new(error) as BoxError)
    }

    fn try_request_headers_with_policy<'a>(
        &'a self,
        forwarded: &'a [ForwardedIcapHeader],
        allow_204: bool,
        allow_206: bool,
        allow_icap_trailers: bool,
    ) -> Result<Vec<Header<'a>>, ServiceEndpointRequestError> {
        let mut fields = Vec::with_capacity(
            self.headers
                .len()
                .saturating_add(forwarded.len())
                .saturating_add(2),
        );
        for (name, value) in &self.headers {
            if [
                header::HOST,
                header::ALLOW,
                header::PREVIEW,
                header::ENCAPSULATED,
                header::PROXY_AUTHENTICATE,
                header::PROXY_AUTHORIZATION,
            ]
            .iter()
            .any(|reserved| name.as_str().eq_ignore_ascii_case(reserved))
            {
                return Err(ServiceEndpointRequestError::ManagedHeader);
            }
            fields.push(Header::new(name.as_str(), value.as_bytes())?);
        }
        for field in forwarded {
            fields.push(Header::new(field.name, field.value.as_bytes())?);
        }
        fields.push(Header::new(header::HOST, self.host_header.as_bytes())?);
        let allow = match (allow_204, allow_206, allow_icap_trailers) {
            (true, true, true) => Some(b"204, 206, trailers".as_slice()),
            (true, true, false) => Some(b"204, 206".as_slice()),
            (true, false, true) => Some(b"204, trailers".as_slice()),
            (true, false, false) => Some(b"204".as_slice()),
            (false, true, true) => Some(b"206, trailers".as_slice()),
            (false, true, false) => Some(b"206".as_slice()),
            (false, false, true) => Some(b"trailers".as_slice()),
            (false, false, false) => None,
        };
        if let Some(allow) = allow {
            fields.push(Header::new(header::ALLOW, allow)?);
        }
        Ok(fields)
    }

    pub(super) fn connect_request(&self) -> ConnectRequest {
        ConnectRequest::new_with_extensions(self.authority.clone(), self.extensions.fork())
            .with_application_protocol(Protocol::ICAP)
            .with_transport_protocol(TransportProtocol::Tcp)
    }

    fn options_connect_request(&self) -> ConnectRequest {
        ConnectRequest::new_with_extensions(self.authority.clone(), self.extensions.clone())
            .with_application_protocol(Protocol::ICAP)
            .with_transport_protocol(TransportProtocol::Tcp)
    }

    fn reset_options_request(&mut self) {
        self.options_request = Arc::new(OnceLock::new());
    }
}
