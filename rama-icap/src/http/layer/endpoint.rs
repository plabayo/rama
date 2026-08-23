use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::{Extensions, ExtensionsRef},
};
use rama_http_types::HeaderMap;
use rama_net::{
    Protocol,
    address::{HostWithOptPort, HostWithPort},
    client::ConnectRequest,
    transport::TransportProtocol,
    uri::{IntoUriInput, Uri},
};
use rama_utils::macros::generate_set_and_with;

use super::headers::ForwardedIcapHeader;
use crate::{
    client::options::{OptionsCachePartition, OptionsRequest},
    codec::{Header, RequestLineSource, validate_icap_uri},
    http::ReplayLimits,
    message::{EncapsulatedParts, Request},
    proto::{Method, Preview, header},
};

/// Configuration for one ICAP adaptation service URI.
#[derive(Clone)]
pub struct ServiceEndpoint {
    uri: Uri,
    authority: HostWithPort,
    host_header: Arc<str>,
    preview: Option<Preview>,
    allow_204: bool,
    allow_206: bool,
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
            .field("replay_limits", &self.replay_limits)
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

impl ServiceEndpoint {
    /// Parse an absolute ICAP service URI and derive its connector target.
    pub fn new(uri: impl IntoUriInput) -> Result<Self, BoxError> {
        let uri = Uri::parse_strict(uri).context("parse ICAP service URI")?;
        validate_icap_uri(&uri).context("validate ICAP service URI")?;
        let uri_authority = uri
            .authority()
            .context("ICAP service URI has no authority")?;
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
        /// capabilities for different credentials or connector policy. Set a
        /// fresh partition after changing connection extensions on an
        /// endpoint that has already performed discovery.
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
    pub fn options_request(&self) -> Result<OptionsRequest, BoxError> {
        if let Some(request) = self.options_request.get() {
            return Ok(request.clone());
        }
        let headers = self.request_headers(&[])?;
        let request = Request::new_from_source(
            RequestLineSource::prepared(Method::Options, &self.uri, self.host_header()),
            &headers,
            Some(EncapsulatedParts::null()),
        )
        .context("build ICAP OPTIONS request")?;
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
                .context("OPTIONS request initialization raced without a result"),
        }
    }

    pub(super) fn adaptation_headers<'a>(
        &'a self,
        forwarded: &'a [ForwardedIcapHeader],
        allow_204: bool,
        allow_206: bool,
    ) -> Result<Vec<Header<'a>>, BoxError> {
        self.request_headers_with_policy(forwarded, allow_204, allow_206)
    }

    pub(super) fn request_headers<'a>(
        &'a self,
        forwarded: &'a [ForwardedIcapHeader],
    ) -> Result<Vec<Header<'a>>, BoxError> {
        self.request_headers_with_policy(forwarded, self.allow_204, self.allow_206)
    }

    fn request_headers_with_policy<'a>(
        &'a self,
        forwarded: &'a [ForwardedIcapHeader],
        allow_204: bool,
        allow_206: bool,
    ) -> Result<Vec<Header<'a>>, BoxError> {
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
                return Err(BoxError::from_static_str(
                    "additional ICAP headers contain a managed field",
                ));
            }
            fields.push(
                Header::new(name.as_str(), value.as_bytes())
                    .context("build additional ICAP request header")?,
            );
        }
        for field in forwarded {
            fields.push(
                Header::new(field.name, field.value.as_bytes())
                    .context("build forwarded ICAP request header")?,
            );
        }
        fields.push(
            Header::new(header::HOST, self.host_header.as_bytes())
                .context("build ICAP Host header")?,
        );
        let allow = match (allow_204, allow_206) {
            (true, true) => Some(b"204, 206".as_slice()),
            (true, false) => Some(b"204".as_slice()),
            (false, true) => Some(b"206".as_slice()),
            (false, false) => None,
        };
        if let Some(allow) = allow {
            fields.push(Header::new(header::ALLOW, allow).context("build ICAP Allow header")?);
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

impl ExtensionsRef for ServiceEndpoint {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
