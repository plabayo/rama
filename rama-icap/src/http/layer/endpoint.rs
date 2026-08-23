use std::{fmt, sync::Arc};

use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
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
    codec::{Header, validate_icap_uri},
    http::ReplayLimits,
    proto::{Preview, header},
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
        let uri =
            Uri::parse_strict(uri).map_err(|error| error.context("parse ICAP service URI"))?;
        validate_icap_uri(&uri).map_err(|error| error.context("validate ICAP service URI"))?;
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
    pub const fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
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
        pub const fn allow_204(mut self, allow: bool) -> Self {
            self.allow_204 = allow;
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
        pub const fn allow_206(mut self, allow: bool) -> Self {
            self.allow_206 = allow;
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

    pub(super) fn request_headers<'a>(
        &'a self,
        forwarded: &'a [ForwardedIcapHeader],
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
                    .map_err(|error| error.context("build additional ICAP request header"))?,
            );
        }
        for field in forwarded {
            fields.push(
                Header::new(field.name, field.value.as_bytes())
                    .map_err(|error| error.context("build forwarded ICAP request header"))?,
            );
        }
        fields.push(
            Header::new(header::HOST, self.host_header.as_bytes())
                .map_err(|error| error.context("build ICAP Host header"))?,
        );
        let allow = match (self.allow_204, self.allow_206) {
            (true, true) => Some(b"204, 206".as_slice()),
            (true, false) => Some(b"204".as_slice()),
            (false, true) => Some(b"206".as_slice()),
            (false, false) => None,
        };
        if let Some(allow) = allow {
            fields.push(
                Header::new(header::ALLOW, allow)
                    .map_err(|error| error.context("build ICAP Allow header"))?,
            );
        }
        Ok(fields)
    }

    pub(super) fn connect_request(&self) -> ConnectRequest {
        ConnectRequest::new_with_extensions(self.authority.clone(), self.extensions.fork())
            .with_application_protocol(Protocol::ICAP)
            .with_transport_protocol(TransportProtocol::Tcp)
    }
}

impl ExtensionsRef for ServiceEndpoint {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
