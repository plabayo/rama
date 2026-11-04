use super::{
    ConnectIpRequestError, ConnectIpRole, ConnectIpScope, ConnectIpSession, ConnectIpSessionConfig,
    ConnectIpTemplate, validate_connect_ip_response,
};
use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
    extensions::{Extensions, ExtensionsRef},
};
use rama_http::{
    HeaderMap, Request, Response, StreamingBody as _, Version, io::upgrade::handle_upgrade,
};
use rama_net::Protocol;
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

/// Prepare a CONNECT-IP handshake from a configured endpoint and typed scope.
///
/// Headers and extensions remain available for authentication and HTTP layers.
/// The method, URI, version and protocol are prepared together by the template.
/// No tunnel bytes are sent before the response is validated.
pub struct ConnectIpRequestBuilder {
    request: Request,
    config: ConnectIpSessionConfig,
    scope: ConnectIpScope,
    template: ConnectIpTemplate,
    open_timeout: std::time::Duration,
}

impl std::fmt::Debug for ConnectIpRequestBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectIpRequestBuilder")
            .field("version", &self.request.version())
            .field("open_timeout", &self.open_timeout)
            .finish_non_exhaustive()
    }
}

impl ConnectIpRequestBuilder {
    /// Prepare an empty HTTP request for this endpoint, scope and HTTP version.
    pub fn new(
        template: &ConnectIpTemplate,
        scope: &ConnectIpScope,
        version: Version,
        config: ConnectIpSessionConfig,
    ) -> Result<Self, ConnectIpRequestError> {
        Ok(Self {
            request: template.request(scope, version)?,
            config,
            scope: scope.clone(),
            template: template.clone(),
            open_timeout: std::time::Duration::from_secs(10),
        })
    }

    /// Recover a request passed through a low-level HTTP connection establishment.
    ///
    /// This escape hatch validates the complete handshake against the configured
    /// endpoint, including its scope, before it can be sent. Prefer [`Self::new`]
    /// when using an HTTP client service directly.
    pub fn try_from_request(
        template: &ConnectIpTemplate,
        request: Request,
        config: ConnectIpSessionConfig,
    ) -> Result<Self, ConnectIpRequestError> {
        if request.uri().scheme() != Some(&Protocol::HTTPS) {
            return Err(ConnectIpRequestError::Template);
        }
        let scope = template.match_request(&request)?;
        if !request.body().is_end_stream() {
            return Err(ConnectIpRequestError::Handshake);
        }
        Ok(Self {
            request,
            config,
            scope,
            template: template.clone(),
            open_timeout: std::time::Duration::from_secs(10),
        })
    }

    /// Add authentication or application headers.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.request.headers_mut()
    }

    /// Metadata consumed by HTTP client layers.
    pub fn extensions(&self) -> &Extensions {
        self.request.extensions()
    }

    generate_set_and_with! {
        /// Total handshake deadline, independent of packet write timeouts.
        /// A zero timeout refuses an opening that cannot complete immediately.
        pub fn open_timeout(mut self, timeout: std::time::Duration) -> Self {
            self.open_timeout = timeout;
            self
        }
    }

    /// Open the session with an existing Rama HTTP client.
    ///
    /// The client must honor the HTTPS URI and requested HTTP version. Response
    /// bodies remain generic: packet I/O comes from the HTTP upgrade extension.
    pub async fn connect<S, B>(mut self, client: &S) -> Result<ConnectIpSession, BoxError>
    where
        S: Service<Request, Output = Response<B>, Error: Into<BoxError>>,
        B: Send + 'static,
    {
        self.template.validate_request_head(&self.request)?;
        self.config.policy_mut().scope_protocol = self.scope.protocol;
        self.config.policy_mut().scope_targets = match self.scope.target {
            super::IpTarget::Prefix(prefix) => vec![prefix],
            super::IpTarget::Any | super::IpTarget::Hostname(_) => Vec::new(),
        };
        let version = self.request.version();
        let deadline = crate::time::expiration_at(tokio::time::Instant::now(), self.open_timeout);
        let response = tokio::time::timeout_at(deadline, client.serve(self.request))
            .await
            .map_err(|_error| super::ConnectIpError::Timeout)?
            .map_err(Into::into)
            .context("CONNECT-IP request")?;
        validate_connect_ip_response(version, &response)?;
        let upgraded = tokio::time::timeout_at(deadline, handle_upgrade(&response))
            .await
            .map_err(|_error| super::ConnectIpError::Timeout)?
            .context("CONNECT-IP upgrade")?;
        Ok(ConnectIpSession::new(
            upgraded,
            ConnectIpRole::Client,
            self.config,
        )?)
    }
}

/// Adapt an HTTP client into a service opening prepared CONNECT-IP sessions.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct ConnectIpConnector<S> {
    inner: S,
}

impl<S> ConnectIpConnector<S> {
    define_inner_service_accessors!();

    /// Wrap an HTTP client service, retaining its authentication and transport layers.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    generate_set_and_with! {
        /// Replace the HTTP client service.
        pub fn inner(mut self, inner: S) -> Self {
            self.inner = inner;
            self
        }
    }
}

impl<S, B> Service<ConnectIpRequestBuilder> for ConnectIpConnector<S>
where
    S: Service<Request, Output = Response<B>, Error: Into<BoxError>>,
    B: Send + 'static,
{
    type Output = ConnectIpSession;
    type Error = BoxError;

    async fn serve(&self, request: ConnectIpRequestBuilder) -> Result<Self::Output, Self::Error> {
        request.connect(&self.inner).await
    }
}
