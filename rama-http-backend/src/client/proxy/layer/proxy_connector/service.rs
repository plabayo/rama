use crate::client::proxy::layer::HttpProxyError;

use super::InnerHttpProxyConnector;
use pin_project_lite::pin_project;
use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _, ErrorExt},
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
    stream::Stream,
    telemetry::tracing,
};
use rama_http::{
    HeaderMap, HeaderValue,
    header::{HOST, PROXY_AUTHORIZATION},
    io::upgrade,
    proto::h1::{Http1HeaderMap, IntoHttp1HeaderName, headers::original::OriginalHttp1Headers},
};
use rama_http_headers::ProxyAuthorization;
use rama_http_types::Version;
use rama_net::{
    Protocol,
    address::ProxyAddress,
    client::{ConnectorService, EstablishedClientConnection},
    transport::TryRefIntoTransportContext,
    user::ProxyCredential,
};
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::macros::generate_set_and_with;
use std::fmt::Debug;
use std::pin::Pin;
use std::task::{self, Poll};
use std::{ops, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "tls")]
use rama_net::tls::TlsTunnel;

/// A connector which can be used to establish a connection over an HTTP Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a [`ProxyAddress`] found in the [`Extensions`].
#[derive(Debug, Clone)]
pub struct HttpProxyConnector<S> {
    pub(super) inner: S,
    pub(super) required: bool,
    pub(super) version: Option<Version>,
    pub(super) headers: Option<Http1HeaderMap>,
}

impl<S> HttpProxyConnector<S> {
    /// Creates a new [`HttpProxyConnector`].
    ///
    /// Protocol version is set to HTTP/1.1 by default.
    pub(super) fn new(inner: S, required: bool) -> Self {
        Self {
            inner,
            required,
            version: Some(Version::HTTP_11),
            headers: None,
        }
    }

    generate_set_and_with! {
        /// Set the HTTP version to use for the CONNECT request.
        ///
        /// By default this is set to HTTP/1.1.
        pub fn version(mut self, version: Version) -> Self {
            self.version = Some(version);
            self
        }
    }

    generate_set_and_with! {
        /// Append a custom header to use for the CONNECT request.
        pub fn custom_header(
            mut self,
            name: impl IntoHttp1HeaderName,
            value: HeaderValue,
        ) -> Self {
            self.headers.get_or_insert_default().append(name, value);
            self
        }
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Extensions`].
    #[must_use]
    pub fn optional(inner: S) -> Self {
        Self::new(inner, false)
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Extensions`].
    #[must_use]
    pub fn required(inner: S) -> Self {
        Self::new(inner, true)
    }

    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for HttpProxyConnector<S>
where
    S: ConnectorService<Input, Connection: Stream + Unpin>,
    Input: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + Send
        + ExtensionsMut
        + 'static,
{
    type Output = EstablishedClientConnection<MaybeHttpProxiedConnection<S::Connection>, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let proxy_info = input.extensions().get::<ProxyAddress>().cloned();
        if !proxy_info
            .as_ref()
            .and_then(|addr| addr.protocol.as_ref())
            .map(|p| p.is_http())
            .unwrap_or(true)
        {
            return Err(BoxError::from(
                "http proxy connector can only serve http protocol",
            ));
        }

        let transport_ctx = input
            .try_ref_into_transport_ctx()
            .context("http proxy connector: get transport context")?;

        #[cfg(feature = "tls")]
        let mut input = input;

        #[cfg(feature = "tls")]
        // in case the provider gave us a proxy info, we insert it into the context
        if let Some(proxy_info) = &proxy_info
            && proxy_info
                .protocol
                .as_ref()
                .map(|p| p.is_secure())
                .unwrap_or_default()
        {
            tracing::trace!(
                server.address = %proxy_info.address.host,
                server.port = proxy_info.address.port,
                "http proxy connector: preparing proxy connection for tls tunnel",
            );
            input.extensions_mut().insert(TlsTunnel {
                server_host: proxy_info.address.host.clone(),
            });
        }

        let established_conn =
            self.inner
                .connect(input)
                .await
                .map_err(|err| match proxy_info.as_ref() {
                    Some(proxy_info) => Box::new(HttpProxyError::Transport(
                        err.context("establish connection to proxy")
                            .context_field("address", proxy_info.address.clone())
                            .context_debug_field("protocol", proxy_info.protocol.clone()),
                    )),
                    None => err.context("establish connection target"),
                })?;

        // return early in case we did not use a proxy
        let Some(proxy_info) = proxy_info else {
            return if self.required {
                Err("http proxy required but none is defined".into())
            } else {
                tracing::trace!(
                    "http proxy connector: no proxy required or set: proceed with direct connection"
                );
                let EstablishedClientConnection { input, conn } = established_conn;
                return Ok(EstablishedClientConnection {
                    input,
                    conn: MaybeHttpProxiedConnection::direct(conn),
                });
            };
        };
        // and do the handshake otherwise...

        let EstablishedClientConnection { input, conn } = established_conn;

        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port,
            "http proxy connector: connected to proxy",
        );

        if !transport_ctx
            .app_protocol
            .map(|p| p.is_secure())
            // TODO: re-evaluate this fallback at some point... seems pretty flawed to me
            .unwrap_or_else(|| transport_ctx.authority.port == Some(Protocol::HTTPS_DEFAULT_PORT))
        {
            // unless the scheme is not secure, in such a case no handshake is required...
            // we do however need to add authorization headers if credentials are present
            // => for this the user has to use another middleware as we do not have access to that here
            return Ok(EstablishedClientConnection {
                input,
                conn: MaybeHttpProxiedConnection::proxied(conn),
            });
        }

        let mut connector = InnerHttpProxyConnector::new(transport_ctx.authority.clone())?;

        if let Some(version) = self.version {
            connector.set_version(version);
        }

        if let Some(credential) = proxy_info.credential.clone() {
            match credential {
                ProxyCredential::Basic(basic) => {
                    connector.set_typed_header(ProxyAuthorization(basic));
                }
                ProxyCredential::Bearer(bearer) => {
                    connector.set_typed_header(ProxyAuthorization(bearer));
                }
            }
        }

        if let Some(headers) = self.headers.clone() {
            let mut map = OriginalHttp1Headers::new();
            for (name, value) in headers.into_iter() {
                let http_name = name.header_name();
                if http_name != PROXY_AUTHORIZATION && http_name != HOST {
                    connector.set_header(http_name.clone(), value);
                }
                map.push(name);
            }
            connector.set_extension(map);
        }

        let (headers, conn) = connector
            .handshake(conn)
            .await
            .context("http proxy handshake")?;

        let mut conn = MaybeHttpProxiedConnection::upgraded_proxy(conn);

        tracing::trace!("inserting HttpProxyHeaders in context");
        conn.extensions_mut()
            .insert(HttpProxyConnectResponseHeaders::new(headers));

        tracing::trace!(
            server.address = %transport_ctx.authority.host,
            server.port = transport_ctx.authority.port,
            "http proxy connector: connected to proxy: ready secure request",
        );
        Ok(EstablishedClientConnection { input, conn })
    }
}

#[derive(Clone, Debug)]
/// Extension added to the [`Extensions`] by [`HttpProxyConnector`] to record the
/// headers from a successful CONNECT response.
///
/// This can be useful, for example, when the upstream proxy provider exposes
/// information in these headers about the connection to the final destination.
pub struct HttpProxyConnectResponseHeaders(Arc<HeaderMap>);

impl HttpProxyConnectResponseHeaders {
    fn new(headers: HeaderMap) -> Self {
        Self(Arc::new(headers))
    }
}

impl AsRef<HeaderMap> for HttpProxyConnectResponseHeaders {
    fn as_ref(&self) -> &HeaderMap {
        &self.0
    }
}

impl ops::Deref for HttpProxyConnectResponseHeaders {
    type Target = HeaderMap;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pin_project! {
    /// A connection which will be proxied if a [`ProxyAddress`] was configured
    pub struct MaybeHttpProxiedConnection<S> {
        #[pin]
        inner: Connection<S>,
    }
}

impl<S: ExtensionsMut + Unpin + Stream> MaybeHttpProxiedConnection<S> {
    fn direct(conn: S) -> Self {
        Self {
            inner: Connection::Direct { conn },
        }
    }

    fn proxied(conn: S) -> Self {
        Self {
            inner: Connection::Proxied { conn },
        }
    }

    fn upgraded_proxy(conn: upgrade::Upgraded) -> Self {
        Self {
            inner: Connection::UpgradedProxy { conn },
        }
    }
}

impl<S: Debug> Debug for MaybeHttpProxiedConnection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaybeHttpProxiedConnection")
            .field("inner", &self.inner)
            .finish()
    }
}

pin_project! {
    #[project = ConnectionProj]
    enum Connection<S> {
        Direct{ #[pin] conn: S },
        Proxied{ #[pin] conn: S },
        UpgradedProxy{ #[pin] conn: upgrade::Upgraded },
    }
}

impl<S: Debug> Debug for Connection<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct { conn } => f.debug_struct("Direct").field("conn", conn).finish(),
            Self::Proxied { conn } => f.debug_struct("Proxied").field("conn", conn).finish(),
            Self::UpgradedProxy { conn } => {
                f.debug_struct("UpgradedProxy").field("conn", conn).finish()
            }
        }
    }
}

impl<S: ExtensionsRef> ExtensionsRef for MaybeHttpProxiedConnection<S> {
    fn extensions(&self) -> &Extensions {
        match &self.inner {
            Connection::Direct { conn } | Connection::Proxied { conn } => conn.extensions(),
            Connection::UpgradedProxy { conn } => conn.extensions(),
        }
    }
}

impl<S: ExtensionsMut> ExtensionsMut for MaybeHttpProxiedConnection<S> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        match &mut self.inner {
            Connection::Direct { conn } | Connection::Proxied { conn } => conn.extensions_mut(),
            Connection::UpgradedProxy { conn } => conn.extensions_mut(),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<Conn: AsyncWrite> AsyncWrite for MaybeHttpProxiedConnection<Conn> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_write(cx, buf)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_flush(cx)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_shutdown(cx)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            Connection::Direct { conn } | Connection::Proxied { conn } => conn.is_write_vectored(),
            Connection::UpgradedProxy { conn } => conn.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_write_vectored(cx, bufs)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_write_vectored(cx, bufs),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<Conn: AsyncRead> AsyncRead for MaybeHttpProxiedConnection<Conn> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project().inner.project() {
            ConnectionProj::Direct { conn } | ConnectionProj::Proxied { conn } => {
                conn.poll_read(cx, buf)
            }
            ConnectionProj::UpgradedProxy { conn } => conn.poll_read(cx, buf),
        }
    }
}
