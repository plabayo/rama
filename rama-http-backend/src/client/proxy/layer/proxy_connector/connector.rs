//! Client Http Proxy Connector
//!
//! As defined in <https://www.ietf.org/rfc/rfc2068.txt>.

use super::HttpProxyError;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_core::extensions::ExtensionsMut;
use rama_core::rt::Executor;
use rama_core::stream::Stream;
use rama_core::telemetry::tracing;
use rama_http::HeaderMap;
use rama_http::io::upgrade;
use rama_http_core::body::Incoming;
use rama_http_core::client::conn::{http1, http2};
use rama_http_headers::{HeaderEncode, HeaderMapExt};
use rama_http_types::Response;
use rama_http_types::{
    Body, HeaderName, HeaderValue, Method, Request, StatusCode, Version,
    header::{HOST, USER_AGENT},
};
use rama_net::address::Authority;

#[derive(Debug)]
/// Connector for HTTP proxies.
///
/// Used to connect as a client to a HTTP proxy server.
pub(super) struct InnerHttpProxyConnector {
    req: Request,
}

impl InnerHttpProxyConnector {
    /// Create a new [`InnerHttpProxyConnector`] with the given authority.
    pub(super) fn new(authority: &Authority) -> Result<Self, OpaqueError> {
        let uri = authority.to_string();
        let host_value: HeaderValue = uri.parse().context("parse authority as header value")?;

        let req = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri(uri)
            .header(HOST, host_value)
            .header(
                USER_AGENT,
                HeaderValue::from_static(const_format::formatcp!(
                    "{}/{}",
                    rama_utils::info::NAME,
                    rama_utils::info::VERSION,
                )),
            )
            .body(Body::empty())
            .context("build http request")?;

        Ok(Self { req })
    }

    pub(super) fn set_version(&mut self, version: Version) -> &mut Self {
        *self.req.version_mut() = version;
        self
    }

    /// Add a header to the request.
    pub(super) fn with_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.req.headers_mut().insert(name, value);
        self
    }

    /// Add a header to the request.
    pub(super) fn with_extension<E: Clone + Send + Sync + 'static>(
        &mut self,
        value: E,
    ) -> &mut Self {
        self.req.extensions_mut().insert(value);
        self
    }

    /// Add a typed header to the request.
    pub(super) fn with_typed_header(&mut self, header: impl HeaderEncode) -> &mut Self {
        self.req.headers_mut().typed_insert(header);
        self
    }

    /// Connect to the proxy server.
    pub(super) async fn handshake<S: Stream + ExtensionsMut + Unpin>(
        self,
        stream: S,
    ) -> Result<(HeaderMap, upgrade::Upgraded), HttpProxyError> {
        let response = match self.req.version() {
            Version::HTTP_10 | Version::HTTP_11 => Self::handshake_h1(self.req, stream).await?,
            Version::HTTP_2 => Self::handshake_h2(self.req, stream).await?,
            version => {
                return Err(HttpProxyError::Other(format!(
                    "invalid http version: {version:?}",
                )));
            }
        };

        match response.status() {
            StatusCode::OK => upgrade::handle_upgrade(&response)
                .await
                .map(|upgraded| {
                    let (parts, _) = response.into_parts();
                    (parts.headers, upgraded)
                })
                .map_err(|err| HttpProxyError::Transport(OpaqueError::from_std(err).into_boxed())),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => Err(HttpProxyError::AuthRequired),
            StatusCode::SERVICE_UNAVAILABLE => Err(HttpProxyError::Unavailable),
            status => Err(HttpProxyError::Other(format!(
                "invalid http proxy conn handshake: status={status}",
            ))),
        }
    }

    async fn handshake_h1<S: Stream + ExtensionsMut + Unpin>(
        req: Request,
        stream: S,
    ) -> Result<Response<Incoming>, HttpProxyError> {
        let (mut tx, conn) = http1::Builder::default()
            .ignore_invalid_headers(true)
            .handshake(stream)
            .await
            .map_err(|err| HttpProxyError::Transport(err.into()))?;

        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                tracing::debug!("http upgrade proxy client conn failed: {err:?}");
            }
        });

        tx.send_request(req)
            .await
            .map_err(|err| HttpProxyError::Transport(OpaqueError::from_std(err).into_boxed()))
    }

    async fn handshake_h2<S: Stream + ExtensionsMut + Unpin>(
        req: Request,
        stream: S,
    ) -> Result<Response<Incoming>, HttpProxyError> {
        let (mut tx, conn) = http2::Builder::new(Executor::new())
            .handshake(stream)
            .await
            .map_err(|err| HttpProxyError::Transport(err.into()))?;

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!("http2 proxy client conn failed: {err:?}");
            }
        });

        tx.send_request(req)
            .await
            .map_err(|err| HttpProxyError::Transport(OpaqueError::from_std(err).into_boxed()))
    }
}
