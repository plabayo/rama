//! Client Http Proxy Connector
//!
//! As defined in <https://www.ietf.org/rfc/rfc2068.txt>.

use std::fmt::Debug;

use super::HttpProxyError;
use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::ExtensionsMut;
use rama_core::rt::Executor;
use rama_core::stream::Stream;
use rama_core::telemetry::tracing;
use rama_http::HeaderMap;
use rama_http::io::upgrade;
use rama_http_core::body::Incoming;
use rama_http_core::client::conn::{http1, http2};
use rama_http_headers::{HeaderEncode, HeaderMapExt, Host, HttpRequestBuilderExt, UserAgent};
use rama_http_types::Response;
use rama_http_types::{Body, HeaderName, HeaderValue, Method, Request, StatusCode, Version};
use rama_net::address::HostWithOptPort;

#[derive(Debug)]
/// Connector for HTTP proxies.
///
/// Used to connect as a client to a HTTP proxy server.
pub(super) struct InnerHttpProxyConnector {
    req: Request,
}

impl InnerHttpProxyConnector {
    /// Create a new [`InnerHttpProxyConnector`] with the given authority.
    pub(super) fn new(authority: HostWithOptPort) -> Result<Self, BoxError> {
        let uri = authority.to_string();

        let req = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .uri(uri)
            .typed_header(Host::from(authority))
            .typed_header(UserAgent::rama())
            .body(Body::empty())
            .context("build http request")?;

        Ok(Self { req })
    }

    rama_utils::macros::generate_set_and_with! {
        pub(super) fn version(mut self, version: Version) -> Self {
            *self.req.version_mut() = version;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add a header to the request.
        pub(super) fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
            self.req.headers_mut().insert(name, value);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add a header to the request.
        pub(super) fn extension(
            mut self,
            value: impl Clone + Send + Sync + Debug + 'static,
        ) -> Self {
            self.req.extensions_mut().insert(value);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add a typed header to the request.
        pub(super) fn typed_header(mut self, header: impl HeaderEncode) -> Self {
            self.req.headers_mut().typed_insert(header);
            self
        }
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
                .map_err(|err| HttpProxyError::Transport(BoxError::from(err))),
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
            .with_ignore_invalid_headers(true)
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
            .map_err(|err| HttpProxyError::Transport(BoxError::from(err)))
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
            .map_err(|err| HttpProxyError::Transport(BoxError::from(err)))
    }
}
