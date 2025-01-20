//! Client Http Proxy Connector
//!
//! As defined in <https://www.ietf.org/rfc/rfc2068.txt>.

use rama_core::error::{ErrorContext, OpaqueError};
use rama_http_core::{client::conn::http1, upgrade};
use rama_http_types::{
    header::{HOST, USER_AGENT},
    headers::{Header, HeaderMapExt},
    Body, HeaderName, HeaderValue, Method, Request, StatusCode, Version,
};
use rama_net::{address::Authority, stream::Stream};

use super::HttpProxyError;

#[derive(Debug)]
/// Connector for HTTP proxies.
///
/// Used to connect as a client to a HTTP proxy server.
pub(super) struct InnerHttpProxyConnector {
    req: Request,
}

impl InnerHttpProxyConnector {
    /// Create a new [`InnerHttpProxyConnector`] with the given authority.
    pub(super) fn new(authority: Authority) -> Result<Self, OpaqueError> {
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

    #[expect(unused)]
    /// Add a header to the request.
    pub(super) fn with_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.req.headers_mut().insert(name, value);
        self
    }

    /// Add a typed header to the request.
    pub(super) fn with_typed_header(&mut self, header: impl Header) -> &mut Self {
        self.req.headers_mut().typed_insert(header);
        self
    }

    /// Connect to the proxy server.
    pub(super) async fn handshake<S: Stream + Unpin>(
        self,
        stream: S,
    ) -> Result<upgrade::Upgraded, HttpProxyError> {
        let (tx, conn) = http1::Builder::default()
            .ignore_invalid_headers(true)
            .handshake(stream)
            .await
            .map_err(|err| HttpProxyError::Transport(err.into()))?;

        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                tracing::debug!(?err, "http upgrade proxy client conn failed");
            }
        });

        let response = tx
            .send_request(self.req)
            .await
            .map_err(|err| HttpProxyError::Transport(OpaqueError::from_std(err).into_boxed()))?;

        match response.status() {
            StatusCode::OK => upgrade::on(response)
                .await
                .map_err(|err| HttpProxyError::Transport(OpaqueError::from_std(err).into_boxed())),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => Err(HttpProxyError::AuthRequired),
            StatusCode::SERVICE_UNAVAILABLE => Err(HttpProxyError::Unavailable),
            status => Err(HttpProxyError::Other(format!(
                "invalid http proxy conn handshake: status={status}",
            ))),
        }
    }
}
