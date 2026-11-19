//! Client Http Proxy Connector
//!
//! As defined in <https://github.com/plabayo/rama/blob/main/rama-http-core/specifications/rfc9112.txt>.

use super::HttpProxyError;
use rama_core::error::{BoxError, ErrorContext};
use rama_http::HeaderMap;
use rama_http::io::upgrade::{self, Upgraded};
use rama_http_headers::{HeaderMapExt, Host, HttpRequestBuilderExt, ProxyAuthorization, UserAgent};
use rama_http_types::{Method, Request, Response, StatusCode, Version};
use rama_net::address::{HostWithOptPort, HostWithPort};
use rama_net::uri::Uri;
use rama_net::user::ProxyCredential;

/// Build the CONNECT request which opens a tunnel to `target`.
///
/// `version` is the version spoken to the proxy; the connection it is sent on has to
/// speak that same version.
pub(super) fn connect_request<B: Default>(
    target: HostWithPort,
    credential: Option<&ProxyCredential>,
    version: Version,
) -> Result<Request<B>, BoxError> {
    let authority = HostWithOptPort::from(target);
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(version)
        // CONNECT request-target is authority-form (`host:port`); build it as
        // such. `.uri(string)` would parse it as `scheme:path` and reject the
        // host (e.g. `127.0.0.1`) as an invalid scheme.
        .uri(Uri::from_authority_form(authority.clone().into()))
        .typed_header(Host::from(authority))
        .typed_header(UserAgent::rama())
        .body(B::default())
        .context("build CONNECT request")?;

    match credential {
        Some(ProxyCredential::Basic(basic)) => {
            request
                .headers_mut()
                .typed_insert(ProxyAuthorization(basic.clone()));
        }
        Some(ProxyCredential::Bearer(bearer)) => {
            request
                .headers_mut()
                .typed_insert(ProxyAuthorization(bearer.clone()));
        }
        None => {}
    }

    Ok(request)
}

/// Turn the proxy's answer to [`connect_request`] into the tunnel it promised.
pub(super) async fn upgrade_connect_response(
    response: Response,
) -> Result<(HeaderMap, Upgraded), HttpProxyError> {
    match response.status() {
        status if status.is_success() => upgrade::handle_upgrade(&response)
            .await
            .map(|upgraded| {
                let (parts, _) = response.into_parts();
                (parts.headers, upgraded)
            })
            .map_err(HttpProxyError::Transport),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED => Err(HttpProxyError::AuthRequired),
        StatusCode::SERVICE_UNAVAILABLE => Err(HttpProxyError::Unavailable),
        StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => {
            Err(HttpProxyError::UpstreamFailure(response.status()))
        }
        status => Err(HttpProxyError::Rejected(status)),
    }
}
