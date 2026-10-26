use std::fmt;

use rama_core::{
    extensions::{Extensions, ExtensionsRef as _},
    matcher::Matcher,
};
use rama_http::{
    Body, HeaderValue, Method, Request, Response, StatusCode, Version,
    datagram::{
        ViolationPolicy,
        handshake::{
            CapsuleHandshakeError, prepare_capsule_request, validate_capsule_request,
            validate_capsule_response,
        },
    },
    header,
    headers::{HeaderMapExt as _, ProxyAuthorization},
    proto::ext::Protocol,
};
use rama_net::{
    address::{ProxyAddress, ProxyPathTemplate},
    uri::{TemplateVariable, UriTemplate, UriTemplateError, UriTemplateMatcher},
    user::ProxyCredential,
};

use super::{ConnectUdpTarget, ConnectUdpTargetError};

/// Why a CONNECT-UDP request could not be built or accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectUdpRequestError {
    /// The proxy address is not a [`rama_net::Protocol::MASQUE`] proxy.
    NotMasque,
    /// The HTTP version cannot carry CONNECT-UDP (HTTP/1.0 and earlier).
    UnsupportedVersion(Version),
    /// The request is not a `connect-udp` upgrade or Extended CONNECT: not ours to answer.
    NotConnectUdp,
    /// A `connect-udp` request that breaks RFC 9298 §3.2/§3.4 or RFC 9297 §3.2: answer 400.
    Malformed(CapsuleHandshakeError),
    /// HTTP/1.1 requires `GET` and a single `Host`; HTTP/2 and HTTP/3 a path: answer 400.
    MalformedRequestLine,
    /// The request path does not match the proxy's template: answer 404.
    TemplateMismatch,
    /// The template values do not form a target: answer 400.
    InvalidTarget(ConnectUdpTargetError),
    /// The proxy's request URI could not be built.
    InvalidUri,
}

impl fmt::Display for ConnectUdpRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMasque => f.write_str("proxy address is not a masque proxy"),
            Self::UnsupportedVersion(version) => {
                write!(f, "{version:?} cannot carry connect-udp")
            }
            Self::NotConnectUdp => f.write_str("request is not a connect-udp request"),
            Self::Malformed(err) => write!(f, "malformed connect-udp request: {err}"),
            Self::MalformedRequestLine => {
                f.write_str("malformed connect-udp request line or authority")
            }
            Self::TemplateMismatch => {
                f.write_str("connect-udp request does not match the proxy template")
            }
            Self::InvalidTarget(err) => write!(f, "invalid connect-udp target: {err}"),
            Self::InvalidUri => f.write_str("connect-udp request uri could not be built"),
        }
    }
}

impl std::error::Error for ConnectUdpRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(err) => Some(err),
            Self::InvalidTarget(err) => Some(err),
            _ => None,
        }
    }
}

impl ConnectUdpRequestError {
    /// The status a proxy answers with, or `None` when the request is not CONNECT-UDP.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::NotConnectUdp => None,
            Self::TemplateMismatch => Some(StatusCode::NOT_FOUND),
            Self::NotMasque | Self::InvalidUri => Some(StatusCode::INTERNAL_SERVER_ERROR),
            Self::UnsupportedVersion(_)
            | Self::Malformed(_)
            | Self::MalformedRequestLine
            | Self::InvalidTarget(_) => Some(StatusCode::BAD_REQUEST),
        }
    }
}

/// Build the CONNECT-UDP request opening a tunnel to `target` through `proxy`.
///
/// HTTP/1.1 gets `GET` with `Upgrade: connect-udp`, HTTP/2 and HTTP/3 Extended
/// CONNECT (RFC 9298 §3.2, §3.4); both carry `Capsule-Protocol: ?1` and no
/// content. Proxy credentials become `Proxy-Authorization`.
pub fn connect_udp_request(
    proxy: &ProxyAddress,
    target: &ConnectUdpTarget,
    version: Version,
) -> Result<Request<Body>, ConnectUdpRequestError> {
    if !proxy
        .protocol
        .as_ref()
        .is_some_and(rama_net::Protocol::is_masque)
    {
        return Err(ConnectUdpRequestError::NotMasque);
    }
    let mut uri = String::with_capacity(96);
    uri.push_str("https://");
    uri.push_str(&proxy.address.to_string());
    match &proxy.template {
        Some(template) => template.expand_target_to(&mut uri, &target.host, target.port.get()),
        None => ProxyPathTemplate::expand_connect_udp_default_to(
            &mut uri,
            &target.host,
            target.port.get(),
        ),
    }
    let mut request = Request::builder()
        .version(version)
        .uri(uri.as_str())
        .body(Body::empty())
        .map_err(|_error| ConnectUdpRequestError::InvalidUri)?;
    if version == Version::HTTP_11 {
        let host = HeaderValue::try_from(proxy.address.to_string())
            .map_err(|_error| ConnectUdpRequestError::InvalidUri)?;
        request.headers_mut().insert(header::HOST, host);
    }
    prepare_capsule_request(&mut request, Protocol::CONNECT_UDP).map_err(|err| match err {
        CapsuleHandshakeError::UnsupportedVersion(version) => {
            ConnectUdpRequestError::UnsupportedVersion(version)
        }
        err => ConnectUdpRequestError::Malformed(err),
    })?;
    match &proxy.credential {
        Some(ProxyCredential::Basic(basic)) => request
            .headers_mut()
            .typed_insert(ProxyAuthorization(basic.clone())),
        Some(ProxyCredential::Bearer(bearer)) => request
            .headers_mut()
            .typed_insert(ProxyAuthorization(bearer.clone())),
        None => {}
    }
    Ok(request)
}

/// Check a proxy's answer to a CONNECT-UDP request (RFC 9298 §3.3, §3.5).
///
/// HTTP/1.1 requires `101` switching to `connect-udp`; HTTP/2 and HTTP/3 a 2xx
/// other than 204, 205 and 206. Responses carrying content framing are refused.
pub fn validate_connect_udp_response<B>(
    version: Version,
    response: &Response<B>,
) -> Result<(), CapsuleHandshakeError> {
    validate_capsule_response(
        version,
        &Protocol::CONNECT_UDP,
        response,
        ViolationPolicy::Reject,
    )
}

/// Recognises CONNECT-UDP requests for a proxy template and extracts their target.
#[derive(Debug, Clone)]
pub struct ConnectUdpRequestMatcher {
    matcher: UriTemplateMatcher,
    target_host: TemplateVariable,
    target_port: TemplateVariable,
}

impl ConnectUdpRequestMatcher {
    /// A matcher for `template`, or for the RFC 9298 default template when `None`.
    pub fn try_new(template: Option<&ProxyPathTemplate>) -> Result<Self, UriTemplateError> {
        let default;
        let template = if let Some(template) = template {
            template
        } else {
            default = ProxyPathTemplate::try_new(ProxyPathTemplate::CONNECT_UDP_DEFAULT)
                .map_err(|_error| UriTemplateError::NotMatchable("invalid default template"))?;
            &default
        };
        Ok(Self {
            matcher: UriTemplateMatcher::try_new(template.template())?,
            target_host: template.target_host(),
            target_port: template.target_port(),
        })
    }

    /// The template requests are matched against.
    #[must_use]
    pub fn template(&self) -> &UriTemplate {
        self.matcher.template()
    }

    /// Classify a request and extract its target.
    ///
    /// [`ConnectUdpRequestError::NotConnectUdp`] means the request is something
    /// else and should be routed elsewhere; every other error says how to refuse it
    /// ([`ConnectUdpRequestError::status`]).
    pub fn match_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<ConnectUdpTarget, ConnectUdpRequestError> {
        let version = request.version();
        if !matches!(
            version,
            Version::HTTP_11 | Version::HTTP_2 | Version::HTTP_3
        ) {
            return Err(ConnectUdpRequestError::NotConnectUdp);
        }
        let protocol = match validate_capsule_request(request, ViolationPolicy::Reject) {
            Ok(protocol) => protocol,
            Err(CapsuleHandshakeError::NotAnUpgrade) => {
                return Err(ConnectUdpRequestError::NotConnectUdp);
            }
            Err(err) => {
                return if request_names_connect_udp(request) {
                    Err(ConnectUdpRequestError::Malformed(err))
                } else {
                    Err(ConnectUdpRequestError::NotConnectUdp)
                };
            }
        };
        if !protocol
            .as_str()
            .eq_ignore_ascii_case(Protocol::CONNECT_UDP.as_str())
        {
            return Err(ConnectUdpRequestError::NotConnectUdp);
        }
        if version == Version::HTTP_11
            && (request.method() != Method::GET
                || request.headers().get_all(header::HOST).iter().count() != 1)
        {
            return Err(ConnectUdpRequestError::MalformedRequestLine);
        }
        let uri = request.uri();
        let Some(path) = uri.path().filter(|path| !path.is_empty()) else {
            return Err(ConnectUdpRequestError::MalformedRequestLine);
        };
        let path = path.as_encoded_str();
        let query = uri.query().map(|query| query.as_encoded_str());
        let captures = self
            .matcher
            .captures(&path, query.as_deref())
            .ok_or(ConnectUdpRequestError::TemplateMismatch)?;
        ConnectUdpTarget::from_template_values(
            captures.get(self.target_host).unwrap_or_default(),
            captures.get(self.target_port).unwrap_or_default(),
        )
        .map_err(ConnectUdpRequestError::InvalidTarget)
    }
}

/// Routes every CONNECT-UDP request, malformed or for another template too, so the
/// proxy answers it ([`ConnectUdpRequestError::status`]); everything else passes by.
impl<B: Send + 'static> Matcher<Request<B>> for ConnectUdpRequestMatcher {
    fn matches(&self, _ext: Option<&Extensions>, request: &Request<B>) -> bool {
        !matches!(
            self.match_request(request),
            Err(ConnectUdpRequestError::NotConnectUdp)
        )
    }
}

pub(super) fn request_names_connect_udp<B>(request: &Request<B>) -> bool {
    request
        .extensions()
        .get_ref::<Protocol>()
        .is_some_and(|protocol| {
            protocol
                .as_str()
                .eq_ignore_ascii_case(Protocol::CONNECT_UDP.as_str())
        })
        || request
            .headers()
            .get_all(header::UPGRADE)
            .iter()
            .any(|value| {
                value
                    .as_bytes()
                    .trim_ascii()
                    .eq_ignore_ascii_case(b"connect-udp")
            })
}

#[cfg(test)]
mod tests;
