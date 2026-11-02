use rama_core::extensions::ExtensionsRef as _;
use rama_http::{
    Body, HeaderValue, Method, Request, Response, Version,
    conn::TargetHttpVersion,
    datagram::{
        ViolationPolicy,
        handshake::{prepare_capsule_request, validate_capsule_request, validate_capsule_response},
    },
    header,
    proto::ext::{HttpDatagrams, Protocol},
};
use rama_net::{
    address::{Authority, AuthorityRef, Domain, ip::ipnet::IpNet},
    ip::IpProtocol,
    uri::{TemplateOperator, Uri, UriTemplate, UriTemplateMatcher},
};
use std::{fmt, net::IpAddr};

/// Requested destination scope. A name is resolved once under server policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpTarget {
    /// Any destination authorized by local policy.
    Any,
    /// A single address or canonical destination prefix.
    Prefix(IpNet),
    /// Addresses returned by an authorized, bounded DNS lookup.
    Hostname(Domain),
}

impl fmt::Display for IpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Prefix(p) => p.fmt(f),
            Self::Hostname(d) => d.fmt(f),
        }
    }
}

/// Destination and protocol requested by the client, before local authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectIpScope {
    /// Requested destination range/name.
    pub target: IpTarget,
    /// `None` means wildcard; `Some(0)` is a real next-header number, not wildcard.
    /// IPv6 extension-header numbers require an explicit IPv4 prefix target;
    /// IPv6 scopes select the protocol after the extension chain (RFC 9484 section 4.8).
    pub protocol: Option<IpProtocol>,
}

impl Default for ConnectIpScope {
    fn default() -> Self {
        Self {
            target: IpTarget::Any,
            protocol: None,
        }
    }
}

impl ConnectIpScope {
    /// Request a typed destination and optional IP protocol.
    /// Prefixes are normalized to their network address.
    #[must_use]
    pub fn new(target: IpTarget, protocol: Option<IpProtocol>) -> Self {
        let target = match target {
            IpTarget::Prefix(prefix) => IpTarget::Prefix(prefix.trunc()),
            target => target,
        };
        Self { target, protocol }
    }

    /// Parse decoded URI-template values. Missing variables are wildcards;
    /// present-but-empty values are invalid.
    pub fn from_template_values(
        target: Option<&str>,
        protocol: Option<&str>,
    ) -> Result<Self, ConnectIpRequestError> {
        let target = match target.unwrap_or("*") {
            "*" => IpTarget::Any,
            "" => return Err(ConnectIpRequestError::Scope),
            s if s.contains('/') => {
                let p: IpNet = s.parse().map_err(|_error| ConnectIpRequestError::Scope)?;
                if p.addr() != p.network() {
                    return Err(ConnectIpRequestError::Scope);
                }
                IpTarget::Prefix(p)
            }
            s => {
                if !s.is_ascii() || s.contains('%') || s.contains('[') || s.contains(']') {
                    return Err(ConnectIpRequestError::Scope);
                }
                if let Ok(ip) = s.parse::<IpAddr>() {
                    IpTarget::Prefix(IpNet::from(ip))
                } else {
                    IpTarget::Hostname(
                        Domain::try_from(s).map_err(|_error| ConnectIpRequestError::Scope)?,
                    )
                }
            }
        };
        let protocol = match protocol.unwrap_or("*") {
            "*" => None,
            s if !s.is_empty() && s.len() <= 3 && s.bytes().all(|c| c.is_ascii_digit()) => Some(
                IpProtocol::new(s.parse().map_err(|_error| ConnectIpRequestError::Scope)?),
            ),
            _ => return Err(ConnectIpRequestError::Scope),
        };
        let scope = Self { target, protocol };
        scope.check_protocol_scope()?;
        Ok(scope)
    }

    fn check_protocol_scope(&self) -> Result<(), ConnectIpRequestError> {
        if self.protocol.is_some_and(IpProtocol::is_ipv6_extension)
            && !matches!(self.target, IpTarget::Prefix(IpNet::V4(_)))
        {
            return Err(ConnectIpRequestError::Scope);
        }
        Ok(())
    }
}

/// A configuration or HTTP handshake error. Peer-controlled values are not echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectIpRequestError {
    /// Invalid/non-HTTPS template, missing path, or forbidden expansion operator.
    Template,
    /// Invalid target or protocol scope.
    Scope,
    /// The template cannot express the requested restriction.
    ScopeNotRepresentable,
    /// HTTP request/response violates the Capsule handshake.
    Handshake,
    /// Request authority, scheme or path does not match this endpoint.
    Mismatch,
}

impl fmt::Display for ConnectIpRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Template => "invalid CONNECT-IP URI template",
            Self::Scope => "invalid CONNECT-IP scope",
            Self::ScopeNotRepresentable => "CONNECT-IP scope cannot be represented by the template",
            Self::Handshake => "invalid CONNECT-IP handshake",
            Self::Mismatch => "CONNECT-IP request does not match the endpoint",
        })
    }
}

impl std::error::Error for ConnectIpRequestError {}

/// A configured CONNECT-IP HTTPS URI template, shared by clients and server matchers.
///
/// The authority is fixed. Template variables occur only in path/query; additional
/// application variables can be supplied with [`Self::request_with`].
#[derive(Debug, Clone)]
pub struct ConnectIpTemplate {
    template: UriTemplate,
    matcher: UriTemplateMatcher,
    authority: Authority,
}

impl ConnectIpTemplate {
    /// Parse an absolute HTTPS template, applying RFC 9484 §3 restrictions.
    pub fn try_new(input: impl AsRef<str>) -> Result<Self, ConnectIpRequestError> {
        let input = input.as_ref();
        if !input
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        {
            return Err(ConnectIpRequestError::Template);
        }
        let rest = &input[8..];
        let slash = rest.find('/').ok_or(ConnectIpRequestError::Template)?;
        let authority = &rest[..slash];
        if authority.is_empty() || authority.contains(['{', '}', '@', '?', '#']) {
            return Err(ConnectIpRequestError::Template);
        }
        let endpoint: Uri = format!("https://{authority}/")
            .parse()
            .map_err(|_error| ConnectIpRequestError::Template)?;
        let authority = endpoint
            .authority()
            .ok_or(ConnectIpRequestError::Template)?
            .into_owned();
        let path = &rest[slash..];
        if path.contains('#') {
            return Err(ConnectIpRequestError::Template);
        }
        let template =
            UriTemplate::try_new(input).map_err(|_error| ConnectIpRequestError::Template)?;
        if template.operators().any(|op| {
            !matches!(
                op,
                TemplateOperator::Simple
                    | TemplateOperator::Query
                    | TemplateOperator::QueryContinuation
            )
        }) {
            return Err(ConnectIpRequestError::Template);
        }
        let path_template =
            UriTemplate::try_new(path).map_err(|_error| ConnectIpRequestError::Template)?;
        let matcher = UriTemplateMatcher::try_new(&path_template)
            .map_err(|_error| ConnectIpRequestError::Template)?;
        Ok(Self {
            template,
            matcher,
            authority,
        })
    }

    /// Original absolute URI template.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.template.as_str()
    }

    /// Build a request; unprovided application variables are omitted by RFC 6570.
    pub fn request(
        &self,
        scope: &ConnectIpScope,
        version: Version,
    ) -> Result<Request, ConnectIpRequestError> {
        self.request_with(scope, version, |_| None)
    }

    /// Build a request with additional template-variable values.
    ///
    /// Credentials can be added to the request by the caller or an authentication
    /// layer. No packets may be sent until the client has accepted the response.
    pub fn request_with<'v>(
        &self,
        scope: &ConnectIpScope,
        version: Version,
        variable: impl Fn(&str) -> Option<&'v str>,
    ) -> Result<Request, ConnectIpRequestError> {
        scope.check_protocol_scope()?;
        if self.template.variable("target").is_none() && scope.target != IpTarget::Any
            || self.template.variable("ipproto").is_none() && scope.protocol.is_some()
        {
            return Err(ConnectIpRequestError::ScopeNotRepresentable);
        }
        let target = scope.target.to_string();
        let protocol = scope
            .protocol
            .map_or_else(|| "*".to_owned(), |p| p.to_string());
        if let IpTarget::Prefix(prefix) = scope.target
            && prefix.addr() != prefix.network()
        {
            return Err(ConnectIpRequestError::Scope);
        }
        let expanded = self
            .template
            .expand(|v| match self.template.variable_name(v) {
                Some("target") => Some(target.as_str()),
                Some("ipproto") => Some(protocol.as_str()),
                Some(name) => variable(name),
                None => None,
            });
        let mut request = Request::builder()
            .version(version)
            .uri(expanded)
            .body(Body::empty())
            .map_err(|_error| ConnectIpRequestError::Template)?;
        if version == Version::HTTP_11 {
            request.headers_mut().insert(
                header::HOST,
                HeaderValue::try_from(self.authority.to_string())
                    .map_err(|_error| ConnectIpRequestError::Template)?,
            );
        }
        prepare_capsule_request(&mut request, Protocol::CONNECT_IP)
            .map_err(|_error| ConnectIpRequestError::Handshake)?;
        request.extensions().insert(HttpDatagrams);
        request.extensions().insert(TargetHttpVersion(version));
        Ok(request)
    }

    /// Validate a handshake and extract its requested scope.
    pub fn match_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<ConnectIpScope, ConnectIpRequestError> {
        self.validate_request_head(request)?;
        let uri = request.uri();
        let path = uri
            .path()
            .ok_or(ConnectIpRequestError::Mismatch)?
            .as_encoded_str();
        let query = uri.query().map(|q| q.as_encoded_str());
        let captures = self
            .matcher
            .captures(&path, query.as_deref())
            .ok_or(ConnectIpRequestError::Mismatch)?;
        let template = self.matcher.template();
        let get = |name| template.variable(name).and_then(|v| captures.get(v));
        ConnectIpScope::from_template_values(get("target"), get("ipproto"))
    }

    // Headers/extensions can be customized after template expansion. Check that
    // they still describe this endpoint without reparsing its typed scope.
    pub(super) fn validate_request_head<B>(
        &self,
        request: &Request<B>,
    ) -> Result<(), ConnectIpRequestError> {
        let protocol = validate_capsule_request(request, ViolationPolicy::Reject)
            .map_err(|_error| ConnectIpRequestError::Handshake)?;
        if !protocol.as_str().eq_ignore_ascii_case("connect-ip") {
            return Err(ConnectIpRequestError::Mismatch);
        }
        let h1 = request.version() == Version::HTTP_11;
        if h1
            && (request.method() != Method::GET
                || request.headers().get_all(header::HOST).iter().count() != 1)
        {
            return Err(ConnectIpRequestError::Handshake);
        }
        let uri = request.uri();
        if uri
            .scheme_str()
            .is_some_and(|s| !s.eq_ignore_ascii_case("https"))
        {
            return Err(ConnectIpRequestError::Mismatch);
        }
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|h| AuthorityRef::parse_strict(h.as_bytes()).ok());
        let actual = uri
            .authority()
            .or(host)
            .ok_or(ConnectIpRequestError::Mismatch)?;
        let expected = self.authority.view();
        if !same_authority(actual, expected)
            || h1 && !host.is_some_and(|h| same_authority(h, expected))
        {
            return Err(ConnectIpRequestError::Mismatch);
        }
        Ok(())
    }
}

fn same_authority(a: AuthorityRef<'_>, b: AuthorityRef<'_>) -> bool {
    a.userinfo().is_none()
        && b.userinfo().is_none()
        && a.host() == b.host()
        && a.port_u16().unwrap_or(443) == b.port_u16().unwrap_or(443)
}

/// Validate the proxy's response before exposing packet I/O.
pub fn validate_connect_ip_response<B>(
    version: Version,
    response: &Response<B>,
) -> Result<(), ConnectIpRequestError> {
    validate_capsule_response(
        version,
        &Protocol::CONNECT_IP,
        response,
        ViolationPolicy::Reject,
    )
    .map_err(|_error| ConnectIpRequestError::Handshake)
}
