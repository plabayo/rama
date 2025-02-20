use crate::forwarded::Forwarded;
use crate::transport::{TransportContext, TransportProtocol, TryRefIntoTransportContext};
use crate::{
    Protocol,
    address::{Authority, Host},
};
use rama_core::Context;
use rama_core::error::OpaqueError;
use rama_http_types::Method;
use rama_http_types::{Request, Uri, Version, dep::http::request::Parts};
use tracing::{trace, warn};

#[cfg(feature = "tls")]
use crate::tls::SecureTransport;

#[cfg(feature = "tls")]
fn try_get_host_from_secure_transport(t: &SecureTransport) -> Option<Host> {
    use crate::tls::client::ClientHelloExtension;

    t.client_hello().and_then(|h| {
        h.extensions().iter().find_map(|e| match e {
            ClientHelloExtension::ServerName(maybe_host) => maybe_host.clone(),
            _ => None,
        })
    })
}

#[cfg(not(feature = "tls"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
struct SecureTransport;

#[cfg(not(feature = "tls"))]
fn try_get_host_from_secure_transport(_: &SecureTransport) -> Option<Host> {
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The context of the [`Request`].
pub struct RequestContext {
    /// The HTTP Version.
    pub http_version: Version,
    /// The [`Protocol`] of the [`Request`].
    pub protocol: Protocol,
    /// The authority of the [`Request`].
    ///
    /// In http/1.1 this is typically defined by the `Host` header,
    /// whereas for h2 and h3 this is found in the pseudo `:authority` header.
    ///
    /// This can be also manually set in case there is support for
    /// forward headers (e.g. `Forwarded`, or `X-Forwarded-Host`)
    /// or forward protocols (e.g. `HaProxy`).
    pub authority: Authority,
}

impl<Body, State> TryFrom<(&Context<State>, &Request<Body>)> for RequestContext {
    type Error = OpaqueError;

    fn try_from((ctx, req): (&Context<State>, &Request<Body>)) -> Result<Self, Self::Error> {
        let uri = req.uri();

        let protocol = protocol_from_uri_or_context(ctx, uri, req.method());
        tracing::trace!(
            uri = %uri, "request context: detected protocol: {protocol} (scheme: {:?})",
            uri.scheme()
        );

        let default_port = uri.port_u16().unwrap_or_else(|| protocol.default_port());
        tracing::trace!(uri = %uri, "request context: detected default port: {default_port}");

        let authority = match ctx.get().and_then(try_get_host_from_secure_transport) {
            Some(h) => {
                tracing::trace!(uri = %uri, host = %h, "request context: detected host from SNI");
                (h, default_port).into()
            },
            None => uri
                .host()
                .and_then(|h| Host::try_from(h).ok().map(|h| {
                    tracing::trace!(uri = %uri, host = %h, "request context: detected host from (abs) uri");
                    (h, default_port).into()
                }))
                .or_else(|| {
                    ctx.get::<Forwarded>().and_then(|f| {
                        f.client_host().map(|fauth| {
                            let (host, port) = fauth.clone().into_parts();
                            let port = port.unwrap_or(default_port);
                            tracing::trace!(uri = %uri, host = %host, "request context: detected host from forwarded info");
                            (host, port).into()
                        })
                    })
                })
                .or_else(|| {
                    req.headers()
                        .get(rama_http_types::header::HOST)
                        .and_then(|host| {
                            host.try_into() // try to consume as Authority, otherwise as Host
                                .or_else(|_| Host::try_from(host).map(|h| {
                                    tracing::trace!(uri = %uri, host = %h, "request context: detected host from host header");
                                    (h, default_port).into()
                                }))
                                .ok()
                        })
                })
                .ok_or_else(|| {
                    OpaqueError::from_display("RequestContext: no authourity found in http::Request")
                })?
        };

        tracing::trace!(uri = %uri, "request context: detected authority: {authority}");

        let http_version = ctx
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_version().map(|v| match v {
                    crate::forwarded::ForwardedVersion::HTTP_09 => Version::HTTP_09,
                    crate::forwarded::ForwardedVersion::HTTP_10 => Version::HTTP_10,
                    crate::forwarded::ForwardedVersion::HTTP_11 => Version::HTTP_11,
                    crate::forwarded::ForwardedVersion::HTTP_2 => Version::HTTP_2,
                    crate::forwarded::ForwardedVersion::HTTP_3 => Version::HTTP_3,
                })
            })
            .unwrap_or_else(|| req.version());
        tracing::trace!(uri = %uri, "request context: maybe detected http version: {http_version:?}");

        Ok(RequestContext {
            http_version,
            protocol,
            authority,
        })
    }
}

impl<State> TryFrom<(&Context<State>, &Parts)> for RequestContext {
    type Error = OpaqueError;

    fn try_from((ctx, parts): (&Context<State>, &Parts)) -> Result<Self, Self::Error> {
        let uri = &parts.uri;

        let protocol = protocol_from_uri_or_context(ctx, uri, &parts.method);
        tracing::trace!(
            uri = %uri, "request context: detected protocol: {protocol} (scheme: {:?})",
            uri.scheme()
        );

        let default_port = uri.port_u16().unwrap_or_else(|| protocol.default_port());
        tracing::trace!(uri = %uri, "request context: detected default port: {default_port}");

        let authority = match ctx.get().and_then(try_get_host_from_secure_transport) {
            Some(h) => {
                tracing::trace!(uri = %uri, host = %h, "request context: detected host from SNI");
                (h, default_port).into()
            }
            None => {
                uri
                    .host()
                    .and_then(|h| Host::try_from(h).ok().map(|h| {
                        tracing::trace!(uri = %uri, host = %h, "request context: detected host from (abs) uri");
                        (h, default_port).into()
                    }))
                    .or_else(|| {
                        ctx.get::<Forwarded>().and_then(|f| {
                            f.client_host().map(|fauth| {
                                let (host, port) = fauth.clone().into_parts();
                                let port = port.unwrap_or(default_port);
                                tracing::trace!(uri = %uri, host = %host, "request context: detected host from forwarded info");
                                (host, port).into()
                            })
                        })
                    })
                    .or_else(|| {
                        parts
                            .headers
                            .get(rama_http_types::header::HOST)
                            .and_then(|host| {
                                host.try_into() // try to consume as Authority, otherwise as Host
                                    .or_else(|_| Host::try_from(host).map(|h| {
                                        tracing::trace!(uri = %uri, host = %h, "request context: detected host from host header");
                                        (h, default_port).into()
                                    }))
                                    .ok()
                            })
                    })
                    .ok_or_else(|| {
                        OpaqueError::from_display(
                            "RequestContext: no authourity found in http::request::Parts",
                        )
                    })?
            }
        };

        tracing::trace!(uri = %uri, "request context: detected authority: {authority}");

        let http_version = ctx
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_version().map(|v| match v {
                    crate::forwarded::ForwardedVersion::HTTP_09 => Version::HTTP_09,
                    crate::forwarded::ForwardedVersion::HTTP_10 => Version::HTTP_10,
                    crate::forwarded::ForwardedVersion::HTTP_11 => Version::HTTP_11,
                    crate::forwarded::ForwardedVersion::HTTP_2 => Version::HTTP_2,
                    crate::forwarded::ForwardedVersion::HTTP_3 => Version::HTTP_3,
                })
            })
            .unwrap_or(parts.version);
        tracing::trace!(uri = %uri, "request context: maybe detected http version: {http_version:?}");

        Ok(RequestContext {
            http_version,
            protocol,
            authority,
        })
    }
}

#[allow(clippy::unnecessary_lazy_evaluations)]
fn protocol_from_uri_or_context<State>(
    ctx: &Context<State>,
    uri: &Uri,
    method: &Method,
) -> Protocol {
    uri.scheme().map(|s| {
        tracing::trace!(uri = %uri, "request context: detected protocol from scheme");
        let protocol = s.into();
        if method == Method::CONNECT {
            match protocol {
                Protocol::HTTP => {
                    trace!(uri = %uri, "CONNECT request: upgrade HTTP => HTTPS");
                    Protocol::HTTPS
                }
                Protocol::HTTPS => Protocol::HTTPS,
                Protocol::WS => {
                    trace!(uri = %uri, "CONNECT request: upgrade WS => WSS");
                    Protocol::WSS
                }
                Protocol::WSS => Protocol::WSS,
                other => {
                    warn!(uri = %uri, protocol = %other, "CONNECT request: unexpected protocol");
                    other
                }
            }
        } else {
            protocol
        }
    }).or_else(|| ctx.get::<Forwarded>()
        .and_then(|f| f.client_proto().map(|p| {
            tracing::trace!(uri = %uri, "request context: detected protocol from forwarded client proto");
            p.into()
        })))
        .unwrap_or_else(|| {
            if method == Method::CONNECT {
                tracing::trace!(uri = %uri, method = %method, "request context: CONNECT: defaulting protocol to HTTPS");
                Protocol::HTTPS
            } else {
                tracing::trace!(uri = %uri, method = %method, "request context: defaulting protocol to HTTP");
                Protocol::HTTP
            }
        })
}

impl From<RequestContext> for TransportContext {
    fn from(value: RequestContext) -> Self {
        Self {
            protocol: if value.http_version == Version::HTTP_3 {
                TransportProtocol::Udp
            } else {
                TransportProtocol::Tcp
            },
            app_protocol: Some(value.protocol),
            http_version: Some(value.http_version),
            authority: value.authority,
        }
    }
}

impl From<&RequestContext> for TransportContext {
    fn from(value: &RequestContext) -> Self {
        Self {
            protocol: if value.http_version == Version::HTTP_3 {
                TransportProtocol::Udp
            } else {
                TransportProtocol::Tcp
            },
            app_protocol: Some(value.protocol.clone()),
            http_version: Some(value.http_version),
            authority: value.authority.clone(),
        }
    }
}

impl<State, Body> TryRefIntoTransportContext<State> for rama_http_types::Request<Body> {
    type Error = OpaqueError;

    fn try_ref_into_transport_ctx(
        &self,
        ctx: &Context<State>,
    ) -> Result<TransportContext, Self::Error> {
        (ctx, self).try_into()
    }
}

impl<State> TryRefIntoTransportContext<State> for rama_http_types::dep::http::request::Parts {
    type Error = OpaqueError;

    fn try_ref_into_transport_ctx(
        &self,
        ctx: &Context<State>,
    ) -> Result<TransportContext, Self::Error> {
        (ctx, self).try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarded::{Forwarded, ForwardedElement, NodeId};
    use rama_http_types::header::FORWARDED;
    use rama_http_types::headers::HeaderMapExt;

    #[test]
    fn test_request_context_from_request() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        let ctx = Context::default();

        let req_ctx = RequestContext::try_from((&ctx, &req)).unwrap();

        assert_eq!(req_ctx.http_version, Version::HTTP_11);
        assert_eq!(req_ctx.protocol, Protocol::HTTP);
        assert_eq!(req_ctx.authority.to_string(), "example.com:8080");
    }

    #[test]
    fn test_request_context_from_parts() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();

        let ctx = Context::default();
        let req_ctx = RequestContext::try_from((&ctx, &parts)).unwrap();

        assert_eq!(req_ctx.http_version, Version::HTTP_11);
        assert_eq!(req_ctx.protocol, Protocol::HTTP);
        assert_eq!(
            req_ctx.authority,
            Authority::try_from("example.com:8080").unwrap()
        );
    }

    #[test]
    fn test_request_context_authority() {
        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::HTTP,
            authority: "example.com:8080".try_into().unwrap(),
        };

        assert_eq!(ctx.authority.to_string(), "example.com:8080");
    }

    #[test]
    fn forwarded_parsing() {
        for (forwarded_str_vec, expected) in [
            // base
            (
                vec!["host=192.0.2.60;proto=http;by=203.0.113.43"],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: "192.0.2.60:80".parse().unwrap(),
                },
            ),
            // ipv6
            (
                vec!["host=\"[2001:db8:cafe::17]:4711\""],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: "[2001:db8:cafe::17]:4711".parse().unwrap(),
                },
            ),
            // multiple values in one header
            (
                vec!["host=192.0.2.60, host=127.0.0.1"],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: "192.0.2.60:80".parse().unwrap(),
                },
            ),
            // multiple header values
            (
                vec!["host=192.0.2.60", "host=127.0.0.1"],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: "192.0.2.60:80".parse().unwrap(),
                },
            ),
        ] {
            let mut req_builder = Request::builder();
            for header in forwarded_str_vec.clone() {
                req_builder = req_builder.header(FORWARDED, header);
            }

            let req = req_builder.body(()).unwrap();
            let mut ctx = Context::default();

            let forwarded = req.headers().typed_get::<Forwarded>().unwrap();
            ctx.insert(forwarded);

            let req_ctx = ctx
                .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())
                .unwrap()
                .clone();

            assert_eq!(req_ctx, expected, "Failed for {:?}", forwarded_str_vec);
        }
    }

    #[test]
    fn test_request_ctx_https_request_behind_haproxy_plain() {
        let req = Request::builder()
            .uri("/en/reservation/roomdetails")
            .version(Version::HTTP_11)
            .header("host", "echo.ramaproxy.org")
            .header("user-agent", "curl/8.6.0")
            .header("accept", "*/*")
            .body(())
            .unwrap();

        let mut ctx = Context::default();
        ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
            NodeId::try_from("127.0.0.1:61234").unwrap(),
        )));

        let req_ctx: &mut RequestContext = ctx
            .get_or_try_insert_with_ctx(|ctx| (ctx, &req).try_into())
            .unwrap();

        assert_eq!(req_ctx.http_version, Version::HTTP_11);
        assert_eq!(req_ctx.protocol, "http");
        assert_eq!(req_ctx.authority.to_string(), "echo.ramaproxy.org:80");
    }

    #[test]
    fn test_request_ctx_connect_req_no_scheme() {
        let test_cases = [
            (80, Protocol::HTTPS),
            (433, Protocol::HTTPS),
            (8080, Protocol::HTTPS),
        ];
        for (port, expected_protocol) in test_cases {
            let req = Request::builder()
                .uri(format!("www.example.com:{port}"))
                .version(Version::HTTP_11)
                .method(Method::CONNECT)
                .header("host", "www.example.com")
                .header("user-agent", "test/42")
                .body(())
                .unwrap();

            let mut ctx = Context::default();
            let req_ctx: &mut RequestContext = ctx
                .get_or_try_insert_with_ctx(|ctx| (ctx, &req).try_into())
                .unwrap();

            assert_eq!(req_ctx.http_version, Version::HTTP_11);
            assert_eq!(req_ctx.protocol, expected_protocol);
            assert_eq!(
                req_ctx.authority.to_string(),
                format!("www.example.com:{}", port)
            );
        }
    }

    #[test]
    fn test_request_ctx_connect_req() {
        let test_cases = [
            ("http", Protocol::HTTPS),
            ("https", Protocol::HTTPS),
            ("ws", Protocol::WSS),
            ("wss", Protocol::WSS),
            ("ftp", Protocol::from_static("ftp")),
        ];
        for (scheme, expected_protocol) in test_cases {
            let req = Request::builder()
                .uri(format!("{scheme}://www.example.com"))
                .version(Version::HTTP_11)
                .method(Method::CONNECT)
                .header("host", "www.example.com")
                .header("user-agent", "test/42")
                .body(())
                .unwrap();

            let mut ctx = Context::default();
            let req_ctx: &mut RequestContext = ctx
                .get_or_try_insert_with_ctx(|ctx| (ctx, &req).try_into())
                .unwrap();

            assert_eq!(req_ctx.http_version, Version::HTTP_11);
            assert_eq!(req_ctx.protocol, expected_protocol);
            assert_eq!(
                req_ctx.authority.to_string(),
                format!("www.example.com:{}", expected_protocol.default_port())
            );
        }
    }
}
