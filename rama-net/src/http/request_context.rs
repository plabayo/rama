use crate::forwarded::Forwarded;
use crate::proxy::ProxyTarget;
use crate::transport::{TransportContext, TransportProtocol, TryRefIntoTransportContext};
use crate::{
    Protocol,
    address::{Authority, Domain, Host},
};
use rama_core::Context;
use rama_core::error::OpaqueError;
use rama_core::telemetry::tracing;
use rama_http_types::{HttpRequestParts, Method};
use rama_http_types::{Uri, Version};

#[cfg(feature = "tls")]
use crate::tls::SecureTransport;

#[cfg(feature = "tls")]
fn try_get_sni_from_secure_transport(t: &SecureTransport) -> Option<Domain> {
    use crate::tls::client::ClientHelloExtension;

    t.client_hello().and_then(|h| {
        h.extensions().iter().find_map(|e| match e {
            ClientHelloExtension::ServerName(maybe_domain) => maybe_domain.clone(),
            _ => None,
        })
    })
}

#[cfg(not(feature = "tls"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
struct SecureTransport;

#[cfg(not(feature = "tls"))]
fn try_get_sni_from_secure_transport(_: &SecureTransport) -> Option<Domain> {
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

impl RequestContext {
    /// Check if [`Authority`] is using the default port for the [`Protocol`] set in this [`RequestContext`]
    pub fn authority_has_default_port(&self) -> bool {
        self.protocol.default_port() == Some(self.authority.port())
    }
}

impl<T: HttpRequestParts, State> TryFrom<(&Context<State>, &T)> for RequestContext {
    type Error = OpaqueError;

    fn try_from((ctx, req): (&Context<State>, &T)) -> Result<Self, Self::Error> {
        let uri = req.uri();

        let protocol = protocol_from_uri_or_context(ctx, uri, req.method());
        tracing::trace!(
            url.full = %uri,
            "request context: detected protocol: {protocol} (scheme: {:?}",
            uri.scheme(),
        );

        let default_port = uri
            .port_u16()
            .unwrap_or_else(|| protocol.default_port().unwrap_or(80));
        tracing::trace!(url.full = %uri, "request context: detected default port: {default_port}");

        let proxy_authority_opt: Option<Authority> = ctx
            .get::<ProxyTarget>()
            .and_then(|t| t.0.host().is_domain().then(|| t.0.clone()));

        let sni_host_opt = ctx.get().and_then(try_get_sni_from_secure_transport);
        let authority = match (proxy_authority_opt, sni_host_opt) {
            (Some(authority), _) => {
                tracing::trace!(url.full = %uri, "request context: use proxy target as authority: {authority}");
                authority
            },
            (None, Some(h)) => {
                tracing::trace!(url.full = %uri, "request context: detected host {h} from SNI");
                (h, default_port).into()
            },
            (None, None) => uri
                .host()
                .and_then(|h| Host::try_from(h).ok().map(|h| {
                    tracing::trace!(url.full = %uri, "request context: detected host {h} from (abs) uri");
                    (h, default_port).into()
                }))
                .or_else(|| {
                    ctx.get::<Forwarded>().and_then(|f| {
                        f.client_host().map(|fauth| {
                            let (host, port) = fauth.clone().into_parts();
                            let port = port.unwrap_or(default_port);
                            tracing::trace!(url.full = %uri, "request context: detected host {host} from forwarded info");
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
                                    tracing::trace!(url.full = %uri, "request context: detected host {h} from host header");
                                    (h, default_port).into()
                                }))
                                .ok()
                        })
                })
                .ok_or_else(|| {
                    OpaqueError::from_display("RequestContext: no authourity found in http::Request")
                })?
        };

        tracing::trace!(url.full = %uri, "request context: detected authority: {authority}");

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
        tracing::trace!(url.full = %uri, "request context: maybe detected http version: {http_version:?}");

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
    Protocol::maybe_from_uri_scheme_str_and_method(uri.scheme(), Some(method)).or_else(|| ctx.get::<Forwarded>()
        .and_then(|f| f.client_proto().map(|p| {
            tracing::trace!(url.furi = %uri, "request context: detected protocol from forwarded client proto");
            p.into()
        })))
        .unwrap_or_else(|| {
            if method == Method::CONNECT {
                tracing::trace!(url.full = %uri, http.method = %method, "request context: CONNECT: defaulting protocol to HTTPS");
                Protocol::HTTPS
            } else {
                tracing::trace!(url.full = %uri, http.method = %method, "request context: defaulting protocol to HTTP");
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
    use rama_http_types::{Request, header::FORWARDED};

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

            let forwarded: Forwarded = req.headers().get(FORWARDED).unwrap().try_into().unwrap();
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
                format!(
                    "www.example.com:{}",
                    expected_protocol.default_port().unwrap_or(80)
                )
            );
        }
    }
}
