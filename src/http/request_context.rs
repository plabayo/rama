use super::{dep::http::request::Parts, Request, Version};
use crate::http::Uri;
use crate::net::forwarded::Forwarded;
use crate::net::{
    address::{Authority, Host},
    Protocol,
};
use crate::service::Context;
use crate::tls::SecureTransport;

#[derive(Debug, Clone, PartialEq, Eq)]
/// The context of the [`Request`] being served by the [`HttpServer`]
///
/// [`HttpServer`]: crate::http::server::HttpServer
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
    ///
    /// Strictly speaking an authority is always required. It is however up to the user
    /// of this [`RequestContext`] to turn this into a dealbreaker if desired.
    pub authority: Option<Authority>,
}

#[doc(hidden)]
#[macro_export]
/// Get the [`RequestContext`] from the given [`Context`] and [`Request`],
/// either because it is already present in the [`Context`] or by creating a new one.
macro_rules! __get_request_context {
    ($ctx:expr, $req:expr) => {{
        let req_ctx: &$crate::http::RequestContext = match $ctx.get() {
            Some(req_ctx) => req_ctx,
            None => {
                let req_ctx: $crate::http::RequestContext = (&$ctx, &$req).into();
                $ctx.insert(req_ctx);
                $ctx.get().unwrap()
            }
        };
        req_ctx
    }};
}

#[doc(inline)]
pub use crate::__get_request_context as get_request_context;

impl RequestContext {
    /// Create a new [`RequestContext`] from the given [`Request`](crate::http::Request)
    /// and [`Context`](crate::service::Context).
    pub fn new<State, Body>(ctx: &Context<State>, req: &Request<Body>) -> Self {
        (ctx, req).into()
    }
}

impl<State, Body> From<(Context<State>, Request<Body>)> for RequestContext {
    fn from((ctx, req): (Context<State>, Request<Body>)) -> Self {
        RequestContext::from((&ctx, &req))
    }
}

impl<State> From<(Context<State>, Parts)> for RequestContext {
    fn from((ctx, parts): (Context<State>, Parts)) -> Self {
        RequestContext::from((&ctx, &parts))
    }
}

fn protocol_from_uri_or_context<State>(ctx: &Context<State>, uri: &Uri) -> Protocol {
    ctx.get::<Forwarded>()
        .and_then(|f| f.client_proto().map(|p| {
            tracing::trace!(uri = %uri, "request context: detected protocol from forwarded client proto");
            p.into()
        }))
        .or_else(|| uri.scheme().map(|s| {
            tracing::trace!(uri = %uri, "request context: detected protocol from scheme");
            s.into()
        }))
        .or_else(|| {
            // In some cases, e.g. https over HTTP/1.1 it is observed that we are missing
            // both the scheme and authority for the request, making us not detect
            // it correctly as https protocol (port 443 by default). The presence of the client hello
            // config does reveal this information to us which assumes that our tls terminators
            // do set this information, otherwise we would never the less be in the blind.
            // TODO: make this work with TLS implementation-agnostic types once we have Boring integrated
            ctx.contains::<SecureTransport>().then(|| {
                tracing::trace!(uri = %uri, "request context: defaulting protocol to HTTPS (secure transport)");
                Protocol::HTTPS
            })
        })
        .unwrap_or_else(|| {
            tracing::trace!(uri = %uri, "request context: defaulting protocol to HTTP");
            Protocol::HTTP
        })
}

impl<State> From<(&Context<State>, &Parts)> for RequestContext {
    fn from((ctx, parts): (&Context<State>, &Parts)) -> Self {
        let uri = &parts.uri;

        let protocol = protocol_from_uri_or_context(ctx, uri);
        tracing::trace!(uri = %uri, "request context: detected protocol: {protocol}",);

        let default_port = uri.port_u16().unwrap_or_else(|| protocol.default_port());
        tracing::trace!(uri = %uri, "request context: detected default port: {default_port}");

        let authority = ctx
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_host().map(|fauth| {
                    let (host, port) = fauth.clone().into_parts();
                    let port = port.unwrap_or(default_port);
                    (host, port).into()
                })
            })
            .or_else(|| {
                parts
                    .headers
                    .get(crate::http::header::HOST)
                    .and_then(|host| {
                        host.try_into() // try to consume as Authority, otherwise as Host
                            .or_else(|_| Host::try_from(host).map(|h| (h, default_port).into()))
                            .ok()
                    })
            })
            .or_else(|| {
                uri.host()
                    .and_then(|h| Host::try_from(h).ok().map(|h| (h, default_port).into()))
            });
        tracing::trace!(uri = %uri, "request context: maybe detected authority: {authority:?}");

        let http_version = ctx
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_version().map(|v| match v {
                    crate::net::forwarded::ForwardedVersion::HTTP_09 => Version::HTTP_09,
                    crate::net::forwarded::ForwardedVersion::HTTP_10 => Version::HTTP_10,
                    crate::net::forwarded::ForwardedVersion::HTTP_11 => Version::HTTP_11,
                    crate::net::forwarded::ForwardedVersion::HTTP_2 => Version::HTTP_2,
                    crate::net::forwarded::ForwardedVersion::HTTP_3 => Version::HTTP_3,
                })
            })
            .unwrap_or(parts.version);
        tracing::trace!(uri = %uri, "request context: maybe detected http version: {http_version:?}");

        RequestContext {
            http_version,
            protocol,
            authority,
        }
    }
}

impl<State, Body> From<(&Context<State>, &Request<Body>)> for RequestContext {
    fn from((ctx, req): (&Context<State>, &Request<Body>)) -> Self {
        let uri = req.uri();

        let protocol = protocol_from_uri_or_context(ctx, uri);
        tracing::trace!(
            uri = %uri, "request context: detected protocol: {protocol} (scheme: {:?})",
            uri.scheme()
        );

        let default_port = uri.port_u16().unwrap_or_else(|| protocol.default_port());
        tracing::trace!(uri = %uri, "request context: detected default port: {default_port}");

        let authority = ctx
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_host().map(|fauth| {
                    let (host, port) = fauth.clone().into_parts();
                    let port = port.unwrap_or(default_port);
                    (host, port).into()
                })
            })
            .or_else(|| {
                req.headers()
                    .get(crate::http::header::HOST)
                    .and_then(|host| {
                        host.try_into() // try to consume as Authority, otherwise as Host
                            .or_else(|_| Host::try_from(host).map(|h| (h, default_port).into()))
                            .ok()
                    })
            })
            .or_else(|| {
                uri.host()
                    .and_then(|h| Host::try_from(h).ok().map(|h| (h, default_port).into()))
            });
        tracing::trace!(uri = %uri, "request context: maybe detected authority: {authority:?}");

        let http_version = ctx
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_version().map(|v| match v {
                    crate::net::forwarded::ForwardedVersion::HTTP_09 => Version::HTTP_09,
                    crate::net::forwarded::ForwardedVersion::HTTP_10 => Version::HTTP_10,
                    crate::net::forwarded::ForwardedVersion::HTTP_11 => Version::HTTP_11,
                    crate::net::forwarded::ForwardedVersion::HTTP_2 => Version::HTTP_2,
                    crate::net::forwarded::ForwardedVersion::HTTP_3 => Version::HTTP_3,
                })
            })
            .unwrap_or_else(|| req.version());
        tracing::trace!(uri = %uri, "request context: maybe detected http version: {http_version:?}");

        RequestContext {
            http_version,
            protocol,
            authority,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::header::FORWARDED;
    use crate::net::forwarded::{Forwarded, ForwardedElement, NodeId};
    use crate::service::Service;
    use crate::{http::layer::forwarded::GetForwardedHeadersLayer, service::ServiceBuilder};
    use std::convert::Infallible;

    #[test]
    fn test_request_context_from_request() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        let ctx = Context::default();

        let req_ctx = RequestContext::from((&ctx, &req));

        assert_eq!(req_ctx.http_version, Version::HTTP_11);
        assert_eq!(req_ctx.protocol, Protocol::HTTP);
        assert_eq!(req_ctx.authority.unwrap().to_string(), "example.com:8080");
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
        let req_ctx = RequestContext::from((&ctx, &parts));

        assert_eq!(req_ctx.http_version, Version::HTTP_11);
        assert_eq!(req_ctx.protocol, Protocol::HTTP);
        assert_eq!(
            req_ctx.authority.unwrap(),
            Authority::try_from("example.com:8080").unwrap()
        );
    }

    #[test]
    fn test_request_context_authority() {
        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::HTTP,
            authority: Some("example.com:8080".try_into().unwrap()),
        };

        assert_eq!(ctx.authority.unwrap().to_string(), "example.com:8080");
    }

    #[tokio::test]
    async fn forwarded_parsing() {
        for (forwarded_str_vec, expected) in [
            // base
            (
                vec!["host=192.0.2.60;proto=http;by=203.0.113.43"],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: Some("192.0.2.60:80".parse().unwrap()),
                },
            ),
            // ipv6
            (
                vec!["host=\"[2001:db8:cafe::17]:4711\""],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: Some("[2001:db8:cafe::17]:4711".parse().unwrap()),
                },
            ),
            // multiple values in one header
            (
                vec!["host=192.0.2.60, host=127.0.0.1"],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: Some("192.0.2.60:80".parse().unwrap()),
                },
            ),
            // multiple header values
            (
                vec!["host=192.0.2.60", "host=127.0.0.1"],
                RequestContext {
                    http_version: Version::HTTP_11,
                    protocol: Protocol::HTTP,
                    authority: Some("192.0.2.60:80".parse().unwrap()),
                },
            ),
        ] {
            let svc = ServiceBuilder::new()
                .layer(GetForwardedHeadersLayer::forwarded())
                .service_fn(|mut ctx: Context<()>, req: Request<()>| async move {
                    let req_ctx = get_request_context!(ctx, req);
                    Ok::<_, Infallible>(req_ctx.clone())
                });

            let mut req_builder = Request::builder();
            for header in forwarded_str_vec.clone() {
                req_builder = req_builder.header(FORWARDED, header);
            }

            let req = req_builder.body(()).unwrap();

            let req_ctx = svc.serve(Context::default(), req).await.unwrap();

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

        let req_ctx = get_request_context!(ctx, req);

        assert_eq!(req_ctx.http_version, Version::HTTP_11);
        assert_eq!(req_ctx.protocol, "http");
        assert_eq!(
            req_ctx.authority.as_ref().unwrap().to_string(),
            "echo.ramaproxy.org:80"
        );
    }

    #[test]
    fn test_request_ctx_https_request_behind_haproxy_secure() {
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
        ctx.insert(SecureTransport::default());

        let req_ctx = get_request_context!(ctx, req);

        assert_eq!(req_ctx.http_version, Version::HTTP_11);
        assert_eq!(req_ctx.protocol, "https");
        assert_eq!(
            req_ctx.authority.as_ref().unwrap().to_string(),
            "echo.ramaproxy.org:443"
        );
    }
}
