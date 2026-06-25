use crate::request::Parts;
use crate::{HttpRequestParts, Request};
use crate::{Uri, Version};
#[cfg(not(feature = "tls"))]
use rama_core::extensions::Extension;
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::telemetry::tracing;
use rama_net::Protocol;
use rama_net::address::{Domain, Host, HostWithOptPort};
use rama_net::forwarded::Forwarded;
use rama_net::transport::TransportProtocol;
use rama_net::{
    AuthorityInputExt, HttpVersionInputExt, PathInputExt, ProtocolInputExt,
    TransportProtocolInputExt, UriInputExt,
};

#[cfg(feature = "tls")]
use rama_net::tls::SecureTransport;

#[cfg(feature = "tls")]
fn try_get_sni_from_secure_transport(t: &SecureTransport) -> Option<Domain> {
    use rama_net::tls::client::ClientHelloExtension;

    t.client_hello().and_then(|h| {
        h.extensions().iter().find_map(|e| match e {
            ClientHelloExtension::ServerName(maybe_domain) => maybe_domain.clone(),
            _ => None,
        })
    })
}

#[cfg(not(feature = "tls"))]
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
#[non_exhaustive]
struct SecureTransport;

#[cfg(not(feature = "tls"))]
fn try_get_sni_from_secure_transport(_: &SecureTransport) -> Option<Domain> {
    None
}

/// Resolve the routing authority of `parts`, walking the
/// uri → TLS SNI → `Forwarded` → `Host`-header fallback chain.
/// `None` when none of them yields a host.
pub(crate) fn authority_from_http_parts(parts: &impl HttpRequestParts) -> Option<HostWithOptPort> {
    let uri = parts.uri();

    let protocol = protocol_from_uri_or_extensions(parts.extensions(), uri);
    let default_port = uri
        .port_u16()
        .unwrap_or_else(|| protocol.default_port().unwrap_or(80));

    uri.host()
        .map(|h| {
            let h: Host = h.into_owned();
            tracing::trace!(url.full = %uri, "request context: detected host {h} from (abs) uri");
            (h, default_port).into()
        })
        .or_else(|| {
            parts
                .extensions()
                .get_ref()
                .and_then(try_get_sni_from_secure_transport)
                .map(|host| {
                    tracing::trace!(url.full = %uri, "request context: detected host {host} from SNI");
                    (host, default_port).into()
                })
        })
        .or_else(|| {
            parts.extensions().get_ref::<Forwarded>().and_then(|f| {
                f.client_host().map(|fauth| {
                    let HostWithOptPort { host, port } = fauth.0.clone();
                    let port = port.as_u16().unwrap_or(default_port);
                    tracing::trace!(url.full = %uri, "request context: detected host {host} from forwarded info");
                    (host, port).into()
                })
            })
        })
        .or_else(|| {
            parts
                .headers()
                .get(crate::header::HOST)
                .and_then(|host_header_value| {
                    HostWithOptPort::try_from(host_header_value.as_bytes()).ok()
                })
        })
}

/// Resolve the HTTP [`Version`] from `parts`: the `Forwarded` client version
/// when present, otherwise the request's own version.
pub(crate) fn http_version_from_http_parts(parts: &impl HttpRequestParts) -> Version {
    parts
        .extensions()
        .get_ref::<Forwarded>()
        .and_then(|f| {
            f.client_version().map(|v| match v {
                rama_net::forwarded::ForwardedVersion::HTTP_09 => Version::HTTP_09,
                rama_net::forwarded::ForwardedVersion::HTTP_10 => Version::HTTP_10,
                rama_net::forwarded::ForwardedVersion::HTTP_11 => Version::HTTP_11,
                rama_net::forwarded::ForwardedVersion::HTTP_2 => Version::HTTP_2,
                rama_net::forwarded::ForwardedVersion::HTTP_3 => Version::HTTP_3,
            })
        })
        .unwrap_or_else(|| parts.version())
}

fn protocol_from_uri_or_extensions<'a>(ext: &'a Extensions, uri: &'a Uri) -> &'a Protocol {
    uri.scheme().or_else(|| {
        // Can be inserted by a server stack to notify the protocol that's being served.
        // This is especially useful for marking a HTTPS server as HTTPS,
        // despite it not showing up anywhere due to a non-default port
        // and it being http/1
        ext.get_ref::<Protocol>()
    }).or_else(|| ext.get_ref::<Forwarded>()
        .and_then(|f| f.client_proto().map(|p| {
            tracing::trace!(url.furi = %uri, "request context: detected protocol from forwarded client proto");
            if p.is_secure() { &Protocol::HTTPS } else { &Protocol::HTTP }
        })))
        .unwrap_or_else(||
    if ext.contains::<SecureTransport>() {
        &Protocol::HTTPS
    } else {
        &Protocol::HTTP
    })
}

impl<Body> AuthorityInputExt for Request<Body> {
    fn authority(&self) -> Option<HostWithOptPort> {
        authority_from_http_parts(self)
    }
}

impl AuthorityInputExt for Parts {
    fn authority(&self) -> Option<HostWithOptPort> {
        authority_from_http_parts(self)
    }
}

impl<Body> ProtocolInputExt for Request<Body> {
    fn protocol(&self) -> Option<&Protocol> {
        Some(protocol_from_uri_or_extensions(
            self.extensions(),
            self.uri(),
        ))
    }
}

impl ProtocolInputExt for Parts {
    fn protocol(&self) -> Option<&Protocol> {
        Some(protocol_from_uri_or_extensions(
            self.extensions(),
            HttpRequestParts::uri(self),
        ))
    }
}

impl<Body> HttpVersionInputExt for Request<Body> {
    fn http_version(&self) -> Option<Version> {
        Some(http_version_from_http_parts(self))
    }
}

impl HttpVersionInputExt for Parts {
    fn http_version(&self) -> Option<Version> {
        Some(http_version_from_http_parts(self))
    }
}

/// HTTP/3 rides on UDP; every other HTTP version on TCP.
fn transport_protocol_for_http_version(version: Version) -> TransportProtocol {
    match version {
        Version::HTTP_3 => TransportProtocol::Udp,
        _ => TransportProtocol::Tcp,
    }
}

impl<Body> TransportProtocolInputExt for Request<Body> {
    fn transport_protocol(&self) -> Option<TransportProtocol> {
        Some(transport_protocol_for_http_version(self.version()))
    }
}

impl TransportProtocolInputExt for Parts {
    fn transport_protocol(&self) -> Option<TransportProtocol> {
        Some(transport_protocol_for_http_version(self.version()))
    }
}

impl<Body> UriInputExt for Request<Body> {
    fn uri(&self) -> &Uri {
        HttpRequestParts::uri(self)
    }
}

impl UriInputExt for Parts {
    fn uri(&self) -> &Uri {
        HttpRequestParts::uri(self)
    }
}

impl<Body> PathInputExt for Request<Body> {
    fn path_ref(&self) -> rama_net::uri::PathRef<'_> {
        self.uri().path_ref_or_root()
    }
}

impl PathInputExt for Parts {
    fn path_ref(&self) -> rama_net::uri::PathRef<'_> {
        HttpRequestParts::uri(self).path_ref_or_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Request, header::FORWARDED};
    use rama_core::extensions::ExtensionsRef;
    use rama_net::forwarded::{Forwarded, ForwardedElement, NodeId};

    #[test]
    fn accessors_from_request() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        assert_eq!(req.http_version(), Some(Version::HTTP_11));
        assert_eq!(req.protocol(), Some(&Protocol::HTTP));
        assert_eq!(req.authority().unwrap().to_string(), "example.com:8080");
    }

    #[test]
    fn path_accessor_from_request_and_parts() {
        let req = Request::builder()
            .uri("http://example.com/a%2Fb?q=1")
            .body(())
            .unwrap();

        assert_eq!(req.path_ref(), "/a%2Fb");
        assert_eq!(req.path_ref(), "/a/b");

        let (parts, _) = req.into_parts();
        assert_eq!(parts.path_ref(), "/a%2Fb");
        assert_eq!(parts.path_ref(), "/a/b");
    }

    #[test]
    fn accessors_resolve() {
        let req = Request::builder()
            .uri("https://example.com:8443")
            .version(Version::HTTP_2)
            .body(())
            .unwrap();
        assert_eq!(req.authority().unwrap().to_string(), "example.com:8443");
        assert_eq!(req.protocol(), Some(&Protocol::HTTPS));
        assert_eq!(req.http_version(), Some(Version::HTTP_2));

        // origin-form with no resolvable authority -> None, but protocol and
        // version still resolve (they don't depend on the authority).
        let req = Request::builder().uri("/path").body(()).unwrap();
        assert_eq!(req.authority(), None);
        assert_eq!(req.protocol(), Some(&Protocol::HTTP));
        assert_eq!(req.http_version(), Some(Version::HTTP_11));
    }

    #[test]
    fn accessors_from_parts() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();

        assert_eq!(parts.http_version(), Some(Version::HTTP_11));
        assert_eq!(parts.protocol(), Some(&Protocol::HTTP));
        assert_eq!(
            parts.authority().unwrap(),
            HostWithOptPort::try_from("example.com:8080").unwrap()
        );
    }

    #[test]
    fn forwarded_parsing() {
        for (forwarded_str_vec, expected_authority) in [
            // base
            (
                vec!["host=192.0.2.60;proto=http;by=203.0.113.43"],
                "192.0.2.60:80",
            ),
            // ipv6
            (
                vec!["host=\"[2001:db8:cafe::17]:4711\""],
                "[2001:db8:cafe::17]:4711",
            ),
            // multiple values in one header
            (vec!["host=192.0.2.60, host=127.0.0.1"], "192.0.2.60:80"),
            // multiple header values
            (vec!["host=192.0.2.60", "host=127.0.0.1"], "192.0.2.60:80"),
        ] {
            let mut req_builder = Request::builder();
            for header in forwarded_str_vec.clone() {
                req_builder = req_builder.header(FORWARDED, header);
            }

            let req = req_builder.body(()).unwrap();

            let forwarded: Forwarded = req
                .headers()
                .get(FORWARDED)
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap();
            req.extensions().insert(forwarded);

            assert_eq!(
                req.authority().map(|a| a.to_string()).as_deref(),
                Some(expected_authority),
                "Failed for {forwarded_str_vec:?}"
            );
            assert_eq!(
                req.protocol(),
                Some(&Protocol::HTTP),
                "Failed for {forwarded_str_vec:?}"
            );
            assert_eq!(
                req.http_version(),
                Some(Version::HTTP_11),
                "Failed for {forwarded_str_vec:?}"
            );
        }
    }

    #[test]
    fn https_request_behind_haproxy_plain() {
        let req = Request::builder()
            .uri("/en/reservation/roomdetails")
            .version(Version::HTTP_11)
            .header("host", "echo.ramaproxy.org")
            .header("user-agent", "curl/8.6.0")
            .header("accept", "*/*")
            .body(())
            .unwrap();

        req.extensions()
            .insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                NodeId::try_from("127.0.0.1:61234").unwrap(),
            )));

        assert_eq!(req.http_version(), Some(Version::HTTP_11));
        assert_eq!(req.protocol(), Some(&Protocol::HTTP));
        let authority = req.authority().unwrap();
        assert_eq!(authority.to_string(), "echo.ramaproxy.org");
        let default_port = req
            .protocol_default_port()
            .unwrap_or(Protocol::HTTP_DEFAULT_PORT);
        assert_eq!(
            authority.into_host_with_port_or(default_port).to_string(),
            "echo.ramaproxy.org:80"
        );
    }

    // An origin-form request (no scheme) carrying a TLS `SecureTransport` marker
    // — the shape of a request read off a terminated TLS connection — must
    // resolve its protocol as HTTPS; the marker is the only secure signal here.
    // This guards the `SecureTransport` fallback in `protocol_from_uri_or_extensions`
    // against the real type being swapped for the tls-off dummy. See the matching
    // cross-crate regression in rama-http-backend's `svc` tests, which catches the
    // feature wiring (`rama-http-types/tls` must follow `rama-net/tls`).
    #[cfg(feature = "tls")]
    #[test]
    fn secure_transport_marks_origin_form_request_https() {
        let req = Request::builder()
            .uri("/ping")
            .header("host", "example.com")
            .body(())
            .unwrap();
        req.extensions().insert(SecureTransport::default());

        assert_eq!(req.protocol(), Some(&Protocol::HTTPS));
    }
}
