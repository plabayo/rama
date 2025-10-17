use crate::{Request, Uri};
use rama_core::{combinators::Either, telemetry::tracing};
use rama_net::http::RequestContext;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::io::Write as _;

// TODO: request_uri probably needs to be part of a trait which works
// on any kind of "input" (request) which identifies its resources via an URI,
// which certainly is not just HTTP... also the internals of `request_uri`
// can be probably improved in several ways.

// TODO: uri from `req` probably always has to return derived,
// one where different, as to make it harder
// to use different values in different layers
// ...
//
// request's ::host, ::authority, ::port and ::uri should
// probably all also take into account extensions, as to
// ensure we all talk the same language... because
// if different components/layers look at the same object
// differently we can get into security issues
// or other logic bugs

/// Get the uri as complete as possible for the given request.
pub fn request_uri<Body>(req: &Request<Body>) -> Cow<'_, Uri> {
    let uri = req.uri();
    if let Ok(req_ctx) = RequestContext::try_from(req) {
        let mut buffer = SmallVec::<[u8; 128]>::new();
        let _ = write!(
            &mut buffer,
            "{}://{}{}",
            req_ctx.protocol,
            if req_ctx.authority_has_default_port() {
                Either::A(req_ctx.authority.host())
            } else {
                Either::B(req_ctx.authority)
            },
            uri.path_and_query()
                .map(|paq| paq.as_str())
                .unwrap_or_default(),
        );
        Uri::try_from(buffer.as_slice())
            .map(Cow::Owned)
            .inspect_err(|err| {
                tracing::debug!("failed to format request uri raw slice: {err}");
            })
            .unwrap_or(Cow::Borrowed(uri))
    } else {
        Cow::Borrowed(uri)
    }
}

#[cfg(test)]
mod tests {
    use crate::header::HOST;
    use rama_net::{
        address::Domain,
        forwarded::{Forwarded, ForwardedElement},
    };

    use super::*;

    #[test]
    fn test_request_uri() {
        for (request, expected_uri_str) in [
            (Request::builder().uri("/foo").body(()).unwrap(), "/foo"),
            (
                Request::builder()
                    .uri("/foo")
                    .header(HOST, "example.com")
                    .body(())
                    .unwrap(),
                "http://example.com/foo",
            ),
            (
                Request::builder()
                    .uri("/foo")
                    .extension(Forwarded::new(ForwardedElement::forwarded_host(
                        Domain::from_static("example.com"),
                    )))
                    .body(())
                    .unwrap(),
                "http://example.com/foo",
            ),
            (
                Request::builder()
                    .uri("http://example.com/foo")
                    .body(())
                    .unwrap(),
                "http://example.com/foo",
            ),
            (
                Request::builder()
                    .uri("https://example.com/foo")
                    .body(())
                    .unwrap(),
                "https://example.com/foo",
            ),
            (
                Request::builder().uri("WwW.ExamplE.COM").body(()).unwrap(),
                "http://WwW.ExamplE.COM/",
            ),
        ] {
            let uri = request_uri(&request);
            let s = uri.to_string();
            assert_eq!(s, expected_uri_str, "request: {request:?}");
        }
    }
}
