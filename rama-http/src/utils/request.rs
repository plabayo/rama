use crate::{Request, Uri};

// TODO: a protocol-independent version (any URI-carrying input, not just an
// HTTP `Request`) could live behind an extension trait.

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
///
/// Convenience free-function wrapper around [`Request::request_uri`].
pub fn request_uri<Body>(req: &Request<Body>) -> Uri {
    req.request_uri()
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
                    .extension(Forwarded::new(ForwardedElement::new_forwarded_host(
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
                Request::builder()
                    .uri(Uri::parse_authority_form("WwW.ExamplE.COM").unwrap())
                    .body(())
                    .unwrap(),
                // native Uri preserves the empty path (no forced trailing `/`)
                "http://WwW.ExamplE.COM",
            ),
        ] {
            let uri = request_uri(&request);
            let s = uri.to_string();
            assert_eq!(s, expected_uri_str, "request: {request:?}");
        }
    }
}
