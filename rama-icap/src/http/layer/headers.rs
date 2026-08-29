use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::{
    HeaderMap, Request as HttpRequest, Version,
    header::{self as http_header, HeaderValue},
};
use rama_net::address::HostWithOptPort;

use crate::http::headers::SanitizedHttpHead;

pub(super) fn sanitize_adapted_http_headers(
    headers: &mut HeaderMap,
    version: Version,
) -> SanitizedHttpHead {
    let sanitized = SanitizedHttpHead::take(headers, version);
    // The adapted body, not the untrusted ICAP response head, determines
    // downstream HTTP framing. This also removes conflicting duplicate values.
    headers.remove(http_header::CONTENT_LENGTH);
    sanitized.restore_trailers(headers);
    sanitized
}

pub(super) fn normalize_request_authority<B>(request: &mut HttpRequest<B>) -> Result<(), BoxError> {
    let Some(authority) = request.uri().authority() else {
        return Ok(());
    };
    let host = HostWithOptPort {
        host: authority.host().into_owned(),
        port: authority.port(),
    }
    .to_string();
    let value = HeaderValue::from_str(&host).context("encode HTTP Host header")?;
    request.headers_mut().insert(http_header::HOST, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapted_heads_do_not_retain_content_length() {
        let mut headers = HeaderMap::new();
        headers.append(http_header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        headers.append(http_header::CONTENT_LENGTH, HeaderValue::from_static("20"));
        headers.insert(http_header::TRAILER, HeaderValue::from_static("x-checksum"));

        sanitize_adapted_http_headers(&mut headers, Version::HTTP_11);

        assert!(!headers.contains_key(http_header::CONTENT_LENGTH));
        assert_eq!(headers[http_header::TRAILER], "x-checksum");
    }

    #[test]
    fn adapted_connection_nomination_suppresses_trailer_declaration() {
        let mut headers = HeaderMap::new();
        headers.insert(http_header::CONNECTION, HeaderValue::from_static("Trailer"));
        headers.insert(http_header::TRAILER, HeaderValue::from_static("x-checksum"));

        sanitize_adapted_http_headers(&mut headers, Version::HTTP_11);

        assert!(!headers.contains_key(http_header::CONNECTION));
        assert!(!headers.contains_key(http_header::TRAILER));
    }
}
