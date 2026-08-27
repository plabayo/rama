use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::{
    HeaderMap, Request as HttpRequest,
    header::{self as http_header, HeaderValue},
};
use rama_net::address::HostWithOptPort;

use crate::http::headers::{ForwardedIcapHeader, sanitize_http_headers};

pub(super) fn trailer_header_values(headers: &HeaderMap) -> Vec<HeaderValue> {
    headers
        .get_all(http_header::TRAILER)
        .iter()
        .cloned()
        .collect()
}

pub(super) fn sanitize_adapted_http_headers(headers: &mut HeaderMap) -> Vec<ForwardedIcapHeader> {
    let trailers = trailer_header_values(headers);
    let forwarded = sanitize_http_headers(headers);
    // The adapted body, not the untrusted ICAP response head, determines
    // downstream HTTP framing. This also removes conflicting duplicate values.
    headers.remove(http_header::CONTENT_LENGTH);
    restore_trailer_header(headers, &trailers);
    forwarded
}

pub(super) fn restore_trailer_header(headers: &mut HeaderMap, values: &[HeaderValue]) {
    if headers.contains_key(http_header::TRAILER) {
        return;
    }
    for value in values {
        headers.append(http_header::TRAILER, value.clone());
    }
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

        sanitize_adapted_http_headers(&mut headers);

        assert!(!headers.contains_key(http_header::CONTENT_LENGTH));
        assert_eq!(headers[http_header::TRAILER], "x-checksum");
    }
}
