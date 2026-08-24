use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::{
    HeaderMap, Request as HttpRequest,
    header::{self as http_header, HeaderName, HeaderValue},
};
use rama_net::address::HostWithOptPort;

use crate::{
    codec::HeaderSlot,
    http::headers::{ForwardedIcapHeader, sanitize_http_headers},
    message::Response as IcapResponse,
    proto::header,
};

pub(super) fn trailer_header_values(headers: &HeaderMap) -> Vec<HeaderValue> {
    headers
        .get_all(http_header::TRAILER)
        .iter()
        .cloned()
        .collect()
}

pub(super) fn sanitize_adapted_http_headers(headers: &mut HeaderMap) {
    let trailers = trailer_header_values(headers);
    sanitize_http_headers(headers);
    restore_trailer_header(headers, &trailers);
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

pub(super) fn response_proxy_headers(
    response: &IcapResponse,
) -> Result<Vec<ForwardedIcapHeader>, BoxError> {
    let slot_count = response
        .head_bytes()
        .windows(2)
        .filter(|window| *window == b"\r\n")
        .count();
    let mut slots = vec![HeaderSlot::EMPTY; slot_count];
    let head = response
        .parse_head(&mut slots)
        .context("decode ICAP response headers")?;
    head.headers()
        .filter_map(|field| {
            [
                (header::PROXY_AUTHENTICATE, &http_header::PROXY_AUTHENTICATE),
                (
                    header::PROXY_AUTHORIZATION,
                    &http_header::PROXY_AUTHORIZATION,
                ),
            ]
            .into_iter()
            .find(|(name, _http_name)| field.name().eq_ignore_ascii_case(name))
            .map(|(name, http_name)| (name, http_name, field.value()))
        })
        .map(|(name, http_name, value)| {
            let mut bytes = Vec::with_capacity(value.encoded_len());
            for segment in value.segments() {
                if !bytes.is_empty() {
                    bytes.push(b' ');
                }
                bytes.extend_from_slice(segment);
            }
            let mut value = HeaderValue::from_bytes(&bytes).context("decode ICAP proxy header")?;
            if http_name.is_sensitive() {
                value.set_sensitive(true);
            }
            Ok(ForwardedIcapHeader { name, value })
        })
        .collect()
}

pub(super) fn restore_proxy_header(
    headers: &mut HeaderMap,
    http_name: &HeaderName,
    icap_name: &str,
    original: &[ForwardedIcapHeader],
    returned: &[ForwardedIcapHeader],
) {
    headers.remove(http_name);
    let values = if returned
        .iter()
        .any(|field| field.name.eq_ignore_ascii_case(icap_name))
    {
        returned
    } else {
        original
    };
    for field in values
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case(icap_name))
    {
        headers.append(http_name.clone(), field.value.clone());
    }
}
