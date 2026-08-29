use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
};
use rama_http_types::{
    HeaderMap,
    header::{self as http_header, HeaderName, HeaderValue},
};

use crate::{
    byte_sets::comma_separated_items,
    codec::{DEFAULT_MAX_HEADERS, HeaderSlot},
    message::Response as IcapResponse,
    proto::header,
};

#[derive(Clone)]
pub(super) struct ForwardedIcapHeader {
    pub(super) name: &'static str,
    pub(super) value: HeaderValue,
}

#[derive(Clone, Default)]
pub(super) struct PreservedUpgradeHeaders {
    upgrade: Vec<HeaderValue>,
}

pub(super) fn preserve_upgrade_headers(headers: &HeaderMap) -> PreservedUpgradeHeaders {
    if !headers.contains_key(&http_header::UPGRADE)
        || !connection_header_names(headers).any(|name| name == http_header::UPGRADE)
    {
        return PreservedUpgradeHeaders::default();
    }
    PreservedUpgradeHeaders {
        upgrade: headers
            .get_all(http_header::UPGRADE)
            .iter()
            .cloned()
            .collect(),
    }
}

pub(super) fn restore_upgrade_headers(
    headers: &mut HeaderMap,
    preserved: &PreservedUpgradeHeaders,
) {
    headers.remove(&http_header::CONNECTION);
    headers.remove(&http_header::UPGRADE);
    if !preserved.upgrade.is_empty() {
        headers.insert(http_header::CONNECTION, HeaderValue::from_static("upgrade"));
        for value in &preserved.upgrade {
            headers.append(http_header::UPGRADE, value.clone());
        }
    }
}

pub(super) fn sanitize_http_headers(headers: &mut HeaderMap) -> Vec<ForwardedIcapHeader> {
    sanitize_http_headers_with_nominated(headers).0
}

pub(super) fn sanitize_http_headers_with_nominated(
    headers: &mut HeaderMap,
) -> (Vec<ForwardedIcapHeader>, Vec<HeaderName>) {
    let mut forwarded = Vec::new();
    for (name, icap_name) in [
        (&http_header::PROXY_AUTHENTICATE, header::PROXY_AUTHENTICATE),
        (
            &http_header::PROXY_AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
        ),
    ] {
        forwarded.extend(headers.get_all(name).iter().cloned().map(|mut value| {
            if name.is_sensitive() {
                value.set_sensitive(true);
            }
            ForwardedIcapHeader {
                name: icap_name,
                value,
            }
        }));
        headers.remove(name);
    }

    let nominated = connection_header_names(headers).collect::<Vec<_>>();
    for name in [
        &http_header::CONNECTION,
        &http_header::KEEP_ALIVE,
        &http_header::PROXY_CONNECTION,
        &http_header::TE,
        &http_header::TRAILER,
        &http_header::TRANSFER_ENCODING,
        &http_header::UPGRADE,
    ] {
        headers.remove(name);
    }
    for name in &nominated {
        headers.remove(name);
    }
    (forwarded, nominated)
}

pub(super) fn connection_nominated_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    connection_header_names(headers).collect()
}

fn connection_header_names(headers: &HeaderMap) -> impl Iterator<Item = HeaderName> + '_ {
    headers
        .get_all(http_header::CONNECTION)
        .iter()
        .flat_map(|value| comma_separated_items(value.as_bytes()))
        .filter(|token| !token.is_empty())
        .filter_map(|token| HeaderName::from_bytes(token).ok())
}

pub(super) fn validate_http_trailers(
    trailers: &HeaderMap,
    head_nominated: &[HeaderName],
) -> Result<(), &'static str> {
    for name in trailers.keys() {
        if !name.is_allowed_in_trailers() {
            return Err("HTTP trailer contains a field that belongs in the message head");
        }
        if head_nominated.iter().any(|value| value == name) {
            return Err("HTTP trailer contains a Connection-nominated field");
        }
    }
    Ok(())
}

pub(super) fn response_proxy_headers(
    response: &IcapResponse,
) -> Result<Vec<ForwardedIcapHeader>, BoxError> {
    let Some(slot_count) = proxy_header_slot_count(response.head_bytes()) else {
        return Ok(Vec::new());
    };
    let mut stack_slots = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
    let mut heap_slots = Vec::new();
    let slots = if slot_count <= stack_slots.len() {
        &mut stack_slots[..slot_count]
    } else {
        heap_slots.resize(slot_count, HeaderSlot::EMPTY);
        &mut heap_slots
    };
    let head = response
        .parse_head(slots)
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
            let mut value = HeaderValue::from_maybe_shared(Bytes::from(bytes))
                .context("decode ICAP proxy header")?;
            if http_name.is_sensitive() {
                value.set_sensitive(true);
            }
            Ok(ForwardedIcapHeader { name, value })
        })
        .collect()
}

fn proxy_header_slot_count(head: &[u8]) -> Option<usize> {
    let mut lines = head.split(|byte| *byte == b'\n');
    lines.next()?;
    let mut count = 0;
    let mut found = false;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            continue;
        }
        count += 1;
        let name = line.split(|byte| *byte == b':').next().unwrap_or(line);
        found |= [header::PROXY_AUTHENTICATE, header::PROXY_AUTHORIZATION]
            .into_iter()
            .any(|expected| name.eq_ignore_ascii_case(expected.as_bytes()));
    }
    found.then_some(count)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_names_share_exact_ows_and_comma_parsing() {
        let mut headers = HeaderMap::new();
        headers.append(
            http_header::CONNECTION,
            HeaderValue::from_static(" keep-alive,\tX-Hop "),
        );
        headers.append(http_header::CONNECTION, HeaderValue::from_static("upgrade"));

        let names = connection_nominated_headers(&headers);
        assert_eq!(
            names.iter().map(HeaderName::as_str).collect::<Vec<_>>(),
            ["keep-alive", "X-Hop", "upgrade"]
        );
    }

    #[test]
    fn upgrade_headers_round_trip_around_sanitization() {
        let mut headers = HeaderMap::new();
        headers.append(
            http_header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        headers.append(http_header::CONNECTION, HeaderValue::from_static("x-hop"));
        headers.append(http_header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert("x-hop", HeaderValue::from_static("secret"));
        let preserved = preserve_upgrade_headers(&headers);

        sanitize_http_headers(&mut headers);
        restore_upgrade_headers(&mut headers, &preserved);

        assert_eq!(headers[http_header::CONNECTION], "upgrade");
        assert_eq!(headers[http_header::UPGRADE], "websocket");
        assert!(!headers.contains_key("x-hop"));

        let mut ordinary = HeaderMap::new();
        ordinary.insert(
            http_header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        let preserved = preserve_upgrade_headers(&ordinary);
        sanitize_http_headers(&mut ordinary);
        restore_upgrade_headers(&mut ordinary, &preserved);
        assert!(!ordinary.contains_key(http_header::CONNECTION));

        let mut missing_connection = HeaderMap::new();
        missing_connection.insert(http_header::UPGRADE, HeaderValue::from_static("websocket"));
        let preserved = preserve_upgrade_headers(&missing_connection);
        sanitize_http_headers(&mut missing_connection);
        restore_upgrade_headers(&mut missing_connection, &preserved);
        assert!(!missing_connection.contains_key(http_header::CONNECTION));
        assert!(!missing_connection.contains_key(http_header::UPGRADE));

        let mut missing_upgrade_token = HeaderMap::new();
        missing_upgrade_token.insert(
            http_header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        missing_upgrade_token.insert(http_header::UPGRADE, HeaderValue::from_static("websocket"));
        let preserved = preserve_upgrade_headers(&missing_upgrade_token);
        sanitize_http_headers(&mut missing_upgrade_token);
        restore_upgrade_headers(&mut missing_upgrade_token, &preserved);
        assert!(!missing_upgrade_token.contains_key(http_header::CONNECTION));
        assert!(!missing_upgrade_token.contains_key(http_header::UPGRADE));
    }

    #[test]
    fn proxy_header_preflight_is_anchored_and_counts_fields_not_folds() {
        let false_positive = b"ICAP/1.0 200 OK\r\nX-Pad: proxy-authenticate\r\n proxy-authorization\r\nEncapsulated: null-body=0\r\n\r\n";
        assert_eq!(proxy_header_slot_count(false_positive), None);

        let actual = b"ICAP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=test\r\n charset=UTF-8\r\nEncapsulated: null-body=0\r\n\r\n";
        assert_eq!(proxy_header_slot_count(actual), Some(2));
    }
}
