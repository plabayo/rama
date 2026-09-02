use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
};
use rama_http_types::{
    HeaderMap, Version,
    header::{
        self as http_header, HeaderName, HeaderValue,
        hop_by_hop::{HopByHopHeaderContext, connection_header_names},
        proxy_auth::{remove_proxy_auth_request_headers, remove_proxy_auth_response_headers},
    },
};

use crate::{
    codec::{DEFAULT_MAX_HEADERS, HeaderSlot},
    message::Response as IcapResponse,
    proto::header,
};

#[derive(Clone)]
pub(super) struct ForwardedIcapHeader {
    pub(super) name: &'static str,
    pub(super) value: HeaderValue,
}

#[derive(Default)]
pub(super) struct SanitizedHttpHead {
    forwarded_icap_headers: Vec<ForwardedIcapHeader>,
    hop_by_hop: HopByHopHeaderContext,
}

impl SanitizedHttpHead {
    pub(super) fn take(headers: &mut HeaderMap, version: Version) -> Self {
        let mut sanitized = Self::default();

        for (name, value) in headers.ordered_iter() {
            if name == http_header::PROXY_AUTHENTICATE {
                let mut value = value.clone();
                value.set_sensitive(true);
                sanitized.forwarded_icap_headers.push(ForwardedIcapHeader {
                    name: header::PROXY_AUTHENTICATE,
                    value,
                });
            } else if name == http_header::PROXY_AUTHORIZATION {
                let mut value = value.clone();
                value.set_sensitive(true);
                sanitized.forwarded_icap_headers.push(ForwardedIcapHeader {
                    name: header::PROXY_AUTHORIZATION,
                    value,
                });
            }
        }
        sanitized.hop_by_hop = HopByHopHeaderContext::take(headers, version);
        remove_proxy_auth_request_headers(headers);
        remove_proxy_auth_response_headers(headers);
        sanitized
    }

    pub(super) fn forwarded_icap_headers(&self) -> &[ForwardedIcapHeader] {
        &self.forwarded_icap_headers
    }

    pub(super) fn nominated_headers(&self) -> &[HeaderName] {
        self.hop_by_hop.nominated_headers()
    }

    pub(super) fn into_forwarded_and_nominated(
        self,
    ) -> (Vec<ForwardedIcapHeader>, Vec<HeaderName>) {
        (
            self.forwarded_icap_headers,
            self.hop_by_hop.nominated_headers().to_vec(),
        )
    }

    pub(super) fn restore_trailer_headers(&self, headers: &mut HeaderMap, version: Version) {
        self.hop_by_hop.restore_trailer_headers(headers, version);
    }

    pub(super) fn restore_response(
        &self,
        headers: &mut HeaderMap,
        version: Version,
        adapted_nominations: &[HeaderName],
    ) {
        self.hop_by_hop
            .restore_response(headers, version, adapted_nominations);
    }

    pub(super) fn restore_request(
        &self,
        headers: &mut HeaderMap,
        version: Version,
        adapted_nominations: &[HeaderName],
    ) {
        self.hop_by_hop
            .restore_request(headers, version, adapted_nominations);
    }
}

pub(super) fn connection_nominated_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    connection_header_names(headers).collect()
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
    fn http1_upgrade_intent_round_trips_original_spelling() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_bytes(b"CoNnEcTiOn").unwrap(),
            HeaderValue::from_static("keep-alive, UpGrAdE"),
        );
        headers.append(
            HeaderName::from_bytes(b"cOnNeCtIoN").unwrap(),
            HeaderValue::from_static("UPGRADE, x-hop"),
        );
        headers.append(
            HeaderName::from_bytes(b"UpGrAdE").unwrap(),
            HeaderValue::from_static("WebSocket"),
        );
        headers.append(
            HeaderName::from_bytes(b"uPgRaDe").unwrap(),
            HeaderValue::from_static("example/1"),
        );
        headers.insert("x-hop", HeaderValue::from_static("secret"));

        let sanitized = SanitizedHttpHead::take(&mut headers, Version::HTTP_11);
        sanitized.restore_response(&mut headers, Version::HTTP_11, &[]);

        assert!(!headers.contains_key("x-hop"));
        let restored = headers
            .ordered_iter()
            .map(|(name, value)| (name.as_original_str().into_owned(), value.to_str().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            restored,
            [
                ("CoNnEcTiOn".to_owned(), "UpGrAdE"),
                ("cOnNeCtIoN".to_owned(), "UPGRADE"),
                ("UpGrAdE".to_owned(), "WebSocket"),
                ("uPgRaDe".to_owned(), "example/1"),
            ]
        );
    }

    #[test]
    fn upgrade_intent_requires_http1_connection_nomination() {
        let mut ordinary = HeaderMap::new();
        ordinary.insert(
            http_header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        let sanitized = SanitizedHttpHead::take(&mut ordinary, Version::HTTP_11);
        sanitized.restore_response(&mut ordinary, Version::HTTP_11, &[]);
        assert!(!ordinary.contains_key(http_header::CONNECTION));

        let mut missing_connection = HeaderMap::new();
        missing_connection.insert(http_header::UPGRADE, HeaderValue::from_static("websocket"));
        let sanitized = SanitizedHttpHead::take(&mut missing_connection, Version::HTTP_11);
        sanitized.restore_response(&mut missing_connection, Version::HTTP_11, &[]);
        assert!(!missing_connection.contains_key(http_header::CONNECTION));
        assert!(!missing_connection.contains_key(http_header::UPGRADE));

        let mut missing_upgrade_token = HeaderMap::new();
        missing_upgrade_token.insert(
            http_header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        missing_upgrade_token.insert(http_header::UPGRADE, HeaderValue::from_static("websocket"));
        let sanitized = SanitizedHttpHead::take(&mut missing_upgrade_token, Version::HTTP_11);
        sanitized.restore_response(&mut missing_upgrade_token, Version::HTTP_11, &[]);
        assert!(!missing_upgrade_token.contains_key(http_header::CONNECTION));
        assert!(!missing_upgrade_token.contains_key(http_header::UPGRADE));
    }

    #[test]
    fn h2_never_restores_http1_upgrade_fields() {
        fn upgrade_headers() -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_bytes(b"Connection").unwrap(),
                HeaderValue::from_static("Upgrade"),
            );
            headers.insert(
                HeaderName::from_bytes(b"Upgrade").unwrap(),
                HeaderValue::from_static("websocket"),
            );
            headers
        }

        let mut h2_source = upgrade_headers();
        let sanitized = SanitizedHttpHead::take(&mut h2_source, Version::HTTP_2);
        sanitized.restore_response(&mut h2_source, Version::HTTP_11, &[]);
        assert!(h2_source.is_empty());

        let mut http1_source = upgrade_headers();
        let sanitized = SanitizedHttpHead::take(&mut http1_source, Version::HTTP_11);
        sanitized.restore_response(&mut http1_source, Version::HTTP_2, &[]);
        assert!(http1_source.is_empty());
    }

    #[test]
    fn request_restoration_reoriginates_only_te_trailers() {
        for (version, expects_connection) in [
            (Version::HTTP_11, true),
            (Version::HTTP_2, false),
            (Version::HTTP_3, false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                http_header::CONNECTION,
                HeaderValue::from_static("close, TE"),
            );
            headers.insert(http_header::TE, HeaderValue::from_static("gzip, trailers"));

            let sanitized = SanitizedHttpHead::take(&mut headers, version);
            sanitized.restore_request(&mut headers, version, &[]);

            assert_eq!(headers[http_header::TE], "trailers");
            assert_eq!(
                headers.contains_key(http_header::CONNECTION),
                expects_connection
            );
            if expects_connection {
                assert_eq!(headers[http_header::CONNECTION], "TE");
            }
        }
    }

    #[test]
    fn connection_nomination_suppresses_trailer_declaration() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(b"Connection").unwrap(),
            HeaderValue::from_static("Trailer"),
        );
        headers.insert(
            HeaderName::from_bytes(b"TrAiLeR").unwrap(),
            HeaderValue::from_static("x-checksum"),
        );

        let sanitized = SanitizedHttpHead::take(&mut headers, Version::HTTP_11);
        sanitized.restore_response(&mut headers, Version::HTTP_11, &[]);

        assert!(!headers.contains_key(http_header::CONNECTION));
        assert!(!headers.contains_key(http_header::TRAILER));
    }

    #[test]
    fn adapted_nomination_suppresses_original_trailer_declaration() {
        let mut original = HeaderMap::new();
        original.insert(
            HeaderName::from_bytes(b"TrAiLeR").unwrap(),
            HeaderValue::from_static("x-original"),
        );
        let original = SanitizedHttpHead::take(&mut original, Version::HTTP_11);

        let mut adapted = HeaderMap::new();
        adapted.insert(http_header::CONNECTION, HeaderValue::from_static("Trailer"));
        adapted.insert(http_header::TRAILER, HeaderValue::from_static("x-adapted"));
        let adapted_head = SanitizedHttpHead::take(&mut adapted, Version::HTTP_11);
        adapted_head.restore_trailer_headers(&mut adapted, Version::HTTP_11);
        original.restore_response(
            &mut adapted,
            Version::HTTP_11,
            adapted_head.nominated_headers(),
        );

        assert!(!adapted.contains_key(http_header::CONNECTION));
        assert!(!adapted.contains_key(http_header::TRAILER));
    }

    #[test]
    fn proxy_header_preflight_is_anchored_and_counts_fields_not_folds() {
        let false_positive = b"ICAP/1.0 200 OK\r\nX-Pad: proxy-authenticate\r\n proxy-authorization\r\nEncapsulated: null-body=0\r\n\r\n";
        assert_eq!(proxy_header_slot_count(false_positive), None);

        let actual = b"ICAP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=test\r\n charset=UTF-8\r\nEncapsulated: null-body=0\r\n\r\n";
        assert_eq!(proxy_header_slot_count(actual), Some(2));
    }
}
