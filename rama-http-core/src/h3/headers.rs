//! Validate decoded HTTP fields before normalization can hide malformed input.

use super::{Error, qpack::FieldPair};
use rama_core::{bytes::Bytes, extensions::ExtensionsRef};
use rama_http_types::proto::h3::{Code, PseudoHeader, PseudoHeaderOrder, PseudoHeaderSensitivity};
use rama_http_types::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version, header,
};
use rama_net::{
    Protocol,
    address::{Authority, AuthorityRef},
    uri::Uri,
};

#[derive(Default)]
struct Fields {
    headers: HeaderMap,
    order: PseudoHeaderOrder,
    sensitivity: PseudoHeaderSensitivity,
    method: Option<Bytes>,
    scheme: Option<Bytes>,
    authority: Option<Bytes>,
    path: Option<Bytes>,
    status: Option<Bytes>,
}

fn malformed(reason: &'static str) -> Error {
    Error::stream(Code::H3_MESSAGE_ERROR, reason)
}

fn parse(fields: Vec<FieldPair>, trailers: bool) -> Result<Fields, Error> {
    let mut result = Fields::default();
    let mut regular = false;
    for field in fields {
        if field.name.first() == Some(&b':') {
            if !header::is_valid_h2_h3_field_value(&field.value) {
                return Err(malformed("invalid pseudo-header value"));
            }
            if regular || trailers {
                return Err(malformed("misplaced pseudo-header"));
            }
            let pseudo = PseudoHeader::from_bytes(&field.name)
                .map_err(|_error| malformed("unknown pseudo-header"))?;
            let slot = match pseudo {
                PseudoHeader::Method => &mut result.method,
                PseudoHeader::Scheme => &mut result.scheme,
                PseudoHeader::Authority => &mut result.authority,
                PseudoHeader::Path => &mut result.path,
                PseudoHeader::Status => &mut result.status,
                PseudoHeader::Protocol => return Err(malformed("extended CONNECT is not enabled")),
            };
            if slot.replace(field.value).is_some() {
                return Err(malformed("duplicate pseudo-header"));
            }
            result.order.push(pseudo);
            result.sensitivity.set_sensitive(pseudo, field.never_index);
            continue;
        }
        regular = true;
        let name = HeaderName::from_lowercase_bytes(field.name)
            .map_err(|_error| malformed("invalid field name"))?;
        validate_name(&name, &field.value, trailers)?;
        let mut value = HeaderValue::from_maybe_shared(field.value)
            .map_err(|_error| malformed("invalid field value"))?;
        validate_value(&value)?;
        value.set_sensitive(field.never_index);
        result.headers.append(name, value);
    }
    Ok(result)
}

fn validate_value(value: &HeaderValue) -> Result<(), Error> {
    if value.has_outer_whitespace() {
        return Err(malformed("invalid field value"));
    }
    Ok(())
}

fn validate_name(name: &HeaderName, value: &[u8], trailers: bool) -> Result<(), Error> {
    if header::hop_by_hop::CONNECTION_SPECIFIC_HEADERS.contains(&name)
        || (*name == header::TE && (trailers || !value.eq_ignore_ascii_case(b"trailers")))
    {
        return Err(malformed("connection-specific field"));
    }
    if trailers && [header::CONTENT_LENGTH, header::HOST].contains(name) {
        return Err(malformed("message framing field in trailers"));
    }
    Ok(())
}

pub(crate) fn validate_regular(headers: &HeaderMap, trailers: bool) -> Result<(), Error> {
    for (name, value) in headers {
        validate_name(name, value.as_bytes(), trailers)?;
        // Applications can construct HeaderValue through its unchecked API.
        // Recheck wire constraints at the outgoing boundary as well.
        if !header::is_valid_h2_h3_field_value(value.as_bytes()) {
            return Err(malformed("invalid field value"));
        }
    }
    content_length(headers)?;
    Ok(())
}

pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<u64>, Error> {
    if !headers.contains_key(header::CONTENT_LENGTH) {
        return Ok(None);
    }
    crate::headers::content_length_parse_all(headers)
        .map(Some)
        .ok_or(malformed("invalid content-length"))
}

fn text(bytes: &Bytes) -> Result<&str, Error> {
    std::str::from_utf8(bytes).map_err(|_error| malformed("invalid pseudo-header value"))
}

pub(crate) fn request(fields: Vec<FieldPair>) -> Result<Request<()>, Error> {
    let mut fields = parse(fields, false)?;
    content_length(&fields.headers)?;
    if fields.status.is_some() {
        return Err(malformed("status in request"));
    }
    let method = Method::from_bytes(
        fields
            .method
            .as_deref()
            .ok_or(malformed("missing method"))?,
    )
    .map_err(|_error| malformed("invalid method"))?;
    let host_values = fields.headers.get_all(header::HOST);
    let mut hosts = host_values.iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return Err(malformed("duplicate Host"));
    }
    // Normalizing Host into the URI must retain its compression restriction
    // when a subsequent HTTP/2 or HTTP/3 encoder emits it as :authority.
    if fields.authority.is_none() && host.is_some_and(HeaderValue::is_sensitive) {
        fields
            .sensitivity
            .set_sensitive(PseudoHeader::Authority, true);
    }
    let authority = fields
        .authority
        .as_deref()
        .or_else(|| host.map(HeaderValue::as_bytes));
    if authority.is_some_and(|value| value.is_empty()) {
        return Err(malformed("empty authority"));
    }
    if let (Some(authority), Some(host)) = (authority, host)
        && !authority.eq_ignore_ascii_case(host.as_bytes())
    {
        return Err(malformed("authority and Host disagree"));
    }
    let authority = authority
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_error| malformed("invalid authority"))?;
    if let Some(authority) = authority {
        AuthorityRef::try_from(authority).map_err(|_error| malformed("invalid authority"))?;
    }
    let mut asterisk_scheme = None;
    let uri = if method == Method::CONNECT {
        if fields.scheme.is_some() || fields.path.is_some() || fields.authority.is_none() {
            return Err(malformed("invalid CONNECT pseudo-headers"));
        }
        Uri::parse_http_request_target(
            authority.ok_or(malformed("missing CONNECT authority"))?,
            true,
        )
        .map_err(|_error| malformed("invalid CONNECT authority"))?
    } else {
        let scheme = text(fields.scheme.as_ref().ok_or(malformed("missing scheme"))?)?;
        let path = text(fields.path.as_ref().ok_or(malformed("missing path"))?)?;
        let http_scheme =
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
        if http_scheme
            && (authority.is_none() || authority.is_some_and(|value| value.contains('@')))
        {
            return Err(malformed("HTTP URI requires an authority without userinfo"));
        }
        if !(path.starts_with('/')
            || (method == Method::OPTIONS && path == "*")
            || (!http_scheme && path.is_empty()))
            || path.contains('#')
        {
            return Err(malformed("invalid request path"));
        }
        let scheme = scheme
            .parse::<Protocol>()
            .map_err(|_error| malformed("invalid scheme"))?;
        if path == "*" {
            asterisk_scheme = Some(scheme.clone());
        }
        let mut uri = if path == "*" {
            Uri::parse("*").map_err(|_error| malformed("invalid asterisk target"))?
        } else if path.is_empty() {
            Uri::default().without_path()
        } else {
            Uri::parse_http_request_target(path, false)
                .map_err(|_error| malformed("invalid request path"))?
        };
        if path != "*" {
            if let Some(authority) = authority {
                uri.set_authority(
                    Authority::try_from(authority)
                        .map_err(|_error| malformed("invalid authority"))?,
                );
            }
            uri.set_scheme(scheme);
        }
        uri
    };
    let mut request = Request::new(());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_3;
    *request.headers_mut() = fields.headers;
    request.extensions().insert(fields.order);
    if fields.sensitivity != PseudoHeaderSensitivity::default() {
        request.extensions().insert(fields.sensitivity);
    }
    if let Some(scheme) = asterisk_scheme {
        request.extensions().insert(scheme);
        if !request.headers().contains_key(header::HOST)
            && let Some(authority) = fields.authority
        {
            let mut host = HeaderValue::from_maybe_shared(authority)
                .map_err(|_error| malformed("invalid authority"))?;
            host.set_sensitive(fields.sensitivity.is_sensitive(PseudoHeader::Authority));
            request.headers_mut().insert(header::HOST, host);
        }
    }
    // Preserve split Cookie lines in this H3 context, as the H2 decoder does.
    // RFC 9114 §4.2.1 requires coalescing at the boundary to a non-H2/H3 context;
    // the HTTP/1 version adapter already handles that conversion.
    Ok(request)
}

#[cfg(test)]
pub(crate) fn response(fields: Vec<FieldPair>) -> Result<Response<()>, Error> {
    response_for_method(fields, false)
}

pub(crate) fn response_for_method(
    fields: Vec<FieldPair>,
    connect: bool,
) -> Result<Response<()>, Error> {
    let mut fields = parse(fields, false)?;
    if fields.headers.contains_key(header::TE) {
        return Err(malformed("TE forbidden in response"));
    }
    if fields.method.is_some()
        || fields.scheme.is_some()
        || fields.authority.is_some()
        || fields.path.is_some()
    {
        return Err(malformed("request pseudo-header in response"));
    }
    let status = StatusCode::from_bytes(
        fields
            .status
            .as_deref()
            .ok_or(malformed("missing status"))?,
    )
    .map_err(|_error| malformed("invalid status"))?;
    if status == StatusCode::SWITCHING_PROTOCOLS {
        return Err(malformed("101 is forbidden in HTTP/3"));
    }
    if connect && status.is_success() {
        // RFC 9110 §9.3.6: successful CONNECT ignores Content-Length entirely.
        fields.headers.remove(header::CONTENT_LENGTH);
    } else {
        content_length(&fields.headers)?;
    }
    if (status.is_informational() || status == StatusCode::NO_CONTENT)
        && fields.headers.contains_key(header::CONTENT_LENGTH)
    {
        return Err(malformed("content-length forbidden on this response"));
    }
    let mut response = Response::new(());
    *response.status_mut() = status;
    *response.version_mut() = Version::HTTP_3;
    *response.headers_mut() = fields.headers;
    response.extensions().insert(fields.order);
    if fields.sensitivity != PseudoHeaderSensitivity::default() {
        response.extensions().insert(fields.sensitivity);
    }
    Ok(response)
}

pub(crate) fn trailers(fields: Vec<FieldPair>) -> Result<HeaderMap, Error> {
    Ok(parse(fields, true)?.headers)
}

pub(crate) fn encode_request<B>(
    shared: &super::connection::Shared,
    id: u64,
    request: &Request<B>,
) -> Result<Bytes, Error> {
    use super::qpack::EncodeField;
    use rama_core::bytes::BytesMut;
    validate_regular(request.headers(), false)?;
    let connect = request.method() == Method::CONNECT;
    if request.uri().fragment().is_some() || (connect && request.uri().port_u16().is_none()) {
        return Err(malformed("invalid request target"));
    }
    // Serialize only components that need wire normalization into one buffer.
    // The scheme and header values can remain borrowed from the request.
    let mut target = BytesMut::new();
    if request.uri().authority().is_some() {
        request
            .uri()
            .write_h2_authority(&mut target)
            .map_err(|_error| malformed("invalid request authority"))?;
    }
    let host_values = request.headers().get_all(header::HOST);
    let mut hosts = host_values.iter();
    if let Some(host) = hosts.next() {
        let parsed_host = AuthorityRef::try_from(host.as_bytes())
            .map_err(|_error| malformed("invalid Host authority"))?;
        if parsed_host.userinfo().is_some() {
            return Err(malformed("Host must not contain userinfo"));
        }
        if host.is_empty()
            || hosts.next().is_some()
            || (!target.is_empty() && !target.eq_ignore_ascii_case(host.as_bytes()))
        {
            return Err(malformed("invalid Host or authority mismatch"));
        }
    } else if target.is_empty()
        && (connect || matches!(request.uri().scheme_str(), Some("http" | "https")))
    {
        return Err(malformed("missing request authority"));
    }
    let scheme = if connect {
        ""
    } else if request.uri().is_asterisk() {
        if request.method() != Method::OPTIONS {
            return Err(malformed("asterisk requires OPTIONS"));
        }
        let protocol = request
            .extensions()
            .get_ref::<Protocol>()
            .ok_or(malformed("missing request scheme"))?;
        if let Some(host) = request.headers().get(header::HOST) {
            target.extend_from_slice(host.as_bytes());
        }
        protocol.as_str()
    } else {
        request
            .uri()
            .scheme_str()
            .ok_or(malformed("missing request scheme"))?
    };

    let authority_len = target.len();
    if !connect
        && (request.uri().is_asterisk()
            || matches!(scheme, "http" | "https")
            || !request.uri().is_path_empty())
    {
        request.uri().write_h2_path(&mut target);
    }
    let (authority, path) = target.split_at(authority_len);
    if matches!(scheme, "http" | "https")
        && authority.is_empty()
        && !request.headers().contains_key(header::HOST)
    {
        return Err(malformed("HTTP URI requires authority"));
    }
    let mut pseudo = [
        Some((PseudoHeader::Method, request.method().as_str().as_bytes())),
        (!authority.is_empty()).then_some((PseudoHeader::Authority, authority)),
        (!connect).then_some((PseudoHeader::Scheme, scheme.as_bytes())),
        (!connect).then_some((PseudoHeader::Path, path)),
    ];
    let mut order = request
        .extensions()
        .get_ref::<PseudoHeaderOrder>()
        .cloned()
        .unwrap_or_default();
    // Keep the requested order and append newly applicable pseudo-headers.
    // Taking each slot also ignores inapplicable entries after a method change.
    order.extend(pseudo.iter().flatten().map(|(name, _)| *name));
    let mut sensitivity = request
        .extensions()
        .get_ref::<PseudoHeaderSensitivity>()
        .copied()
        .unwrap_or_default();
    if request.uri().is_asterisk()
        && request
            .headers()
            .get(header::HOST)
            .is_some_and(HeaderValue::is_sensitive)
    {
        // An asterisk URI has no authority; the value above came from Host.
        sensitivity.set_sensitive(PseudoHeader::Authority, true);
    }
    let pseudo = order.into_iter().filter_map(|name| {
        pseudo
            .iter_mut()
            .find(|field| field.as_ref().is_some_and(|(key, _)| *key == name))
            .and_then(Option::take)
            .map(|(name, value)| EncodeField {
                name: std::borrow::Cow::Borrowed(name.as_bytes()),
                value,
                never_index: sensitivity.is_sensitive(name),
            })
    });
    shared.encode(
        id,
        pseudo.chain(
            request
                .headers()
                .ordered_iter()
                .map(|(name, value)| EncodeField::from_header(name, value)),
        ),
    )
}

pub(crate) fn encode_response<B>(
    shared: &super::connection::Shared,
    id: u64,
    response: &Response<B>,
) -> Result<Bytes, Error> {
    use super::qpack::EncodeField;
    validate_regular(response.headers(), false)?;
    if response.headers().contains_key(header::TE) {
        return Err(malformed("TE forbidden in response"));
    }
    if response.status() == StatusCode::SWITCHING_PROTOCOLS
        || ((response.status().is_informational() || response.status() == StatusCode::NO_CONTENT)
            && response.headers().contains_key(header::CONTENT_LENGTH))
    {
        return Err(malformed("invalid response status or content-length"));
    }
    shared.encode(
        id,
        std::iter::once(EncodeField {
            name: std::borrow::Cow::Borrowed(PseudoHeader::Status.as_bytes()),
            value: response.status().as_str().as_bytes(),
            never_index: response
                .extensions()
                .get_ref::<PseudoHeaderSensitivity>()
                .is_some_and(|sensitivity| sensitivity.is_sensitive(PseudoHeader::Status)),
        })
        .chain(
            response
                .headers()
                .ordered_iter()
                .map(|(name, value)| EncodeField::from_header(name, value)),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fields(values: &[(&'static str, &'static str)]) -> Vec<FieldPair> {
        values
            .iter()
            .map(|(name, value)| FieldPair {
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
                never_index: false,
            })
            .collect()
    }

    #[test]
    fn incoming_and_outgoing_field_boundaries_are_rejected() {
        for value in [" leading", "trailing ", "\tleading", "trailing\t"] {
            assert!(parse(fields(&[("x-test", value)]), false).is_err());
            let mut headers = HeaderMap::new();
            headers.insert("x-test", HeaderValue::from_static(value));
            assert!(validate_regular(&headers, false).is_err());
        }
        for value in ["", "internal \t whitespace", "\"quoted\""] {
            let parsed = parse(fields(&[("x-test", value)]), false).unwrap();
            validate_regular(&parsed.headers, false).unwrap();
        }
        for value in ["nul\0byte", "new\nline", "carriage\rreturn"] {
            assert!(parse(fields(&[("x-test", value)]), false).is_err());
            assert!(parse(fields(&[(":path", value)]), false).is_err());
        }
    }

    #[test]
    fn connection_fields_are_rejected_but_trailer_declarations_are_allowed() {
        for name in header::hop_by_hop::CONNECTION_SPECIFIC_HEADERS {
            assert!(validate_name(name, b"value", false).is_err());
            assert!(validate_name(name, b"value", true).is_err());
        }
        validate_name(&header::TRAILER, b"x-checksum", false).unwrap();
        validate_name(&header::TE, b"trailers", false).unwrap();
    }

    #[test]
    fn te_trailers_is_case_insensitive() {
        // RFC 9110 §10.1.4 defines the keyword using case-insensitive ABNF.
        for value in ["trailers", "Trailers", "TRAILERS"] {
            let mut request = request(fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", "/"),
                ("te", value),
            ]))
            .unwrap();
            validate_regular(request.headers(), false).unwrap();
            validate_regular(request.headers(), true).unwrap_err();
            request
                .headers_mut()
                .insert(header::TE, HeaderValue::from_static("gzip"));
            validate_regular(request.headers(), false).unwrap_err();
        }
    }

    #[test]
    fn outgoing_host_fallback_is_validated_before_encoding() {
        let shared = crate::h3::connection::Shared::new(
            crate::h3::connection::Config::default(),
            crate::h3::control::Role::Client,
            Default::default(),
        )
        .unwrap();
        for host in ["bad host", "user@example.com", "[invalid]"] {
            let mut request = Request::new(());
            *request.uri_mut() = Uri::parse("custom:/path").unwrap();
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_static(host));
            encode_request(&shared, 0, &request).unwrap_err();
        }
    }

    #[test]
    fn empty_cookie_segments_and_individual_sensitivity_are_preserved() {
        let mut input = fields(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
            ("cookie", ""),
            ("cookie", "session=secret"),
            ("cookie", ""),
        ]);
        input[5].never_index = true;
        let request = request(input).unwrap();
        let cookies: Vec<_> = request.headers().get_all(header::COOKIE).iter().collect();
        assert_eq!(
            cookies
                .iter()
                .map(|value| value.as_bytes())
                .collect::<Vec<_>>(),
            [b"".as_slice(), b"session=secret", b""]
        );
        assert!(!cookies[0].is_sensitive());
        assert!(cookies[1].is_sensitive());
        assert!(!cookies[2].is_sensitive());
    }

    fn shared() -> std::sync::Arc<crate::h3::connection::Shared> {
        crate::h3::connection::Shared::new(
            crate::h3::connection::Config::default(),
            crate::h3::control::Role::Client,
            Default::default(),
        )
        .unwrap()
    }

    fn decode(encoded: Bytes) -> Vec<FieldPair> {
        crate::h3::qpack::Decoder::new(crate::h3::qpack::DecoderConfig::default())
            .decode_field_section(0, encoded)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn request_relay_preserves_each_pseudo_order_and_interleaved_field_lines() {
        let pseudo = [
            (":path", "/a%2Fb?x=1&x=2"),
            (":authority", "example.com:8443"),
            (":scheme", "https"),
            (":method", "GET"),
        ];
        // Every permutation is valid as long as pseudo-fields precede regular fields.
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let indices = [a, b, c, d];
                        if (0..4).any(|i| indices[i + 1..].contains(&indices[i])) {
                            continue;
                        }
                        let mut input = fields(&indices.map(|i| pseudo[i]));
                        input.extend(fields(&[
                            ("x-first", "one"),
                            ("cookie", ""),
                            ("x-middle", "Keep CASE"),
                            ("x-first", "two"),
                            ("cookie", "session=secret"),
                            ("x-last", ""),
                        ]));
                        input[0].never_index = true;
                        input[8].never_index = true;
                        let request = request(input.clone()).unwrap();
                        let received_order: Vec<_> = request
                            .extensions()
                            .get_ref::<PseudoHeaderOrder>()
                            .unwrap()
                            .iter()
                            .map(|name| name.as_str())
                            .collect();
                        assert_eq!(received_order, indices.map(|i| pseudo[i].0));
                        assert_eq!(
                            decode(encode_request(&shared(), 0, &request).unwrap()),
                            input
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn response_and_trailers_relay_preserve_interleaved_fields_and_sensitivity() {
        let mut regular = fields(&[
            ("set-cookie", "first=1"),
            ("x-middle", "Keep CASE"),
            ("set-cookie", "second=2"),
            ("x-middle", ""),
        ]);
        regular[2].never_index = true;
        let mut input = fields(&[(":status", "200")]);
        input[0].never_index = true;
        input.extend(regular.clone());
        let response = response(input.clone()).unwrap();
        assert_eq!(
            decode(encode_response(&shared(), 0, &response).unwrap()),
            input
        );

        let trailers = trailers(regular.clone()).unwrap();
        assert_eq!(
            decode(crate::h3::stream::encode_trailers(&shared(), 0, &trailers).unwrap()),
            regular
        );
    }

    #[test]
    fn outgoing_custom_names_are_lowercase_without_mutating_the_header_map() {
        let mut request = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();
        let name = HeaderName::from_bytes(b"X-Custom-CASE").unwrap();
        request
            .headers_mut()
            .append(name, HeaderValue::from_static("Keep CASE"));
        let output = decode(encode_request(&shared(), 0, &request).unwrap());
        assert_eq!(output.last().unwrap().name, "x-custom-case");
        assert_eq!(output.last().unwrap().value, "Keep CASE");
        assert_eq!(
            request
                .headers()
                .ordered_iter()
                .next()
                .unwrap()
                .0
                .as_original_str(),
            "X-Custom-CASE"
        );
    }

    #[test]
    fn qpack_never_index_requirements_survive_hpack_forwarding() {
        use rama_core::bytes::{BufMut, BytesMut};
        use rama_http_types::proto::h2::{frame, hpack};

        let mut input = fields(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
            ("x-private", "secret"),
        ]);
        // Include exact static-table matches: indexing them would silently drop N.
        for field in &mut input {
            field.never_index = true;
        }
        let request = request(input.clone()).unwrap();
        let request =
            self::request(decode(encode_request(&shared(), 0, &request).unwrap())).unwrap();
        let (frame, _) = crate::h2::client::Peer::convert_send_message(
            frame::StreamId::from(1),
            request,
            None,
            true,
            None,
            None,
        )
        .unwrap();
        let mut wire = BytesMut::new();
        assert!(
            frame
                .encode(&mut hpack::Encoder::default(), &mut (&mut wire).limit(4096))
                .is_none()
        );
        let head = frame::Head::parse(&wire[..9]).unwrap();
        let (mut frame, mut payload) = frame::Headers::load(head, wire.split_off(9)).unwrap();
        frame
            .load_hpack(&mut payload, 4096, &mut hpack::Decoder::new(4096))
            .unwrap();
        let (pseudo, headers) = frame.into_parts();
        let mut forwarded = self::request(fields(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
        ]))
        .unwrap();
        forwarded.extensions().insert(pseudo.sensitivity);
        *forwarded.headers_mut() = headers;
        assert_eq!(
            decode(encode_request(&shared(), 0, &forwarded).unwrap()),
            input
        );
    }

    #[test]
    fn request_edits_use_current_values_and_append_new_pseudo_fields() {
        let mut request = request(fields(&[
            (":authority", "example.com:443"),
            (":method", "CONNECT"),
            ("x-untouched", "one"),
            ("x-change", "before"),
            ("x-untouched", "two"),
        ]))
        .unwrap();
        *request.method_mut() = Method::POST;
        *request.uri_mut() = Uri::parse("https://example.com:443/new").unwrap();
        request
            .headers_mut()
            .insert("x-change", HeaderValue::from_static("after"));
        let output = decode(encode_request(&shared(), 0, &request).unwrap());
        assert_eq!(
            &output[..4],
            &fields(&[
                (":authority", "example.com:443"),
                (":method", "POST"),
                (":scheme", "https"),
                (":path", "/new"),
            ])
        );
        assert_eq!(
            output
                .iter()
                .filter(|field| field.name == "x-untouched")
                .map(|field| field.value.as_ref())
                .collect::<Vec<_>>(),
            [b"one", b"two"]
        );
        assert!(
            output
                .iter()
                .any(|field| field.name == "x-change" && field.value == "after")
        );

        *request.method_mut() = Method::CONNECT;
        *request.uri_mut() = Uri::parse_http_request_target("other.example:8443", true).unwrap();
        let output = decode(encode_request(&shared(), 0, &request).unwrap());
        assert_eq!(
            &output[..2],
            &fields(&[(":authority", "other.example:8443"), (":method", "CONNECT")])
        );
        assert!(
            output
                .iter()
                .all(|field| field.name != ":path" && field.name != ":scheme")
        );
    }

    #[test]
    fn raw_names_and_values_are_rejected_before_normalization() {
        for name in ["", "Upper", "bad name", ":Status", ":status ", ":protocol"] {
            response(fields(&[(":status", "200"), (name, "x")])).unwrap_err();
        }
        for value in [" leading", "trailing\t", "a\0b", "a\rb", "a\nb"] {
            response(fields(&[(":status", "200"), ("x", value)])).unwrap_err();
        }
    }

    #[test]
    fn request_response_and_trailer_field_rules() {
        for name in [
            "connection",
            "proxy-connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
        ] {
            response(fields(&[(":status", "200"), (name, "x")])).unwrap_err();
            trailers(fields(&[(name, "x")])).unwrap_err();
        }
        for name in ["content-length", "host", "te"] {
            trailers(fields(&[(name, "0")])).unwrap_err();
        }
        response(fields(&[(":status", "200"), ("te", "trailers")])).unwrap_err();
        response(fields(&[(":status", "103"), ("content-length", "0")])).unwrap_err();
        let response = response_for_method(
            fields(&[(":status", "200"), ("content-length", "invalid")]),
            true,
        )
        .unwrap();
        assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
        trailers(fields(&[("x-checksum", "abc")])).unwrap();
    }

    #[test]
    fn response_rejects_each_request_pseudo_header_independently() {
        for pseudo in [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
        ] {
            let error = response(fields(&[(":status", "200"), pseudo])).unwrap_err();
            assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
            assert_eq!(error.scope(), crate::h3::qpack::ErrorScope::Stream);
        }
    }

    #[test]
    fn request_paths_and_connect() {
        for path in ["/", "//double/slash", "/?query=1"] {
            let req = request(fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", path),
            ]))
            .unwrap();
            assert_eq!(req.uri().request_target(), path);
        }
        let req = request(fields(&[
            (":method", "CONNECT"),
            (":authority", "example.com:443"),
        ]))
        .unwrap();
        assert_eq!(
            req.uri().authority().unwrap().to_string(),
            "example.com:443"
        );
        request(fields(&[
            (":method", "CONNECT"),
            (":authority", "example.com"),
        ]))
        .unwrap_err();
    }

    #[test]
    fn sensitive_host_fallback_preserves_synthesized_authority_sensitivity() {
        use rama_http_types::proto::h2::frame::StreamId;

        for path in ["/", "*"] {
            let mut input = fields(&[
                (":method", "OPTIONS"),
                (":scheme", "https"),
                (":path", path),
                ("host", "example.com"),
            ]);
            input[3].never_index = true;
            let request = request(input).unwrap();
            assert!(
                request
                    .extensions()
                    .get_ref::<PseudoHeaderSensitivity>()
                    .unwrap()
                    .is_sensitive(PseudoHeader::Authority)
            );
            let output = decode(encode_request(&shared(), 0, &request).unwrap());
            assert!(
                output
                    .iter()
                    .find(|field| field.name == ":authority")
                    .unwrap()
                    .never_index
            );
            assert!(
                output
                    .iter()
                    .find(|field| field.name == "host")
                    .unwrap()
                    .never_index
            );

            if path == "/" {
                let (frame, _) = crate::h2::client::Peer::convert_send_message(
                    StreamId::from(1),
                    request,
                    None,
                    true,
                    None,
                    None,
                )
                .unwrap();
                assert!(
                    frame
                        .pseudo()
                        .sensitivity
                        .is_sensitive(PseudoHeader::Authority)
                );
            }
        }
    }

    #[test]
    fn options_asterisk_survives_forwarding() {
        let req = request(fields(&[
            (":method", "OPTIONS"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "*"),
        ]))
        .unwrap();
        assert!(req.uri().is_asterisk());
        assert_eq!(req.uri().request_target(), "*");
        assert_eq!(req.headers()[header::HOST], "example.com");
        let shared = crate::h3::connection::Shared::new(
            crate::h3::connection::Config::default(),
            crate::h3::control::Role::Client,
            Default::default(),
        )
        .unwrap();
        let encoded = encode_request(&shared, 0, &req).unwrap();
        let mut decoder =
            crate::h3::qpack::Decoder::new(crate::h3::qpack::DecoderConfig::default());
        let decoded = request(decoder.decode_field_section(0, encoded).unwrap().unwrap()).unwrap();
        assert!(decoded.uri().is_asterisk());
        assert_eq!(decoded.headers()[header::HOST], "example.com");
    }

    #[test]
    fn options_asterisk_preserves_authority_and_host_sensitivity() {
        for existing_host in [false, true] {
            let mut input = fields(&[
                (":method", "OPTIONS"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", "*"),
            ]);
            input[2].never_index = !existing_host;
            if existing_host {
                input.push(FieldPair {
                    name: Bytes::from_static(b"host"),
                    value: Bytes::from_static(b"EXAMPLE.COM"),
                    never_index: true,
                });
            }
            let request = request(input).unwrap();
            assert!(request.headers()[header::HOST].is_sensitive());
            if existing_host {
                assert_eq!(request.headers()[header::HOST], "EXAMPLE.COM");
            }
            let output = decode(encode_request(&shared(), 0, &request).unwrap());
            assert!(
                output
                    .iter()
                    .find(|field| field.name == "host")
                    .unwrap()
                    .never_index
            );
            assert!(
                output
                    .iter()
                    .find(|field| field.name == ":authority")
                    .unwrap()
                    .never_index
            );
        }
    }

    #[test]
    fn rejects_before_header_normalization() {
        for bad in [
            vec![(":status", "200"), ("Upper", "value")],
            vec![("x", "v"), (":status", "200")],
            vec![(":status", "200"), (":status", "200")],
            vec![(":status", "101")],
            vec![(":status", "204"), ("content-length", "0")],
            vec![(":status", "200"), ("connection", "close")],
            vec![(":status", "200"), ("x", " value")],
            vec![
                (":status", "200"),
                ("content-length", "1"),
                ("content-length", "2"),
            ],
        ] {
            assert_eq!(
                response(fields(&bad)).unwrap_err().code(),
                Code::H3_MESSAGE_ERROR
            );
        }
        trailers(fields(&[(":status", "200")])).unwrap_err();
    }

    #[test]
    fn response_values_share_bytes_and_preserve_sensitivity() {
        let value = Bytes::from_static(b"secret");
        let mut input = fields(&[(":status", "200")]);
        input.push(FieldPair {
            name: Bytes::from_static(b"x-secret"),
            value: value.clone(),
            never_index: true,
        });
        let resp = response(input).unwrap();
        assert_eq!(
            resp.headers()["x-secret"].as_bytes().as_ptr(),
            value.as_ptr()
        );
        assert!(resp.headers()["x-secret"].is_sensitive());
    }
}
