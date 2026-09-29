//! Validate decoded HTTP fields before normalization can hide malformed input.

use super::{
    Error,
    qpack::{EncodeField, FieldPair},
};
use rama_core::{
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef,
};
use rama_http_types::proto::{
    ext,
    h3::{Code, PseudoHeader, PseudoHeaderOrder, PseudoHeaderSensitivity},
};
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
    protocol: Option<Bytes>,
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
                PseudoHeader::Protocol => &mut result.protocol,
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
        result
            .headers
            .try_append(name, value)
            .map_err(|_error| Error::stream(Code::H3_EXCESSIVE_LOAD, "too many header fields"))?;
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

/// Decode a request head. `extended_connect` is whether this endpoint advertised
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL`; `:protocol` is malformed otherwise (RFC 8441 §3).
#[cfg(test)]
pub(crate) fn request(fields: Vec<FieldPair>) -> Result<Request<()>, Error> {
    request_head(fields, false)
}

pub(crate) fn request_head(
    fields: Vec<FieldPair>,
    extended_connect: bool,
) -> Result<Request<()>, Error> {
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
    let protocol = fields
        .protocol
        .take()
        .map(|value| {
            if !extended_connect {
                return Err(malformed("extended CONNECT is not enabled"));
            }
            // RFC 8441 §4: Extended CONNECT carries :scheme, :path and an ordinary :authority.
            if method != Method::CONNECT || fields.scheme.is_none() || fields.path.is_none() {
                return Err(malformed("invalid extended CONNECT pseudo-headers"));
            }
            ext::Protocol::try_from_bytes(value).map_err(|_error| malformed("invalid :protocol"))
        })
        .transpose()?;
    let host_values = fields.headers.get_all(header::HOST);
    let mut hosts = host_values.iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return Err(malformed("duplicate Host"));
    }
    // RFC 9110 §7.2: Host is `uri-host [":" port]` for every scheme, as encoding requires.
    if let Some(host) = host
        && AuthorityRef::try_from(host.as_bytes())
            .map_err(|_error| malformed("invalid Host authority"))?
            .userinfo()
            .is_some()
    {
        return Err(malformed("Host must not contain userinfo"));
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
    let uri = if method == Method::CONNECT && protocol.is_none() {
        if fields.scheme.is_some() || fields.path.is_some() || fields.authority.is_none() {
            return Err(malformed("invalid CONNECT pseudo-headers"));
        }
        Uri::parse_http_request_target(
            authority.ok_or(malformed("missing CONNECT authority"))?,
            true,
        )
        .map_err(|_error| malformed("invalid CONNECT authority"))?
    } else {
        let scheme = text(fields.scheme.as_ref().ok_or(malformed("missing scheme"))?)?
            .parse::<Protocol>()
            .map_err(|_error| malformed("invalid scheme"))?;
        let path = text(fields.path.as_ref().ok_or(malformed("missing path"))?)?;
        let http_scheme = scheme.is_http();
        // RFC 8441 §5: a WebSocket bootstrap uses http or https.
        if protocol.as_ref().is_some_and(ext::Protocol::is_websocket) && !http_scheme {
            return Err(malformed(
                "websocket extended CONNECT requires http or https",
            ));
        }
        // Encoders send ws/wss as http/https, so a raw ws/wss scheme cannot be forwarded as is.
        if protocol.is_some() && scheme.is_ws() {
            return Err(malformed("extended CONNECT sends ws/wss as http/https"));
        }
        if http_scheme && authority.is_none() {
            return Err(malformed("HTTP URI requires an authority"));
        }
        // The HTTP family never carries userinfo on the wire (RFC 9114 §4.3.1), nor can an
        // asterisk target, whose authority becomes Host. Other schemes keep theirs.
        let userinfo = authority.is_some_and(|value| value.contains('@'));
        if userinfo && (scheme.is_http_based() || path == "*") {
            return Err(malformed("authority must not carry userinfo"));
        }
        if !(path.starts_with('/')
            || (method == Method::OPTIONS && path == "*")
            || (!http_scheme && path.is_empty()))
            || path.contains('#')
        {
            return Err(malformed("invalid request path"));
        }
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
    if let Some(protocol) = protocol {
        request.extensions().insert(protocol);
    }
    if let Some(scheme) = asterisk_scheme {
        request.extensions().insert(scheme);
        if !request.headers().contains_key(header::HOST)
            && let Some(authority) = fields.authority
        {
            let mut host = HeaderValue::from_maybe_shared(authority)
                .map_err(|_error| malformed("invalid authority"))?;
            host.set_sensitive(fields.sensitivity.is_sensitive(PseudoHeader::Authority));
            request
                .headers_mut()
                .try_insert(header::HOST, host)
                .map_err(|_error| {
                    Error::stream(Code::H3_EXCESSIVE_LOAD, "too many header fields")
                })?;
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
    let fields = parse(fields, false)?;
    if fields.headers.contains_key(header::TE) {
        return Err(malformed("TE forbidden in response"));
    }
    if fields.method.is_some()
        || fields.scheme.is_some()
        || fields.authority.is_some()
        || fields.path.is_some()
        || fields.protocol.is_some()
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
    // RFC 9110 §9.3.6: a successful CONNECT (any 2xx) ignores Content-Length for framing.
    // The field stays visible so protocols forbidding it can reject the message (RFC 9297 §3.2).
    let tunnel = connect && status.is_success();
    if !tunnel {
        content_length(&fields.headers)?;
    }
    if !tunnel
        && (status.is_informational() || status == StatusCode::NO_CONTENT)
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
    validate_regular(request.headers(), false)?;
    let protocol = request.extensions().get_ref::<ext::Protocol>();
    if protocol.is_some() && request.method() != Method::CONNECT {
        return Err(malformed(":protocol requires CONNECT"));
    }
    // Ordinary CONNECT uses authority-form; Extended CONNECT is an ordinary target.
    let connect = request.method() == Method::CONNECT && protocol.is_none();
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
        // Compared with the wire projection (HTTP-family userinfo is already stripped), as
        // parsed host and port: a decoded `Host: h:02` became port 2.
        let mismatch = !target.is_empty()
            && AuthorityRef::try_from(&target[..]).map_or(true, |projected| {
                projected.userinfo().is_some()
                    || projected.host() != parsed_host.host()
                    || projected.port() != parsed_host.port()
            });
        if host.is_empty() || hosts.next().is_some() || mismatch {
            return Err(malformed("invalid Host or authority mismatch"));
        }
        // RFC 9114 §4.3.1: both fields then carry the same value, byte for byte.
        if !target.is_empty() {
            target.clear();
            target.extend_from_slice(host.as_bytes());
        }
    } else if target.is_empty()
        && (connect || request.uri().scheme().is_some_and(Protocol::is_http))
    {
        return Err(malformed("missing request authority"));
    }
    let scheme = if connect {
        None
    } else if protocol.is_some() {
        Some(ext::extended_connect_pseudo_scheme(
            request
                .uri()
                .scheme()
                .ok_or(malformed("missing request scheme"))?,
        ))
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
        Some(protocol)
    } else {
        Some(
            request
                .uri()
                .scheme()
                .ok_or(malformed("missing request scheme"))?,
        )
    };
    let http_scheme = scheme.is_some_and(Protocol::is_http);

    let authority_len = target.len();
    if !connect && (request.uri().is_asterisk() || http_scheme || !request.uri().is_path_empty()) {
        request.uri().write_h2_path(&mut target);
    }
    let (authority, path) = target.split_at(authority_len);
    // RFC 9114 §4.3.1: http(s) needs :authority or Host, for Extended CONNECT too.
    if http_scheme && authority.is_empty() && !request.headers().contains_key(header::HOST) {
        return Err(malformed("HTTP URI requires authority"));
    }
    if protocol.is_some() && http_scheme && path.is_empty() {
        return Err(malformed("extended CONNECT requires a path"));
    }
    let mut pseudo = [
        Some((PseudoHeader::Method, request.method().as_str().as_bytes())),
        (!authority.is_empty()).then_some((PseudoHeader::Authority, authority)),
        scheme.map(|scheme| (PseudoHeader::Scheme, scheme.as_str().as_bytes())),
        (!connect).then_some((PseudoHeader::Path, path)),
        protocol.map(|protocol| (PseudoHeader::Protocol, protocol.as_ref())),
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
                // Userinfo, kept only outside the HTTP family, is never indexed.
                never_index: sensitivity.is_sensitive(name)
                    || (name == PseudoHeader::Authority && value.contains(&b'@')),
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
    use crate::h3::qpack::ErrorScope;
    use rama_core::{Service as _, bytes::BufMut, service::service_fn};
    use rama_http::layer::required_header::AddRequiredRequestHeaders;
    use rama_http_types::proto::h2::{
        frame::{self, StreamId},
        hpack,
    };

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
    fn excessive_distinct_header_names_return_an_error_without_panicking() {
        let fields = (0..32_768)
            .map(|index| FieldPair {
                name: Bytes::from(format!("x-field-{index}")),
                value: Bytes::new(),
                never_index: false,
            })
            .collect();
        let error = parse(fields, false).err().unwrap();
        assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        assert_eq!(error.scope(), ErrorScope::Stream);
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
    fn typed_schemes_preserve_http_validation_and_custom_scheme_paths() {
        for scheme in ["http", "HTTPS", "HtTp", "hTtPs"] {
            for authority in [None, Some("user@example.com")] {
                let mut input = fields(&[(":method", "GET"), (":scheme", scheme), (":path", "/")]);
                if let Some(authority) = authority {
                    input.extend(fields(&[(":authority", authority)]));
                }
                request(input).unwrap_err();
            }
            let request = request(fields(&[
                (":method", "GET"),
                (":scheme", scheme),
                (":authority", "example.com"),
                (":path", "/"),
            ]))
            .unwrap();
            assert!(request.uri().scheme().unwrap().is_http());
            let encoded = decode(encode_request(&shared(), 0, &request).unwrap());
            let decoded = super::request(encoded).unwrap();
            assert_eq!(decoded.uri(), request.uri());
        }

        // H3 also carries non-HTTP URI schemes; their empty paths stay empty.
        let request = request(fields(&[
            (":method", "GET"),
            (":scheme", "custom"),
            (":path", ""),
        ]))
        .unwrap();
        let encoded = decode(encode_request(&shared(), 0, &request).unwrap());
        assert!(
            encoded
                .iter()
                .any(|field| field.name == ":path" && field.value.is_empty())
        );
        assert_eq!(super::request(encoded).unwrap().uri(), request.uri());
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
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "invalid");
        trailers(fields(&[("x-checksum", "abc")])).unwrap();
    }

    #[test]
    fn successful_connect_keeps_content_length_for_every_2xx() {
        for status in ["200", "201", "204", "205", "206", "299"] {
            for length in ["0", "5", "invalid"] {
                let response = response_for_method(
                    fields(&[(":status", status), ("content-length", length)]),
                    true,
                )
                .unwrap_or_else(|error| panic!("CONNECT {status} CL={length}: {error:?}"));
                assert_eq!(response.headers()[header::CONTENT_LENGTH], length);
            }
        }
        // Without a tunnel the ordinary framing rules stay.
        for (status, connect) in [("204", false), ("103", true), ("403", true)] {
            let length = if status == "403" { "invalid" } else { "0" };
            response_for_method(
                fields(&[(":status", status), ("content-length", length)]),
                connect,
            )
            .unwrap_err();
        }
        let refused =
            response_for_method(fields(&[(":status", "403"), ("content-length", "5")]), true)
                .unwrap();
        assert_eq!(refused.headers()[header::CONTENT_LENGTH], "5");
    }

    #[test]
    fn extended_connect_requests_keep_content_length() {
        let head = |length| {
            fields(&[
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", "/capsules"),
                (":protocol", "x-capsule"),
                ("content-length", length),
            ])
        };
        for length in ["0", "5"] {
            let request = request_head(head(length), true).unwrap();
            assert_eq!(request.headers()[header::CONTENT_LENGTH], length);
        }
        request_head(head("invalid"), true).unwrap_err();
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
    fn authority_userinfo_is_kept_outside_the_http_family_and_never_indexed() {
        for (uri, authority, never_index) in [
            ("https://user@example.com/", "example.com", false),
            ("ftp://user:pw@example.com/f", "user:pw@example.com", true),
        ] {
            let request = Request::builder().uri(uri).body(()).unwrap();
            let fields = decode(encode_request(&shared(), 0, &request).unwrap());
            let field = fields
                .iter()
                .find(|field| field.name == ":authority")
                .unwrap();
            assert_eq!(
                (&field.value[..], field.never_index),
                (authority.as_bytes(), never_index)
            );
        }
    }

    /// The `:authority` actually sent, or `None` when encoding refuses the request.
    fn wire_authority(uri: &str, host: Option<&str>) -> Option<Bytes> {
        let mut builder = Request::builder().uri(uri);
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        let encoded = encode_request(&shared(), 0, &builder.body(()).unwrap()).ok()?;
        let fields = decode(encoded);
        fields
            .into_iter()
            .find(|field| field.name == ":authority")
            .map(|field| field.value)
    }

    /// PR9-M5-001: Host is compared with the projected wire authority, not the raw URI.
    #[test]
    fn host_is_compared_with_the_projected_authority() {
        for (uri, host, expected) in [
            // HTTP-family userinfo is stripped whether or not a Host is present.
            ("https://user:pw@example.com/", None, Some("example.com")),
            (
                "https://user:pw@example.com/",
                Some("example.com"),
                Some("example.com"),
            ),
            (
                "http://user@example.com/",
                Some("EXAMPLE.com"),
                Some("EXAMPLE.com"),
            ),
            // A matching Host is sent byte for byte, including a leading-zero port.
            (
                "https://example.com:02/",
                Some("example.com:02"),
                Some("example.com:02"),
            ),
            // Other schemes keep userinfo, which a Host can never express.
            ("ftp://user@example.com/f", None, Some("user@example.com")),
            ("ftp://user@example.com/f", Some("example.com"), None),
            // Host itself never carries userinfo, and must name the same authority.
            ("https://example.com/", Some("user@example.com"), None),
            ("https://example.com/", Some("other.example"), None),
        ] {
            assert_eq!(
                wire_authority(uri, host),
                expected.map(|value: &str| Bytes::copy_from_slice(value.as_bytes())),
                "{uri} with Host {host:?}"
            );
        }
    }

    /// The required-header layer adds `Host: example.com` to a credential URI; it must still encode.
    #[tokio::test]
    async fn required_host_headers_keep_the_http_userinfo_projection() {
        let service =
            AddRequiredRequestHeaders::new(service_fn(|request: Request<()>| async move {
                assert_eq!(request.headers()[header::HOST], "example.com");
                let fields = decode(encode_request(&shared(), 0, &request)?);
                let authority = fields
                    .iter()
                    .find(|field| field.name == ":authority")
                    .unwrap();
                assert_eq!(&authority.value[..], b"example.com");
                Ok::<_, Error>(Response::new(()))
            }));
        let request = Request::builder()
            .uri("https://user:pw@example.com/")
            .body(())
            .unwrap();
        service.serve(request).await.unwrap();
    }

    /// Found by the `h3_request_head` round-trip oracle: heads the encoder could not forward.
    #[test]
    fn decoded_hosts_reencode_and_never_carry_userinfo() {
        for scheme in ["custom", "https"] {
            let head = |host: &'static str| {
                let mut head = fields(&[(":method", "GET"), (":scheme", scheme), (":path", "/")]);
                head.extend(fields(&[("host", host)]));
                head
            };
            request(head("user@example.com")).unwrap_err();
            for host in ["example.com", "Example.COM:02"] {
                let accepted = request(head(host)).unwrap();
                let forwarded = request(decode(encode_request(&shared(), 0, &accepted).unwrap()));
                assert_eq!(forwarded.unwrap().uri(), accepted.uri(), "{host}");
            }
        }
    }

    #[test]
    fn extended_connect_pseudo_header_rules() {
        let extended = [
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", "https"),
            (":authority", "proxy.example:4443"),
            (":path", "/.well-known/masque/udp/192.0.2.6/443/"),
        ];
        let req = request_head(fields(&extended), true).unwrap();
        assert_eq!(
            req.extensions().get_ref::<ext::Protocol>(),
            Some(&ext::Protocol::from_static("connect-udp"))
        );
        assert_eq!(
            req.uri().to_string(),
            "https://proxy.example:4443/.well-known/masque/udp/192.0.2.6/443/"
        );
        // Not advertised: malformed (RFC 8441 §3), never an ordinary tunnel.
        assert_eq!(
            request_head(fields(&extended), false).unwrap_err().code(),
            Code::H3_MESSAGE_ERROR
        );
        for missing in [":scheme", ":path"] {
            let input: Vec<_> = extended
                .iter()
                .copied()
                .filter(|(name, _)| *name != missing)
                .collect();
            request_head(fields(&input), true).unwrap_err();
        }
        for (name, value) in [
            (":method", "GET"),
            (":protocol", "bad token"),
            (":protocol", ""),
        ] {
            let input: Vec<_> = extended
                .iter()
                .map(|field| {
                    if field.0 == name {
                        (name, value)
                    } else {
                        *field
                    }
                })
                .collect();
            request_head(fields(&input), true).unwrap_err();
        }
        let mut duplicate = extended.to_vec();
        duplicate.insert(2, (":protocol", "websocket"));
        request_head(fields(&duplicate), true).unwrap_err();
    }

    #[test]
    fn extended_connect_encoding_keeps_target_and_orders_protocol() {
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://example.com/chat?x=1")
            .body(())
            .unwrap();
        request.extensions().insert(ext::Protocol::WEBSOCKET);
        let output = decode(encode_request(&shared(), 0, &request).unwrap());
        assert_eq!(
            output,
            fields(&[
                (":method", "CONNECT"),
                (":authority", "example.com"),
                (":scheme", "https"),
                (":path", "/chat?x=1"),
                (":protocol", "websocket"),
            ])
        );
        let decoded = request_head(output, true).unwrap();
        assert_eq!(decoded.uri(), request.uri());
        // A forwarded request keeps the received pseudo-header order.
        let reordered = request_head(
            fields(&[
                (":protocol", "websocket"),
                (":method", "CONNECT"),
                (":scheme", "https"),
                (":path", "/chat"),
                (":authority", "example.com"),
            ]),
            true,
        )
        .unwrap();
        let output = decode(encode_request(&shared(), 0, &reordered).unwrap());
        let names: Vec<_> = output.iter().map(|field| field.name.clone()).collect();
        assert_eq!(
            names,
            [":protocol", ":method", ":scheme", ":path", ":authority"]
        );
        *request.method_mut() = Method::GET;
        encode_request(&shared(), 0, &request).unwrap_err();
    }

    #[test]
    fn websocket_uris_use_their_http_scheme() {
        for (uri, scheme) in [
            ("wss://example.com/chat", "https"),
            ("ws://example.com/chat", "http"),
        ] {
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(uri)
                .body(())
                .unwrap();
            request.extensions().insert(ext::Protocol::WEBSOCKET);
            let output = decode(encode_request(&shared(), 0, &request).unwrap());
            let value = output
                .iter()
                .find(|field| field.name == ":scheme")
                .map(|field| field.value.clone());
            assert_eq!(value.as_deref(), Some(scheme.as_bytes()), "{uri}");
        }
    }

    // RFC 8441 §5 for websocket; other protocols keep their scheme, except ws/wss.
    #[test]
    fn extended_connect_schemes_follow_rfc8441() {
        for (protocol, scheme, accepted) in [
            ("websocket", "https", true),
            ("websocket", "http", true),
            ("WebSocket", "https", true),
            ("websocket", "custom", false),
            ("WebSocket", "ftp", false),
            ("websocket", "wss", false),
            ("x", "custom", true),
            ("x", "ws", false),
            ("x", "wss", false),
        ] {
            let head = [
                (":method", "CONNECT"),
                (":protocol", protocol),
                (":scheme", scheme),
                (":authority", "example.com"),
                (":path", "/chat"),
            ];
            assert_eq!(
                request_head(fields(&head), true).is_ok(),
                accepted,
                "{protocol} {scheme}"
            );
        }
    }

    // RFC 9114 §4.3.1: Host stands in for a missing :authority, for Extended CONNECT too.
    #[test]
    fn host_stands_in_for_the_authority_of_every_request_kind() {
        for (method, protocol, uri) in [
            (Method::GET, None, "https:/chat"),
            (
                Method::CONNECT,
                Some(ext::Protocol::WEBSOCKET),
                "https:/chat",
            ),
            (Method::CONNECT, Some(ext::Protocol::WEBSOCKET), "wss:/chat"),
        ] {
            let mut request = Request::new(());
            *request.method_mut() = method;
            *request.uri_mut() = Uri::parse(uri).unwrap();
            if let Some(protocol) = protocol {
                request.extensions().insert(protocol);
            }
            encode_request(&shared(), 0, &request).unwrap_err();
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_static("example.com"));
            let output = decode(encode_request(&shared(), 0, &request).unwrap());
            assert!(
                !output.iter().any(|field| field.name == ":authority"),
                "{uri}"
            );
            let decoded = request_head(output, true).unwrap();
            assert_eq!(
                decoded.uri().to_string(),
                "https://example.com/chat",
                "{uri}"
            );
        }
    }

    #[test]
    fn protocol_is_never_a_response_field() {
        response(fields(&[(":status", "200"), (":protocol", "websocket")])).unwrap_err();
    }

    #[test]
    fn sensitive_host_fallback_preserves_synthesized_authority_sensitivity() {
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
    fn options_asterisk_host_synthesis_respects_header_capacity() {
        let mut headers = HeaderMap::new();
        for index in 0.. {
            let name = HeaderName::try_from(format!("x-field-{index}")).unwrap();
            if headers
                .try_insert(name, HeaderValue::from_static("value"))
                .is_err()
            {
                break;
            }
        }
        let mut input = fields(&[
            (":method", "OPTIONS"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "*"),
        ]);
        input.extend(headers.iter().map(|(name, value)| FieldPair {
            name: Bytes::copy_from_slice(name.as_str().as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            never_index: false,
        }));
        // The received fields fit; only the additional synthesized Host exceeds
        // capacity. It must reject this request without panicking the driver.
        parse(input.clone(), false).unwrap();
        let error = request(input).unwrap_err();
        assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        assert_eq!(error.scope(), ErrorScope::Stream);
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
