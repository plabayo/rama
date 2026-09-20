//! Validate decoded HTTP fields before normalization can hide malformed input.

use super::{Error, qpack::FieldPair};
use rama_core::{bytes::Bytes, extensions::ExtensionsRef};
use rama_http_types::proto::h3::Code;
use rama_http_types::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version, header,
};
use rama_net::{Protocol, address::Authority, uri::Uri};

#[derive(Default)]
struct Fields {
    headers: HeaderMap,
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
        if field.name.is_empty() || field.name.iter().any(u8::is_ascii_uppercase) {
            return Err(malformed("empty or uppercase field name"));
        }
        if field
            .value
            .first()
            .is_some_and(|b| matches!(b, b' ' | b'\t'))
            || field
                .value
                .last()
                .is_some_and(|b| matches!(b, b' ' | b'\t'))
            || field
                .value
                .iter()
                .any(|b| *b == 0 || *b == b'\r' || *b == b'\n')
        {
            return Err(malformed("invalid field value"));
        }
        if field.name[0] == b':' {
            if regular || trailers {
                return Err(malformed("misplaced pseudo-header"));
            }
            let slot = match field.name.as_ref() {
                b":method" => &mut result.method,
                b":scheme" => &mut result.scheme,
                b":authority" => &mut result.authority,
                b":path" => &mut result.path,
                b":status" => &mut result.status,
                _ => return Err(malformed("unknown pseudo-header")),
            };
            if slot.replace(field.value).is_some() {
                return Err(malformed("duplicate pseudo-header"));
            }
            continue;
        }
        regular = true;
        let name = HeaderName::from_bytes(&field.name)
            .map_err(|_error| malformed("invalid field name"))?;
        if [
            header::CONNECTION,
            header::PROXY_CONNECTION,
            header::KEEP_ALIVE,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
        ]
        .contains(&name)
            || (name == header::TE && (trailers || field.value.as_ref() != b"trailers"))
        {
            return Err(malformed("connection-specific field"));
        }
        if trailers && [header::CONTENT_LENGTH, header::HOST].contains(&name) {
            return Err(malformed("message framing field in trailers"));
        }
        let mut value = HeaderValue::from_maybe_shared(field.value)
            .map_err(|_error| malformed("invalid field value"))?;
        value.set_sensitive(field.never_index);
        result.headers.append(name, value);
    }
    Ok(result)
}

pub(crate) fn validate_regular(headers: &HeaderMap, trailers: bool) -> Result<(), Error> {
    for (name, value) in headers {
        if [
            header::CONNECTION,
            header::PROXY_CONNECTION,
            header::KEEP_ALIVE,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
        ]
        .contains(name)
            || (*name == header::TE && (trailers || value.as_bytes() != b"trailers"))
            || (trailers && [header::CONTENT_LENGTH, header::HOST].contains(name))
        {
            return Err(malformed("field forbidden in HTTP/3 message"));
        }
        if value
            .as_bytes()
            .first()
            .is_some_and(|b| matches!(b, b' ' | b'\t'))
            || value
                .as_bytes()
                .last()
                .is_some_and(|b| matches!(b, b' ' | b'\t'))
        {
            return Err(malformed("field value has surrounding whitespace"));
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
    let fields = parse(fields, false)?;
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
        Authority::try_from(authority).map_err(|_error| malformed("invalid authority"))?;
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
    if let Some(scheme) = asterisk_scheme {
        request.extensions().insert(scheme);
        if let Some(authority) = fields.authority {
            request.headers_mut().insert(
                header::HOST,
                HeaderValue::from_maybe_shared(authority)
                    .map_err(|_error| malformed("invalid authority"))?,
            );
        }
    }
    // RFC 9114 §4.2.1 requires joining split Cookie fields for non-H2/H3 consumers.
    let cookies = request.headers().get_all(header::COOKIE);
    if cookies.iter().count() > 1 {
        let mut joined = Vec::new();
        let mut sensitive = false;
        for value in cookies {
            if !joined.is_empty() {
                joined.extend_from_slice(b"; ");
            }
            joined.extend_from_slice(value.as_bytes());
            sensitive |= value.is_sensitive();
        }
        let mut value = HeaderValue::from_maybe_shared(Bytes::from(joined))
            .map_err(|_error| malformed("invalid cookie"))?;
        value.set_sensitive(sensitive);
        request.headers_mut().insert(header::COOKIE, value);
    }
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
    let mut authority = BytesMut::new();
    if request.uri().authority().is_some() {
        request
            .uri()
            .write_h2_authority(&mut authority)
            .map_err(|_error| malformed("invalid request authority"))?;
    }
    let host_values = request.headers().get_all(header::HOST);
    let mut hosts = host_values.iter();
    if let Some(host) = hosts.next() {
        if host.is_empty()
            || hosts.next().is_some()
            || (!authority.is_empty() && !authority.eq_ignore_ascii_case(host.as_bytes()))
        {
            return Err(malformed("invalid Host or authority mismatch"));
        }
    } else if authority.is_empty()
        && (connect || matches!(request.uri().scheme_str(), Some("http" | "https")))
    {
        return Err(malformed("missing request authority"));
    }
    let mut scheme = BytesMut::new();
    let mut path = BytesMut::new();
    if !connect {
        if request.uri().is_asterisk() {
            if request.method() != Method::OPTIONS {
                return Err(malformed("asterisk requires OPTIONS"));
            }
            let protocol = request
                .extensions()
                .get_ref::<Protocol>()
                .ok_or(malformed("missing request scheme"))?;
            scheme.extend_from_slice(protocol.as_str().as_bytes());
            if let Some(host) = request.headers().get(header::HOST) {
                authority.extend_from_slice(host.as_bytes());
            }
        } else {
            request
                .uri()
                .write_h2_scheme(&mut scheme)
                .map_err(|_error| malformed("missing request scheme"))?;
        }
        if request.uri().is_asterisk() {
            path.extend_from_slice(b"*");
        } else if !matches!(request.uri().scheme_str(), Some("http" | "https"))
            && request.uri().is_path_empty()
        {
            // Non-HTTP schemes may have an empty path (RFC 9114 §4.3.1).
        } else {
            request.uri().write_h2_path(&mut path);
        }
    }
    if matches!(scheme.as_ref(), b"http" | b"https")
        && authority.is_empty()
        && !request.headers().contains_key(header::HOST)
    {
        return Err(malformed("HTTP URI requires authority"));
    }
    let pseudo = [
        Some((b":method".as_slice(), request.method().as_str().as_bytes())),
        (!authority.is_empty()).then_some((b":authority".as_slice(), authority.as_ref())),
        (!connect).then_some((b":scheme".as_slice(), scheme.as_ref())),
        (!connect).then_some((b":path".as_slice(), path.as_ref())),
    ];
    shared.encode(
        id,
        pseudo.into_iter().flatten().map(EncodeField::from).chain(
            request
                .headers()
                .iter()
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
        std::iter::once(EncodeField::from((
            b":status".as_slice(),
            response.status().as_str().as_bytes(),
        )))
        .chain(
            response
                .headers()
                .iter()
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
