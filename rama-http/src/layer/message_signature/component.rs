//! HTTP message component identifiers and canonicalization (RFC 9421 §2).

use rama_core::bytes::BytesMut;
use rama_http_headers::signature_input::ComponentIdentifier;
use rama_http_headers::util::structured_fields::{
    Dictionary, DictionaryMember, ParameterValue, parse_dictionary, parse_item, parse_list,
    serialize_dictionary, serialize_item_value, serialize_list,
};
use rama_http_types::{HeaderMap, HeaderName, Method, StatusCode};
use rama_net::address::HostRef;
use rama_net::uri::Uri;
use std::fmt;
use std::net::IpAddr;

/// Whether the target message is a request or a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
}

/// Expected Structured Fields type for `;sf` serialization (RFC 9421 §2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredFieldType {
    Dictionary,
    List,
    Item,
}

/// Resolve the application-known SF type for a field name.
///
/// RFC 9421 requires the application to know the field type when using `;sf`.
/// Unknown fields must not guess between Dictionary/List/Item.
pub fn known_structured_field_type(field_name: &str) -> Option<StructuredFieldType> {
    match field_name {
        "content-digest" | "repr-digest" | "accept-digest" | "signature" | "signature-input" => {
            Some(StructuredFieldType::Dictionary)
        }
        _ => None,
    }
}

/// Context needed to resolve component values from an HTTP message.
#[derive(Debug, Clone)]
pub struct ComponentContext<'a> {
    pub kind: MessageKind,
    pub method: Option<&'a Method>,
    pub uri: Option<&'a Uri>,
    pub status: Option<StatusCode>,
    pub headers: &'a HeaderMap,
    pub trailers: Option<&'a HeaderMap>,
    /// Scheme used when reconstructing `@target-uri` for origin-form requests.
    pub scheme_hint: Option<&'a str>,
    /// Optional overrides for `;sf` field types (field name → type).
    pub sf_types: Option<&'a ahash::HashMap<String, StructuredFieldType>>,
    /// Related request headers/uri/method when resolving `req` components on a response.
    pub related_request: Option<Box<Self>>,
}

impl<'a> ComponentContext<'a> {
    #[must_use]
    pub fn for_request(method: &'a Method, uri: &'a Uri, headers: &'a HeaderMap) -> Self {
        Self {
            kind: MessageKind::Request,
            method: Some(method),
            uri: Some(uri),
            status: None,
            headers,
            trailers: None,
            scheme_hint: None,
            sf_types: None,
            related_request: None,
        }
    }

    #[must_use]
    pub fn for_response(status: StatusCode, headers: &'a HeaderMap) -> Self {
        Self {
            kind: MessageKind::Response,
            method: None,
            uri: None,
            status: Some(status),
            headers,
            trailers: None,
            scheme_hint: None,
            sf_types: None,
            related_request: None,
        }
    }

    #[must_use]
    pub fn with_related_request(mut self, related: Self) -> Self {
        self.related_request = Some(Box::new(related));
        self
    }

    #[must_use]
    pub fn with_trailers(mut self, trailers: &'a HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }

    #[must_use]
    pub fn with_scheme_hint(mut self, scheme: &'a str) -> Self {
        self.scheme_hint = Some(scheme);
        self
    }

    #[must_use]
    pub fn with_sf_types(
        mut self,
        sf_types: &'a ahash::HashMap<String, StructuredFieldType>,
    ) -> Self {
        self.sf_types = Some(sf_types);
        self
    }
}

/// Error resolving a component value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentError {
    pub message: String,
}

impl ComponentError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ComponentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "component error: {}", self.message)
    }
}

impl std::error::Error for ComponentError {}

/// Resolve the canonical component value for a covered component identifier.
pub fn resolve_component_value(
    ctx: &ComponentContext<'_>,
    id: &ComponentIdentifier,
) -> Result<String, ComponentError> {
    validate_component_parameters(id)?;

    let use_req = id
        .parameters
        .get("req")
        .is_some_and(|v| matches!(v, ParameterValue::Boolean(true)));

    if use_req {
        if ctx.kind == MessageKind::Request {
            return Err(ComponentError::new(
                ";req is not allowed when signing or verifying a request",
            ));
        }
        let related = ctx
            .related_request
            .as_deref()
            .ok_or_else(|| ComponentError::new("req parameter requires related request context"))?;
        // Strip `req` when resolving against the related request
        let mut stripped = id.clone();
        stripped.parameters.params.retain(|p| p.name != "req");
        return resolve_component_value(related, &stripped);
    }

    if id.name.starts_with('@') {
        resolve_derived(ctx, id)
    } else {
        resolve_field(ctx, id)
    }
}

/// Reject unknown / inapplicable component parameters (RFC 9421 §2.5).
fn validate_component_parameters(id: &ComponentIdentifier) -> Result<(), ComponentError> {
    let is_derived = id.name.starts_with('@');
    for p in &id.parameters.params {
        match p.name.as_str() {
            "req" => {
                if !matches!(p.value, ParameterValue::Boolean(true)) {
                    return Err(ComponentError::new(";req must be a boolean true flag"));
                }
            }
            "sf" | "bs" | "tr" => {
                if is_derived {
                    return Err(ComponentError::new(format!(
                        "derived component {} must not have ;{}",
                        id.name, p.name
                    )));
                }
                if !matches!(p.value, ParameterValue::Boolean(true)) {
                    return Err(ComponentError::new(format!(
                        ";{} must be a boolean true flag",
                        p.name
                    )));
                }
            }
            "key" => {
                if is_derived {
                    return Err(ComponentError::new(format!(
                        "derived component {} must not have ;key",
                        id.name
                    )));
                }
                if !matches!(p.value, ParameterValue::String(_)) {
                    return Err(ComponentError::new(";key requires a string value"));
                }
            }
            "name" => {
                if id.name != "@query-param" {
                    return Err(ComponentError::new(";name is only valid on @query-param"));
                }
                if !matches!(p.value, ParameterValue::String(_)) {
                    return Err(ComponentError::new(";name requires a string value"));
                }
            }
            other => {
                return Err(ComponentError::new(format!(
                    "unknown component parameter: {other}"
                )));
            }
        }
    }
    Ok(())
}

fn resolve_derived(
    ctx: &ComponentContext<'_>,
    id: &ComponentIdentifier,
) -> Result<String, ComponentError> {
    match id.name.as_str() {
        "@method" => {
            let method = ctx
                .method
                .ok_or_else(|| ComponentError::new("@method requires a request"))?;
            Ok(method.as_str().to_owned())
        }
        "@authority" => authority_value(ctx),
        "@scheme" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@scheme requires a request URI"))?;
            let scheme = uri
                .scheme_str()
                .or(ctx.scheme_hint)
                .ok_or_else(|| ComponentError::new("@scheme not available"))?
                .to_ascii_lowercase();
            Ok(scheme)
        }
        "@target-uri" => target_uri_value(ctx),
        "@request-target" => request_target_value(ctx),
        "@path" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@path requires a request URI"))?;
            if uri.is_asterisk() {
                return Err(ComponentError::new(
                    "@path is not available for asterisk-form",
                ));
            }
            Ok(uri.path_or_root().into_owned())
        }
        "@query" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@query requires a request URI"))?;
            if uri.is_asterisk() {
                return Err(ComponentError::new(
                    "@query is not available for asterisk-form",
                ));
            }
            match uri.query() {
                Some(q) => Ok(format!("?{}", q.as_encoded_str())),
                None => Ok("?".to_owned()),
            }
        }
        "@query-param" => query_param_value(ctx, id),
        "@status" => {
            let status = ctx
                .status
                .ok_or_else(|| ComponentError::new("@status requires a response"))?;
            Ok(status.as_u16().to_string())
        }
        "@signature-params" => Err(ComponentError::new(
            "@signature-params is produced by base assembly, not resolved as a covered component",
        )),
        other => Err(ComponentError::new(format!(
            "unsupported derived component: {other}"
        ))),
    }
}

fn authority_value(ctx: &ComponentContext<'_>) -> Result<String, ComponentError> {
    let uri = ctx
        .uri
        .ok_or_else(|| ComponentError::new("@authority requires a request URI"))?;

    if let Some(auth) = uri.authority() {
        return Ok(format_authority_host_port(
            auth.host(),
            auth.port_u16(),
            uri.scheme().and_then(|s| s.default_port()),
        ));
    }

    let host = ctx
        .headers
        .get(rama_http_types::header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ComponentError::new("@authority not available"))?;
    Ok(strip_default_port_from_host_header(
        host,
        uri.scheme().and_then(|s| s.default_port()).or_else(|| {
            ctx.scheme_hint
                .and_then(|s| match s.to_ascii_lowercase().as_str() {
                    "http" | "ws" => Some(80),
                    "https" | "wss" => Some(443),
                    _ => None,
                })
        }),
    )
    .to_ascii_lowercase())
}

fn format_authority_host_port(
    host: HostRef<'_>,
    port: Option<u16>,
    default_port: Option<u16>,
) -> String {
    let host = match host {
        HostRef::Address(IpAddr::V6(ip)) => format!("[{ip}]"),
        other => other.to_string(),
    }
    .to_ascii_lowercase();
    match (port, default_port) {
        (Some(p), Some(d)) if p == d => host,
        (Some(p), _) => format!("{host}:{p}"),
        (None, _) => host,
    }
}

fn strip_default_port_from_host_header(host: &str, default_port: Option<u16>) -> String {
    let Some(default_port) = default_port else {
        return host.to_owned();
    };
    // IPv6 Host headers are `[addr]:port` or `[addr]`
    if let Some(bracket_end) = host.find(']') {
        let rest = &host[bracket_end + 1..];
        if let Some(p) = rest.strip_prefix(':')
            && p.parse::<u16>().ok() == Some(default_port)
        {
            return host[..=bracket_end].to_owned();
        }
        return host.to_owned();
    }
    if let Some((name, port)) = host.rsplit_once(':')
        && !name.is_empty()
        && port.parse::<u16>().ok() == Some(default_port)
    {
        return name.to_owned();
    }
    host.to_owned()
}

fn request_target_value(ctx: &ComponentContext<'_>) -> Result<String, ComponentError> {
    let uri = ctx
        .uri
        .ok_or_else(|| ComponentError::new("@request-target requires a request URI"))?;
    if uri.is_asterisk() {
        return Ok("*".to_owned());
    }
    let mut buf = BytesMut::new();
    if uri.scheme().is_some() {
        uri.write_http_absolute_form(&mut buf)
            .map_err(|e| ComponentError::new(format!("@request-target absolute-form: {e}")))?;
    } else if uri.authority().is_some() && uri.is_path_empty() && uri.query().is_none() {
        // CONNECT authority-form
        uri.write_http_authority_form(&mut buf)
            .map_err(|e| ComponentError::new(format!("@request-target authority-form: {e}")))?;
    } else {
        uri.write_http_origin_form(&mut buf)
            .map_err(|e| ComponentError::new(format!("@request-target origin-form: {e}")))?;
    }
    String::from_utf8(buf.to_vec())
        .map_err(|_err| ComponentError::new("@request-target is not UTF-8"))
}

fn target_uri_value(ctx: &ComponentContext<'_>) -> Result<String, ComponentError> {
    let uri = ctx
        .uri
        .ok_or_else(|| ComponentError::new("@target-uri requires a request URI"))?;
    if uri.is_asterisk() {
        return Err(ComponentError::new(
            "@target-uri is not available for asterisk-form",
        ));
    }
    if uri.scheme().is_some() {
        let mut buf = BytesMut::new();
        uri.write_http_absolute_form(&mut buf)
            .map_err(|e| ComponentError::new(format!("@target-uri: {e}")))?;
        return String::from_utf8(buf.to_vec())
            .map_err(|_err| ComponentError::new("@target-uri is not UTF-8"));
    }

    let scheme = ctx
        .scheme_hint
        .ok_or_else(|| {
            ComponentError::new(
                "@target-uri requires an absolute URI or a scheme_hint for origin-form",
            )
        })?
        .to_ascii_lowercase();
    let authority = authority_value(ctx)?;
    let mut buf = BytesMut::new();
    uri.write_http_origin_form(&mut buf)
        .map_err(|e| ComponentError::new(format!("@target-uri path: {e}")))?;
    let path_query = String::from_utf8(buf.to_vec())
        .map_err(|_err| ComponentError::new("@target-uri path is not UTF-8"))?;
    Ok(format!("{scheme}://{authority}{path_query}"))
}

fn query_param_value(
    ctx: &ComponentContext<'_>,
    id: &ComponentIdentifier,
) -> Result<String, ComponentError> {
    let name = match id.parameters.get("name") {
        Some(ParameterValue::String(s)) => s.clone(),
        _ => {
            return Err(ComponentError::new(
                "@query-param requires ;name=\"...\" parameter",
            ));
        }
    };
    let uri = ctx
        .uri
        .ok_or_else(|| ComponentError::new("@query-param requires a request URI"))?;
    let query = uri
        .query()
        .ok_or_else(|| ComponentError::new("@query-param: request has no query"))?;

    // Match after form-decoding both the identifier name and query names.
    let mut matches = query
        .pairs()
        .filter(|p| p.name_decoded() == name)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(ComponentError::new(format!(
            "@query-param name={name} not found"
        )));
    }
    if matches.len() > 1 {
        return Err(ComponentError::new(format!(
            "@query-param name={name} appears more than once"
        )));
    }
    let value = matches
        .pop()
        .and_then(|p| p.value_decoded())
        .unwrap_or_default();
    Ok(form_urlencoded_percent_encode(&value))
}

/// application/x-www-form-urlencoded percent-encode with space as `%20` (RFC 9421 §2.2.8).
fn form_urlencoded_percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 0xf) as usize]));
            }
        }
    }
    out
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn resolve_field(
    ctx: &ComponentContext<'_>,
    id: &ComponentIdentifier,
) -> Result<String, ComponentError> {
    // RFC 9421 §2.1: field component names MUST be lowercase in the signature base.
    if id.name != id.name.to_ascii_lowercase() {
        return Err(ComponentError::new(
            "field component names must be lowercase",
        ));
    }
    let name = id.name.as_str();
    if name.starts_with('@') {
        return Err(ComponentError::new("field names must not start with @"));
    }

    let use_tr = id
        .parameters
        .get("tr")
        .is_some_and(|v| matches!(v, ParameterValue::Boolean(true)));
    let use_sf = id
        .parameters
        .get("sf")
        .is_some_and(|v| matches!(v, ParameterValue::Boolean(true)));
    let use_bs = id
        .parameters
        .get("bs")
        .is_some_and(|v| matches!(v, ParameterValue::Boolean(true)));
    let key = match id.parameters.get("key") {
        Some(ParameterValue::String(s)) => Some(s.as_str()),
        _ => None,
    };

    if use_bs && (use_sf || key.is_some()) {
        return Err(ComponentError::new(
            ";bs is mutually exclusive with ;sf and ;key",
        ));
    }
    if use_sf && key.is_none() {
        // ;sf alone is fine; ;key without ;sf is also allowed for dictionary lookup
    }

    let map = if use_tr {
        ctx.trailers.ok_or_else(|| {
            ComponentError::new(format!("trailer field {name} requested but no trailers"))
        })?
    } else {
        ctx.headers
    };

    let header_name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_err| ComponentError::new("invalid field name"))?;

    if use_bs {
        let values: Vec<_> = map.get_all(&header_name).iter().collect();
        if values.is_empty() {
            return Err(ComponentError::new(format!("field {name} not present")));
        }
        let mut out = String::new();
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            let canonical = canonicalize_field_value_bytes(v.as_bytes())?;
            out.push(':');
            use base64::Engine as _;
            out.push_str(&base64::engine::general_purpose::STANDARD.encode(canonical));
            out.push(':');
        }
        return Ok(out);
    }

    if use_sf || key.is_some() {
        let combined = combine_field_values(map, &header_name)?;
        if let Some(key_name) = key {
            let dict = parse_dictionary(&combined).map_err(|e| {
                ComponentError::new(format!("field {name} is not a valid SF dictionary: {e}"))
            })?;
            let member = dict.get(key_name).ok_or_else(|| {
                ComponentError::new(format!("dictionary key {key_name} not found"))
            })?;
            return Ok(serialize_dictionary_member(member));
        }
        // Strict SF serialization — require application-known field type (RFC 9421 §2.1.1).
        let sf_type = ctx
            .sf_types
            .and_then(|m| m.get(name).copied())
            .or_else(|| known_structured_field_type(name))
            .ok_or_else(|| {
                ComponentError::new(format!(
                    ";sf requires a known structured field type for {name}"
                ))
            })?;
        return serialize_strict_sf(&combined, sf_type).map_err(|e| {
            ComponentError::new(format!("field {name} is not a valid structured field: {e}"))
        });
    }

    combine_field_values(map, &header_name)
}

/// RFC 9421 §2.1.3: strip leading/trailing whitespace and collapse obs-fold to SP.
fn canonicalize_field_value_bytes(raw: &[u8]) -> Result<Vec<u8>, ComponentError> {
    // Collapse obs-fold (CR LF 1*(SP / HTAB)) to a single SP.
    let mut normalized = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if i + 2 < raw.len()
            && raw[i] == b'\r'
            && raw[i + 1] == b'\n'
            && matches!(raw[i + 2], b' ' | b'\t')
        {
            normalized.push(b' ');
            i += 3;
            while i < raw.len() && matches!(raw[i], b' ' | b'\t') {
                i += 1;
            }
            continue;
        }
        normalized.push(raw[i]);
        i += 1;
    }
    let start = normalized
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(normalized.len());
    let end = normalized
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(start, |p| p + 1);
    Ok(normalized[start..end].to_vec())
}

fn serialize_strict_sf(combined: &str, sf_type: StructuredFieldType) -> Result<String, String> {
    match sf_type {
        StructuredFieldType::Dictionary => {
            let dict = parse_dictionary(combined).map_err(|e| e.to_string())?;
            Ok(serialize_dictionary(&dict))
        }
        StructuredFieldType::List => {
            let list = parse_list(combined).map_err(|e| e.to_string())?;
            Ok(serialize_list(&list))
        }
        StructuredFieldType::Item => {
            let item = parse_item(combined).map_err(|e| e.to_string())?;
            Ok(serialize_item_value(&item))
        }
    }
}

fn combine_field_values(map: &HeaderMap, name: &HeaderName) -> Result<String, ComponentError> {
    let mut values = map.get_all(name).iter();
    let first = values
        .next()
        .ok_or_else(|| ComponentError::new(format!("field {name} not present")))?;
    let mut out = first
        .to_str()
        .map_err(|_err| ComponentError::new("field value is not ASCII"))?
        .trim()
        .to_owned();
    for v in values {
        out.push_str(", ");
        out.push_str(
            v.to_str()
                .map_err(|_err| ComponentError::new("field value is not ASCII"))?
                .trim(),
        );
    }
    Ok(out)
}

fn serialize_dictionary_member(member: &DictionaryMember) -> String {
    match member {
        DictionaryMember::Item(item) => {
            let mut dict = Dictionary::new();
            dict.insert("_", DictionaryMember::Item(item.clone()));
            let full = serialize_dictionary(&dict);
            full.strip_prefix("_=").unwrap_or(&full).to_owned()
        }
        DictionaryMember::InnerList(list) => {
            let mut dict = Dictionary::new();
            dict.insert("_", DictionaryMember::InnerList(list.clone()));
            let full = serialize_dictionary(&dict);
            full.strip_prefix("_=").unwrap_or(&full).to_owned()
        }
    }
}

/// Serialize a component identifier for the signature base left-hand side.
pub fn serialize_component_identifier(id: &ComponentIdentifier) -> String {
    id.serialize_identifier()
}

/// Identity key for duplicate detection: name + parameters ignoring parameter order.
pub fn component_identity_key(id: &ComponentIdentifier) -> String {
    let mut params: Vec<_> = id
        .parameters
        .params
        .iter()
        .map(|p| {
            let mut s = p.name.clone();
            s.push('=');
            match &p.value {
                ParameterValue::Boolean(true) => s.push('1'),
                ParameterValue::Boolean(false) => s.push('0'),
                ParameterValue::String(v) => {
                    s.push('"');
                    s.push_str(v);
                    s.push('"');
                }
                ParameterValue::Token(v) => s.push_str(v),
                ParameterValue::Integer(n) => s.push_str(&n.to_string()),
                ParameterValue::Decimal {
                    negative,
                    integer,
                    fraction,
                    fraction_digits,
                } => {
                    if *negative {
                        s.push('-');
                    }
                    s.push_str(&integer.to_string());
                    s.push('.');
                    let width = usize::from(*fraction_digits);
                    s.push_str(&format!("{fraction:0width$}"));
                }
                ParameterValue::ByteSequence(b) => {
                    use base64::Engine as _;
                    s.push(':');
                    s.push_str(&base64::engine::general_purpose::STANDARD.encode(b));
                    s.push(':');
                }
                ParameterValue::Date(n) => {
                    s.push('@');
                    s.push_str(&n.to_string());
                }
                ParameterValue::DisplayString(v) => {
                    s.push_str("%\"");
                    s.push_str(v);
                    s.push('"');
                }
            }
            s
        })
        .collect();
    params.sort();
    format!("{}|{}", id.name.to_ascii_lowercase(), params.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_headers::util::structured_fields::Parameters;
    use rama_http_types::{Method, Request};
    use rama_net::uri::Uri;

    #[test]
    fn derived_method_path_authority_query() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/foo?param=Value&Pet=dog")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());

        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@method")).unwrap(),
            "POST"
        );
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@authority")).unwrap(),
            "example.com"
        );
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@path")).unwrap(),
            "/foo"
        );
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@query")).unwrap(),
            "?param=Value&Pet=dog"
        );
    }

    #[test]
    fn authority_strips_default_https_port() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com:443/foo")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@authority")).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn query_param_rejects_duplicates_and_reencodes() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/?Pet=dog&Pet=cat")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let id = ComponentIdentifier::new("@query-param")
            .with_parameters(Parameters::new().with("name", ParameterValue::String("Pet".into())));
        resolve_component_value(&ctx, &id).unwrap_err();

        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/?q=a+b")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let id = ComponentIdentifier::new("@query-param")
            .with_parameters(Parameters::new().with("name", ParameterValue::String("q".into())));
        assert_eq!(resolve_component_value(&ctx, &id).unwrap(), "a%20b");
    }

    #[test]
    fn sf_fails_closed_on_non_sf() {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("x-plain", "not; a = structured field!!!")
            .body(())
            .unwrap();
        let _ = &mut req;
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let id = ComponentIdentifier::new("x-plain")
            .with_parameters(Parameters::new().with("sf", ParameterValue::Boolean(true)));
        // Unknown field type: fail closed without guessing.
        resolve_component_value(&ctx, &id).unwrap_err();

        use ahash::{HashMap, HashMapExt as _};
        let mut types = HashMap::new();
        types.insert("x-plain".into(), StructuredFieldType::Item);
        let ctx = ctx.with_sf_types(&types);
        resolve_component_value(&ctx, &id).unwrap_err();
    }

    #[test]
    fn sf_decimal_round_trips() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("example", "1.50")
            .body(())
            .unwrap();
        use ahash::{HashMap, HashMapExt as _};
        let mut types = HashMap::new();
        types.insert("example".into(), StructuredFieldType::Item);
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers())
            .with_sf_types(&types);
        let id = ComponentIdentifier::new("example")
            .with_parameters(Parameters::new().with("sf", ParameterValue::Boolean(true)));
        assert_eq!(resolve_component_value(&ctx, &id).unwrap(), "1.5");
    }

    #[test]
    fn sf_known_builtin_content_digest() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("content-digest", "sha-256=:YQ==:")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let id = ComponentIdentifier::new("content-digest")
            .with_parameters(Parameters::new().with("sf", ParameterValue::Boolean(true)));
        assert_eq!(
            resolve_component_value(&ctx, &id).unwrap(),
            "sha-256=:YQ==:"
        );
    }

    #[test]
    fn reject_uppercase_field_component_name() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        resolve_component_value(&ctx, &ComponentIdentifier::new("Content-Type")).unwrap_err();
    }

    #[test]
    fn reject_bs_with_key_and_req_on_request() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("x-bin", " value ")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let id = ComponentIdentifier::new("x-bin").with_parameters(
            Parameters::new()
                .with("bs", ParameterValue::Boolean(true))
                .with("key", ParameterValue::String("a".into())),
        );
        resolve_component_value(&ctx, &id).unwrap_err();

        let id = ComponentIdentifier::new("@method")
            .with_parameters(Parameters::new().with("req", ParameterValue::Boolean(true)));
        // Related context alone is not enough — request kind forbids ;req.
        let related = ctx.clone();
        let ctx = ctx.with_related_request(related);
        resolve_component_value(&ctx, &id).unwrap_err();
    }

    #[test]
    fn bs_strips_whitespace() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("x-bin", " value ")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let id = ComponentIdentifier::new("x-bin")
            .with_parameters(Parameters::new().with("bs", ParameterValue::Boolean(true)));
        use base64::Engine as _;
        let expected = format!(
            ":{}:",
            base64::engine::general_purpose::STANDARD.encode(b"value")
        );
        assert_eq!(resolve_component_value(&ctx, &id).unwrap(), expected);
    }

    #[test]
    fn unknown_component_param_errors() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let id = ComponentIdentifier::new("@method")
            .with_parameters(Parameters::new().with("foo", ParameterValue::Boolean(true)));
        resolve_component_value(&ctx, &id).unwrap_err();
    }

    #[test]
    fn request_target_asterisk_and_authority_form() {
        let uri = Uri::from_static("*");
        let headers = HeaderMap::new();
        let method = Method::OPTIONS;
        let ctx = ComponentContext::for_request(&method, &uri, &headers);
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@request-target")).unwrap(),
            "*"
        );

        let uri = Uri::parse_authority_form("example.com:443").unwrap();
        let method = Method::CONNECT;
        let ctx = ComponentContext::for_request(&method, &uri, &headers);
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@request-target")).unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn target_uri_from_origin_form_with_scheme_hint() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/foo?bar=1")
            .header("host", "example.com")
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers())
            .with_scheme_hint("https");
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("@target-uri")).unwrap(),
            "https://example.com/foo?bar=1"
        );
    }

    #[test]
    fn field_combine() {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header("host", "example.com")
            .body(())
            .unwrap();
        req.headers_mut()
            .append("cache-control", "max-age=60".parse().unwrap());
        req.headers_mut()
            .append("cache-control", "must-revalidate".parse().unwrap());
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        assert_eq!(
            resolve_component_value(&ctx, &ComponentIdentifier::new("cache-control")).unwrap(),
            "max-age=60, must-revalidate"
        );
    }

    #[test]
    fn component_identity_ignores_param_order() {
        let a = ComponentIdentifier::new("digest").with_parameters(
            Parameters::new()
                .with("sf", ParameterValue::Boolean(true))
                .with("key", ParameterValue::String("sha-256".into())),
        );
        let b = ComponentIdentifier::new("digest").with_parameters(
            Parameters::new()
                .with("key", ParameterValue::String("sha-256".into()))
                .with("sf", ParameterValue::Boolean(true)),
        );
        assert_eq!(component_identity_key(&a), component_identity_key(&b));
    }
}
