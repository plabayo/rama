//! HTTP message component identifiers and canonicalization (RFC 9421 §2).

use rama_http_headers::signature_input::ComponentIdentifier;
use rama_http_headers::util::structured_fields::{
    Dictionary, DictionaryMember, ParameterValue, parse_dictionary, serialize_dictionary,
};
use rama_http_types::{HeaderMap, HeaderName, Method, StatusCode};
use rama_net::uri::Uri;
use std::fmt;

/// Whether the target message is a request or a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
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
    let use_req = id
        .parameters
        .get("req")
        .is_some_and(|v| matches!(v, ParameterValue::Boolean(true)));

    if use_req {
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

fn resolve_derived(
    ctx: &ComponentContext<'_>,
    id: &ComponentIdentifier,
) -> Result<String, ComponentError> {
    // Derived components must not carry sf/bs/tr
    for forbidden in ["sf", "bs", "tr"] {
        if id.parameters.get(forbidden).is_some() {
            return Err(ComponentError::new(format!(
                "derived component {} must not have ;{forbidden}",
                id.name
            )));
        }
    }

    match id.name.as_str() {
        "@method" => {
            let method = ctx
                .method
                .ok_or_else(|| ComponentError::new("@method requires a request"))?;
            Ok(method.as_str().to_owned())
        }
        "@authority" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@authority requires a request URI"))?;
            let authority = uri
                .authority()
                .map(|a| a.to_string().to_ascii_lowercase())
                .or_else(|| {
                    ctx.headers
                        .get(rama_http_types::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_ascii_lowercase())
                })
                .ok_or_else(|| ComponentError::new("@authority not available"))?;
            Ok(authority)
        }
        "@scheme" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@scheme requires a request URI"))?;
            let scheme = uri
                .scheme_str()
                .ok_or_else(|| ComponentError::new("@scheme not available"))?
                .to_ascii_lowercase();
            Ok(scheme)
        }
        "@target-uri" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@target-uri requires a request URI"))?;
            Ok(uri.to_string())
        }
        "@request-target" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@request-target requires a request URI"))?;
            let path = uri.path_or_root();
            match uri.query() {
                Some(q) => Ok(format!("{path}?{}", q.as_encoded_str())),
                None => Ok(path.into_owned()),
            }
        }
        "@path" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@path requires a request URI"))?;
            Ok(uri.path_or_root().into_owned())
        }
        "@query" => {
            let uri = ctx
                .uri
                .ok_or_else(|| ComponentError::new("@query requires a request URI"))?;
            match uri.query() {
                Some(q) => Ok(format!("?{}", q.as_encoded_str())),
                None => Ok("?".to_owned()),
            }
        }
        "@query-param" => {
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
            uri.first_query_value(name.as_str())
                .map(|v| v.into_owned())
                .ok_or_else(|| ComponentError::new(format!("@query-param name={name} not found")))
        }
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

fn resolve_field(
    ctx: &ComponentContext<'_>,
    id: &ComponentIdentifier,
) -> Result<String, ComponentError> {
    let name = id.name.to_ascii_lowercase();
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

    if use_sf && use_bs {
        return Err(ComponentError::new(";sf and ;bs are mutually exclusive"));
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
        // Byte-sequence wrap each field value, serialize as SF List of byte sequences
        let values: Vec<_> = map.get_all(&header_name).iter().collect();
        if values.is_empty() {
            return Err(ComponentError::new(format!("field {name} not present")));
        }
        let mut out = String::new();
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push(':');
            use base64::Engine as _;
            out.push_str(&base64::engine::general_purpose::STANDARD.encode(v.as_bytes()));
            out.push(':');
        }
        return Ok(out);
    }

    if use_sf || key.is_some() {
        // Combine field values and parse as Structured Field
        let combined = combine_field_values(map, &header_name)?;
        if let Some(key_name) = key {
            // Dictionary member lookup
            let dict = parse_dictionary(&combined).map_err(|e| {
                ComponentError::new(format!("field {name} is not a valid SF dictionary: {e}"))
            })?;
            let member = dict.get(key_name).ok_or_else(|| {
                ComponentError::new(format!("dictionary key {key_name} not found"))
            })?;
            return Ok(serialize_dictionary_member(member));
        }
        // Strict SF serialization: re-parse and re-serialize dictionary (most common for Content-Digest)
        if let Ok(dict) = parse_dictionary(&combined) {
            return Ok(serialize_dictionary(&dict));
        }
        // Fallback: return combined as-is if not a dictionary (lists etc. — subset limitation)
        return Ok(combined);
    }

    combine_field_values(map, &header_name)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::{Method, Request};

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
}
