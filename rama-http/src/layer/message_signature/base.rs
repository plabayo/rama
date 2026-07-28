//! Signature base assembly (RFC 9421 §2.5).

use rama_http_headers::signature_input::{
    ComponentIdentifier, SignatureParameters, SignatureParams,
};
use rama_http_headers::{SignatureInput, serialize_signature_params_value};
use std::fmt;

use super::component::{
    ComponentContext, ComponentError, component_identity_key, resolve_component_value,
    serialize_component_identifier,
};

/// Error building a signature base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBaseError {
    pub message: String,
}

impl SignatureBaseError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SignatureBaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signature base error: {}", self.message)
    }
}

impl std::error::Error for SignatureBaseError {}

impl From<ComponentError> for SignatureBaseError {
    fn from(e: ComponentError) -> Self {
        Self { message: e.message }
    }
}

/// Build the signature base string for the given covered components and params.
///
/// The result is the exact byte sequence (as UTF-8 string) passed to HTTP_SIGN / HTTP_VERIFY.
pub fn build_signature_base(
    ctx: &ComponentContext<'_>,
    components: &[ComponentIdentifier],
    parameters: &SignatureParameters,
) -> Result<String, SignatureBaseError> {
    // Dedup: component identifiers that differ only by parameter order are duplicates.
    let mut seen = Vec::new();
    for c in components {
        let key = component_identity_key(c);
        if seen.iter().any(|s| s == &key) {
            return Err(SignatureBaseError::new(format!(
                "duplicate component identifier: {}",
                serialize_component_identifier(c)
            )));
        }
        seen.push(key);
    }

    let mut lines = Vec::with_capacity(components.len() + 1);
    for c in components {
        let value = resolve_component_value(ctx, c)?;
        validate_component_value_ascii(&value)?;
        let id = serialize_component_identifier(c);
        lines.push(format!("{id}: {value}"));
    }

    let params = SignatureParams {
        components: components.to_vec(),
        parameters: parameters.clone(),
    };
    let params_line = build_signature_params_line(&params);
    validate_component_value_ascii(&params_line)?;
    lines.push(format!("\"@signature-params\": {params_line}"));

    let base = lines.join("\n");
    validate_signature_base_ascii(&base)?;
    Ok(base)
}

fn validate_component_value_ascii(value: &str) -> Result<(), SignatureBaseError> {
    if value.contains('\n') || value.contains('\r') {
        return Err(SignatureBaseError::new(
            "component value must not contain CR or LF",
        ));
    }
    if !value.is_ascii() {
        return Err(SignatureBaseError::new(
            "component value must be ASCII",
        ));
    }
    Ok(())
}

fn validate_signature_base_ascii(base: &str) -> Result<(), SignatureBaseError> {
    if !base.is_ascii() {
        return Err(SignatureBaseError::new(
            "signature base must be ASCII",
        ));
    }
    // Printable ASCII + LF separators between lines (already joined with \n)
    for b in base.bytes() {
        if b != b'\n' && !(0x20..=0x7e).contains(&b) {
            return Err(SignatureBaseError::new(
                "signature base contains non-printable ASCII",
            ));
        }
    }
    Ok(())
}

/// Serialize the `@signature-params` component value (Inner List + params).
#[must_use]
pub fn build_signature_params_line(params: &SignatureParams) -> String {
    serialize_signature_params_value(params)
}

/// Build a [`SignatureInput`] entry for a label from components + parameters.
#[must_use]
pub fn signature_input_for_label(
    label: impl Into<String>,
    components: Vec<ComponentIdentifier>,
    parameters: SignatureParameters,
) -> SignatureInput {
    let mut input = SignatureInput::new();
    input.insert(
        label,
        SignatureParams {
            components,
            parameters,
        },
    );
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_headers::util::structured_fields::{ParameterValue, Parameters};
    use rama_http_types::{HeaderMap, HeaderValue, Method, Request};

    /// RFC 9421 §4.3 proxy signature-base example (without content-digest body specifics).
    #[test]
    fn rfc_4_3_signature_base_shape() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("content-length", HeaderValue::from_static("18"));
        headers.insert(
            "content-digest",
            HeaderValue::from_static(
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            ),
        );
        headers.insert(
            "forwarded",
            HeaderValue::from_static("for=192.0.2.123;host=example.com;proto=https"),
        );
        headers.insert(
            "host",
            HeaderValue::from_static("origin.host.internal.example"),
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri("https://origin.host.internal.example/foo?param=Value&Pet=dog")
            .body(())
            .unwrap();
        let mut req = req;
        *req.headers_mut() = headers;

        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let components = vec![
            ComponentIdentifier::new("@method"),
            ComponentIdentifier::new("@authority"),
            ComponentIdentifier::new("@path"),
            ComponentIdentifier::new("content-digest"),
            ComponentIdentifier::new("content-type"),
            ComponentIdentifier::new("content-length"),
            ComponentIdentifier::new("forwarded"),
        ];
        let mut parameters = SignatureParameters::new();
        parameters.created = Some(1618884480);
        parameters.expires = Some(1618884540);
        parameters.keyid = Some("test-key-rsa".into());
        parameters.alg = Some("rsa-v1_5-sha256".into());

        let base = build_signature_base(&ctx, &components, &parameters).unwrap();
        let expected = "\
\"@method\": POST\n\
\"@authority\": origin.host.internal.example\n\
\"@path\": /foo\n\
\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n\
\"content-type\": application/json\n\
\"content-length\": 18\n\
\"forwarded\": for=192.0.2.123;host=example.com;proto=https\n\
\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"content-length\" \"forwarded\");created=1618884480;expires=1618884540;alg=\"rsa-v1_5-sha256\";keyid=\"test-key-rsa\"";

        assert_eq!(base, expected);
    }

    #[test]
    fn duplicate_components_param_order_independent() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .header(
                "content-digest",
                "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
            )
            .body(())
            .unwrap();
        let ctx = ComponentContext::for_request(req.method(), req.uri(), req.headers());
        let a = ComponentIdentifier::new("content-digest").with_parameters(
            Parameters::new()
                .with("sf", ParameterValue::Boolean(true))
                .with("key", ParameterValue::String("sha-256".into())),
        );
        let b = ComponentIdentifier::new("content-digest").with_parameters(
            Parameters::new()
                .with("key", ParameterValue::String("sha-256".into()))
                .with("sf", ParameterValue::Boolean(true)),
        );
        let err = build_signature_base(
            &ctx,
            &[a, b],
            &SignatureParameters::default(),
        )
        .unwrap_err();
        assert!(err.message.contains("duplicate"));
    }
}
