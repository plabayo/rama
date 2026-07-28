//! Signature base assembly (RFC 9421 §2.5).

use rama_http_headers::signature_input::{
    ComponentIdentifier, SignatureParameters, SignatureParams,
};
use rama_http_headers::{SignatureInput, serialize_signature_params_value};
use std::fmt;

use super::component::{
    ComponentContext, ComponentError, resolve_component_value, serialize_component_identifier,
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
    // Dedup check: each component identifier (name + params) must appear once
    let mut seen = Vec::new();
    for c in components {
        let key = serialize_component_identifier(c);
        if seen.iter().any(|s| s == &key) {
            return Err(SignatureBaseError::new(format!(
                "duplicate component identifier: {key}"
            )));
        }
        seen.push(key);
    }

    let mut lines = Vec::with_capacity(components.len() + 1);
    for c in components {
        let value = resolve_component_value(ctx, c)?;
        if value.contains('\n') {
            return Err(SignatureBaseError::new(
                "component value must not contain newline",
            ));
        }
        let id = serialize_component_identifier(c);
        lines.push(format!("{id}: {value}"));
    }

    let params = SignatureParams {
        components: components.to_vec(),
        parameters: parameters.clone(),
    };
    let params_line = build_signature_params_line(&params);
    lines.push(format!("\"@signature-params\": {params_line}"));

    Ok(lines.join("\n"))
}

/// Serialize the `@signature-params` component value (Inner List + params).
#[must_use]
pub fn build_signature_params_line(params: &SignatureParams) -> String {
    // Re-export path: use the same serialization as Signature-Input member values
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
        // Use builder headers + our map
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
        let parameters = SignatureParameters {
            created: Some(1618884480),
            expires: Some(1618884540),
            keyid: Some("test-key-rsa".into()),
            alg: Some("rsa-v1_5-sha256".into()),
            ..Default::default()
        };

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
}
