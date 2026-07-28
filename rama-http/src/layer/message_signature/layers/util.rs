//! Helpers shared by sign/verify/proxy layers.

use std::time::{SystemTime, UNIX_EPOCH};

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use rama_http_headers::signature_input::{
    ComponentIdentifier, SignatureParameters, SignatureParams,
};
use rama_http_headers::{HeaderMapExt, Signature, SignatureInput, TypedHeader};
use rama_http_types::{HeaderMap, Method, Request, Response};
use rama_net::uri::Uri;

use super::super::{ComponentContext, build_signature_base, component::component_identity_key};
use super::config::{SignConfig, VerifyConfig};

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn build_parameters(config: &SignConfig) -> SignatureParameters {
    let mut parameters = SignatureParameters::default();
    if config.include_created {
        parameters.created = Some(now_unix());
    }
    if let Some(d) = config.expires_after {
        parameters.expires = Some(now_unix() + d.as_secs() as i64);
    }
    if config.include_alg {
        parameters.alg = Some(config.signer.algorithm().to_owned());
    }
    parameters.keyid = config.keyid.clone();
    parameters.tag = config.tag.clone();
    parameters
}

pub(crate) fn compute_signature(
    ctx: &ComponentContext<'_>,
    config: &SignConfig,
) -> Result<(Vec<u8>, SignatureParams), BoxError> {
    validate_signature_label(&config.label)?;
    let parameters = build_parameters(config);
    let base =
        build_signature_base(ctx, &config.components, &parameters).map_err(BoxError::from)?;
    let signature = config
        .signer
        .sign_message(base.as_bytes())
        .context("sign HTTP message")?;
    Ok((
        signature,
        SignatureParams {
            components: config.components.clone(),
            parameters,
        },
    ))
}

/// Structured Fields dictionary key grammar (RFC 9651 §3.1.2):
/// `lcalpha / "*"` then `*(lcalpha / DIGIT / "_" / "-" / "." / "*")`.
pub(crate) fn validate_signature_label(label: &str) -> Result<(), BoxError> {
    let mut bytes = label.as_bytes().iter().copied();
    match bytes.next() {
        Some(b @ (b'a'..=b'z' | b'*')) => {
            let _ = b;
        }
        _ => {
            return Err(BoxError::from_static_str(
                "signature label is not a valid structured field key",
            ));
        }
    }
    if bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')) {
        Ok(())
    } else {
        Err(BoxError::from_static_str(
            "signature label is not a valid structured field key",
        ))
    }
}

/// Insert or replace a signature label (used by sign layers).
pub(crate) fn apply_signature(
    headers: &mut HeaderMap,
    label: &str,
    signature: Vec<u8>,
    params: SignatureParams,
) -> Result<(), BoxError> {
    validate_signature_label(label)?;
    let mut input = headers.typed_get::<SignatureInput>().unwrap_or_default();
    input.insert(label.to_owned(), params);
    headers.typed_insert(input);

    let mut sig = headers.typed_get::<Signature>().unwrap_or_default();
    sig.insert(label.to_owned(), signature);
    headers.typed_insert(sig);
    Ok(())
}

/// Append a signature label; errors if the label already exists (proxy / §4.3).
///
/// If `Signature` / `Signature-Input` are present but malformed, fails instead of
/// discarding them via `typed_get(...).unwrap_or_default()`.
pub(crate) fn apply_signature_unique(
    headers: &mut HeaderMap,
    label: &str,
    signature: Vec<u8>,
    params: SignatureParams,
) -> Result<(), BoxError> {
    validate_signature_label(label)?;

    let mut input = if headers.contains_key(SignatureInput::name()) {
        headers.typed_get::<SignatureInput>().ok_or_else(|| {
            BoxError::from_static_str(
                "existing Signature-Input header is malformed; refusing to replace",
            )
        })?
    } else {
        SignatureInput::default()
    };
    let mut sig = if headers.contains_key(Signature::name()) {
        headers.typed_get::<Signature>().ok_or_else(|| {
            BoxError::from_static_str("existing Signature header is malformed; refusing to replace")
        })?
    } else {
        Signature::default()
    };

    if input.get(label).is_some() || sig.get(label).is_some() {
        return Err(BoxError::from_static_str(
            "signature label already present; proxy signatures must use a unique label",
        ));
    }

    input.insert(label.to_owned(), params);
    headers.typed_insert(input);
    sig.insert(label.to_owned(), signature);
    headers.typed_insert(sig);
    Ok(())
}

pub(crate) fn verify_from_headers(
    ctx: &ComponentContext<'_>,
    headers: &HeaderMap,
    config: &VerifyConfig,
) -> Result<String, BoxError> {
    let input = headers
        .typed_get::<SignatureInput>()
        .ok_or_else(|| BoxError::from_static_str("missing Signature-Input header"))?;
    let sig = headers
        .typed_get::<Signature>()
        .ok_or_else(|| BoxError::from_static_str("missing Signature header"))?;

    let label = if let Some(ref label) = config.label {
        label.clone()
    } else {
        input
            .labels()
            .next()
            .ok_or_else(|| BoxError::from_static_str("Signature-Input has no labels"))?
            .to_owned()
    };

    let params = input
        .get(&label)
        .ok_or_else(|| BoxError::from_static_str("signature label not found in Signature-Input"))?;
    let signature = sig
        .get(&label)
        .ok_or_else(|| BoxError::from_static_str("signature label not found in Signature"))?;

    for required in &config.required_components {
        let want = component_identity_key(required);
        if !params
            .components
            .iter()
            .any(|c| component_identity_key(c) == want)
        {
            return Err(BoxError::from_static_str(
                "signature missing required covered component",
            ));
        }
    }

    // Temporal checks
    let now = now_unix();
    if config.require_created && params.parameters.created.is_none() {
        return Err(BoxError::from_static_str(
            "signature missing created parameter",
        ));
    }
    if let Some(created) = params.parameters.created {
        let skew = config.clock_skew.as_secs() as i64;
        if created > now + skew {
            return Err(BoxError::from_static_str("signature created in the future"));
        }
        if let Some(max_age) = config.max_age
            && now - created > max_age.as_secs() as i64 + skew
        {
            return Err(BoxError::from_static_str("signature too old"));
        }
    }
    if let Some(expires) = params.parameters.expires
        && expires < now - config.clock_skew.as_secs() as i64
    {
        return Err(BoxError::from_static_str("signature expired"));
    }

    let verifier = config
        .resolver
        .resolve(
            params.parameters.keyid.as_deref(),
            params.parameters.alg.as_deref(),
        )
        .ok_or_else(|| BoxError::from_static_str("no verification key for signature"))?;

    if let Some(ref alg) = params.parameters.alg
        && alg != verifier.algorithm()
    {
        return Err(BoxError::from_static_str(
            "alg parameter does not match verifier algorithm",
        ));
    }

    let base = build_signature_base(ctx, &params.components, &params.parameters)
        .map_err(BoxError::from)?;
    verifier
        .verify_message(base.as_bytes(), signature)
        .context("verify HTTP message signature")?;
    Ok(label)
}

pub(crate) fn request_context<'a, B>(req: &'a Request<B>) -> ComponentContext<'a> {
    ComponentContext::for_request(req.method(), req.uri(), req.headers())
}

pub(crate) fn response_context<'a, B>(
    res: &'a Response<B>,
    related: Option<ComponentContext<'a>>,
) -> ComponentContext<'a> {
    let mut ctx = ComponentContext::for_response(res.status(), res.headers());
    if let Some(related) = related {
        ctx = ctx.with_related_request(related);
    }
    ctx
}

/// Snapshot of the related request needed to resolve `;req` on responses.
#[derive(Clone)]
pub(crate) struct RelatedRequestSnapshot {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}

impl RelatedRequestSnapshot {
    pub(crate) fn from_request<B>(req: &Request<B>) -> Self {
        Self {
            method: req.method().clone(),
            uri: req.uri().clone(),
            headers: req.headers().clone(),
        }
    }

    pub(crate) fn context(&self) -> ComponentContext<'_> {
        ComponentContext::for_request(&self.method, &self.uri, &self.headers)
    }
}

/// Default covered components matching curl's experimental default.
#[must_use]
pub fn default_request_components() -> Vec<ComponentIdentifier> {
    vec![
        ComponentIdentifier::new("@method"),
        ComponentIdentifier::new("@authority"),
        ComponentIdentifier::new("@path"),
        ComponentIdentifier::new("@query"),
    ]
}

/// Default response components (status + common entity headers).
#[must_use]
pub fn default_response_components() -> Vec<ComponentIdentifier> {
    vec![
        ComponentIdentifier::new("@status"),
        ComponentIdentifier::new("content-type"),
        ComponentIdentifier::new("content-digest"),
    ]
}
