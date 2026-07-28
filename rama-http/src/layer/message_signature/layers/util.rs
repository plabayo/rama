//! Helpers shared by sign/verify layers.

use std::time::{SystemTime, UNIX_EPOCH};

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use rama_http_headers::signature_input::{
    ComponentIdentifier, SignatureParameters, SignatureParams,
};
use rama_http_headers::{HeaderMapExt, Signature, SignatureInput};
use rama_http_types::{HeaderMap, Request, Response};

use super::super::{ComponentContext, build_signature_base};
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

pub(crate) fn apply_signature(
    headers: &mut HeaderMap,
    label: &str,
    signature: Vec<u8>,
    params: SignatureParams,
) {
    let mut input = headers.typed_get::<SignatureInput>().unwrap_or_default();
    input.insert(label.to_owned(), params);
    headers.typed_insert(input);

    let mut sig = headers.typed_get::<Signature>().unwrap_or_default();
    sig.insert(label.to_owned(), signature);
    headers.typed_insert(sig);
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
