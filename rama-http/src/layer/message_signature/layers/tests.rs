//! End-to-end tests for HTTP Message Signature layers.

#![cfg(feature = "message-signature")]

use std::sync::Arc;

use rama_core::error::BoxError;
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use rama_crypto::http_message_signature::{Ed25519SigningKey, HmacSha256Key, HttpMessageVerifier};
use rama_http_headers::{HeaderMapExt, Signature, SignatureInput};
use rama_http_types::{Body, Method, Request, Response, StatusCode};

use super::util::{apply_signature, compute_signature, request_context, verify_from_headers};
use super::{
    KeyidVerifierMap, SignConfig, SignRequestLayer, StaticVerifier, VerifyConfig,
    VerifyRequestLayer, default_request_components,
};

#[tokio::test]
async fn sign_and_verify_ed25519_request() {
    let signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let verifier: Arc<dyn HttpMessageVerifier> = Arc::new(signer.verifier());

    let sign_config = SignConfig::new(signer, default_request_components())
        .with_keyid("test-ed25519")
        .with_label("sig1");
    let verify_config = VerifyConfig::new(Arc::new(
        KeyidVerifierMap::new().with("test-ed25519", verifier),
    ))
    .with_label("sig1");

    let svc = (
        SignRequestLayer::new(sign_config),
        VerifyRequestLayer::new(verify_config),
    )
        .into_layer(service_fn(async |req: Request| {
            assert!(req.headers().typed_get::<Signature>().is_some());
            assert!(req.headers().typed_get::<SignatureInput>().is_some());
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }));

    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/foo?q=1")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn hmac_sign_verify() {
    let key = Arc::new(HmacSha256Key::new(b"shared-secret-key-material!!!!"));
    let key2: Arc<dyn HttpMessageVerifier> =
        Arc::new(HmacSha256Key::new(b"shared-secret-key-material!!!!"));

    let sign_config = SignConfig::new(key, default_request_components()).with_keyid("hmac-1");
    let verify_config = VerifyConfig::new(Arc::new(StaticVerifier::new(key2)));

    let svc = (
        SignRequestLayer::new(sign_config),
        VerifyRequestLayer::new(verify_config),
    )
        .into_layer(service_fn(async |_req: Request| {
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }));

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://api.example.com/v1")
        .body(Body::empty())
        .unwrap();
    svc.serve(req).await.unwrap();
}


#[tokio::test]
async fn reject_tampered_request() {
    let signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let verifier: Arc<dyn HttpMessageVerifier> = Arc::new(signer.verifier());

    let sign_config = SignConfig::new(signer, default_request_components()).with_keyid("k");
    let verify_config = VerifyConfig::new(Arc::new(StaticVerifier::new(verifier)));

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/a")
        .body(Body::empty())
        .unwrap();

    let (signature, params) = {
        let ctx = request_context(&req);
        compute_signature(&ctx, &sign_config).unwrap()
    };
    apply_signature(req.headers_mut(), &sign_config.label, signature, params);

    *req.uri_mut() = "https://evil.example.com/a".parse().unwrap();

    let ctx = request_context(&req);
    verify_from_headers(&ctx, req.headers(), &verify_config).unwrap_err();
}
