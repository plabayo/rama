//! End-to-end tests for HTTP Message Signature layers.

#![cfg(feature = "message-signature")]

use std::sync::Arc;

use rama_core::error::BoxError;
use rama_core::service::service_fn;
use rama_core::{Layer, Service};
use rama_crypto::http_message_signature::{Ed25519SigningKey, HmacSha256Key, HttpMessageVerifier};
use rama_http_headers::signature_input::ComponentIdentifier;
use rama_http_headers::{HeaderMapExt, Signature, SignatureInput};
use rama_http_types::{Body, Method, Request, Response, StatusCode};

use super::util::{apply_signature, compute_signature, request_context, verify_from_headers};
use super::{
    AddProxySignatureLayer, KeyidVerifierMap, ProxySignaturePolicy, SignConfig, SignRequestLayer,
    StaticVerifier, VerifyConfig, VerifyRequestLayer, default_request_components,
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
async fn proxy_appends_second_label() {
    let client_signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let client_verifier: Arc<dyn HttpMessageVerifier> = Arc::new(client_signer.verifier());
    let proxy_signer = Arc::new(Ed25519SigningKey::generate().unwrap());

    let client_sign = SignConfig::new(client_signer, default_request_components())
        .with_keyid("client")
        .with_label("sig1");

    let proxy_sign = SignConfig::new(proxy_signer, default_request_components())
        .with_keyid("proxy")
        .with_label("proxy_sig");

    let verify = VerifyConfig::new(Arc::new(
        KeyidVerifierMap::new().with("client", client_verifier),
    ))
    .with_label("sig1");

    let svc = (
        SignRequestLayer::new(client_sign),
        AddProxySignatureLayer::new(ProxySignaturePolicy::new(proxy_sign).with_verify(verify)),
    )
        .into_layer(service_fn(async |req: Request| {
            let input = req.headers().typed_get::<SignatureInput>().unwrap();
            let sig = req.headers().typed_get::<Signature>().unwrap();
            assert_eq!(input.len(), 2);
            assert!(input.get("sig1").is_some());
            assert!(input.get("proxy_sig").is_some());
            assert!(sig.get("sig1").is_some());
            assert!(sig.get("proxy_sig").is_some());
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }));

    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
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
    apply_signature(req.headers_mut(), &sign_config.label, signature, params).unwrap();

    *req.uri_mut() = "https://evil.example.com/a".parse().unwrap();

    let ctx = request_context(&req);
    verify_from_headers(&ctx, req.headers(), &verify_config).unwrap_err();
}

#[tokio::test]
async fn response_sign_verify_with_req_binding() {
    use super::{SignResponseLayer, VerifyResponseLayer};
    use rama_http_headers::util::structured_fields::{ParameterValue, Parameters};

    let signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let verifier: Arc<dyn HttpMessageVerifier> = Arc::new(signer.verifier());

    let components = vec![
        ComponentIdentifier::new("@status"),
        ComponentIdentifier::new("@method")
            .with_parameters(Parameters::new().with("req", ParameterValue::Boolean(true))),
        ComponentIdentifier::new("@path")
            .with_parameters(Parameters::new().with("req", ParameterValue::Boolean(true))),
    ];

    let sign_config = SignConfig::new(signer, components.clone())
        .with_keyid("resp")
        .with_label("resp");
    let verify_config = VerifyConfig::new(Arc::new(StaticVerifier::new(verifier)))
        .with_label("resp")
        .with_required_components(vec![
            ComponentIdentifier::new("@status"),
            ComponentIdentifier::new("@method")
                .with_parameters(Parameters::new().with("req", ParameterValue::Boolean(true))),
        ]);

    let svc = (
        VerifyResponseLayer::new(verify_config),
        SignResponseLayer::new(sign_config),
    )
        .into_layer(service_fn(async |_req: Request| {
            Ok::<_, BoxError>(Response::builder().status(200).body(Body::empty()).unwrap())
        }));

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/resource")
        .body(Body::empty())
        .unwrap();
    svc.serve(req).await.unwrap();
}

#[tokio::test]
async fn required_components_enforced() {
    let signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let verifier: Arc<dyn HttpMessageVerifier> = Arc::new(signer.verifier());

    let sign_config =
        SignConfig::new(signer, vec![ComponentIdentifier::new("@method")]).with_keyid("k");
    let verify_config = VerifyConfig::new(Arc::new(StaticVerifier::new(verifier)))
        .with_required_components(default_request_components());

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .body(Body::empty())
        .unwrap();
    let (signature, params) = {
        let ctx = request_context(&req);
        compute_signature(&ctx, &sign_config).unwrap()
    };
    apply_signature(req.headers_mut(), &sign_config.label, signature, params).unwrap();

    let ctx = request_context(&req);
    verify_from_headers(&ctx, req.headers(), &verify_config).unwrap_err();
}

#[tokio::test]
async fn reject_invalid_signature_label() {
    let signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let sign_config = SignConfig::new(signer, default_request_components())
        .with_keyid("k")
        .with_label("Sig1");
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .body(Body::empty())
        .unwrap();
    let ctx = request_context(&req);
    compute_signature(&ctx, &sign_config).unwrap_err();
}

#[tokio::test]
async fn proxy_rejects_duplicate_label() {
    let client_signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let proxy_signer = Arc::new(Ed25519SigningKey::generate().unwrap());

    let client_sign = SignConfig::new(client_signer, default_request_components())
        .with_keyid("client")
        .with_label("sig1");
    let proxy_sign = SignConfig::new(proxy_signer, default_request_components())
        .with_keyid("proxy")
        .with_label("sig1");

    let svc = (
        SignRequestLayer::new(client_sign),
        AddProxySignatureLayer::new(ProxySignaturePolicy::new(proxy_sign)),
    )
        .into_layer(service_fn(async |_req: Request| {
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }));

    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .body(Body::empty())
        .unwrap();
    svc.serve(req).await.unwrap_err();
}

#[tokio::test]
async fn proxy_rejects_malformed_existing_signature_input() {
    let proxy_signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let proxy_sign = SignConfig::new(proxy_signer, default_request_components())
        .with_keyid("proxy")
        .with_label("proxy_sig");

    let svc = AddProxySignatureLayer::new(ProxySignaturePolicy::new(proxy_sign))
        .into_layer(service_fn(async |_req: Request| {
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }));

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .body(Body::empty())
        .unwrap();
    req.headers_mut().insert(
        rama_http_types::header::SIGNATURE_INPUT,
        "not a valid structured field!!!".parse().unwrap(),
    );
    svc.serve(req).await.unwrap_err();
}

#[tokio::test]
async fn proxy_response_appends_with_req_binding() {
    use super::{AddProxyResponseSignatureLayer, SignResponseLayer};
    use rama_http_headers::util::structured_fields::{ParameterValue, Parameters};

    let origin_signer = Arc::new(Ed25519SigningKey::generate().unwrap());
    let proxy_signer = Arc::new(Ed25519SigningKey::generate().unwrap());

    let components = vec![
        ComponentIdentifier::new("@status"),
        ComponentIdentifier::new("@method")
            .with_parameters(Parameters::new().with("req", ParameterValue::Boolean(true))),
    ];

    let origin_sign = SignConfig::new(origin_signer, components.clone())
        .with_keyid("origin")
        .with_label("sig1");
    let proxy_sign = SignConfig::new(proxy_signer, components)
        .with_keyid("proxy")
        .with_label("proxy_sig");

    let svc = (
        AddProxyResponseSignatureLayer::new(ProxySignaturePolicy::new(proxy_sign)),
        SignResponseLayer::new(origin_sign),
    )
        .into_layer(service_fn(async |_req: Request| {
            Ok::<_, BoxError>(Response::builder().status(200).body(Body::empty()).unwrap())
        }));

    let req = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/item")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(req).await.unwrap();
    let input = res.headers().typed_get::<SignatureInput>().unwrap();
    assert_eq!(input.len(), 2);
    assert!(input.get("sig1").is_some());
    assert!(input.get("proxy_sig").is_some());
}
