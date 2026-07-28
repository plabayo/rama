//! HTTP Message Signatures (RFC 9421): client signs, server verifies (ed25519).
//!
//! # Run
//!
//! ```sh
//! cargo run -p rama-examples --bin http_message_signature --features=http-full,message-signature
//! ```

use std::sync::Arc;

use rama::{
    Layer, Service,
    crypto::http_message_signature::{Ed25519SigningKey, HttpMessageVerifier},
    error::BoxError,
    http::{
        Body, Method, Request, Response, StatusCode,
        headers::{HeaderMapExt, Signature, SignatureInput},
        layer::message_signature::{
            KeyidVerifierMap, SignConfig, SignRequestLayer, VerifyConfig, VerifyRequestLayer,
            default_request_components,
        },
    },
    service::service_fn,
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let signer = Arc::new(Ed25519SigningKey::generate()?);
    let verifier: Arc<dyn HttpMessageVerifier> = Arc::new(signer.verifier());

    let sign = SignConfig::new(signer, default_request_components())
        .with_keyid("demo-ed25519")
        .with_label("sig1");
    let verify = VerifyConfig::new(Arc::new(
        KeyidVerifierMap::new().with("demo-ed25519", verifier),
    ))
    .with_label("sig1");

    let svc = (SignRequestLayer::new(sign), VerifyRequestLayer::new(verify)).into_layer(
        service_fn(async |req: Request| {
            let input = req.headers().typed_get::<SignatureInput>().unwrap();
            let sig = req.headers().typed_get::<Signature>().unwrap();
            println!(
                "Signature-Input labels: {:?}",
                input.labels().collect::<Vec<_>>()
            );
            println!("Signature present for sig1: {}", sig.get("sig1").is_some());
            Ok::<_, BoxError>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .unwrap(),
            )
        }),
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/hello?x=1")
        .body(Body::empty())?;

    let res = svc.serve(req).await?;
    println!("status: {}", res.status());
    Ok(())
}
