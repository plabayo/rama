use super::utils;
use rama::tls::backend::rustls::dep::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    rustls::ServerConfig,
};
use rama::tls::dep::rcgen::KeyPair;
use rama::{
    http::{response::Json, server::HttpServer, BodyExtractExt, Request},
    net::address::ProxyAddress,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::backend::rustls::server::TlsAcceptorLayer,
    Context, Layer,
};
use serde_json::{json, Value};
use std::sync::Arc;

#[tokio::test]
#[ignore]
async fn test_http_mitm_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63003",
                service_fn(|req: Request| async move {
                    Ok(Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    })))
                }),
            )
            .await
            .unwrap();
    });

    let (_root_cert_der, server_cert_der, server_key_der) = generate_tls_cert_server();
    let mut tls_server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert_der],
            PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
        )
        .expect("create tls server config");
    tls_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let executor = Executor::default();

    let tcp_service = TlsAcceptorLayer::new(Arc::new(tls_server_config)).layer(
        HttpServer::auto(executor).service(service_fn(|req: Request| async move {
            Ok(Json(json!({
                "method": req.method().as_str(),
                "path": req.uri().path(),
            })))
        })),
    );

    tokio::spawn(async {
        TcpListener::bind("127.0.0.1:63004")
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: secure web service: {e}"))
            .serve(tcp_service)
            .await;
    });

    let runner = utils::ExampleRunner::interactive("http_mitm_proxy", Some("rustls"));

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress::try_from("http://john:secret@127.0.0.1:62017").unwrap());

    // test http request proxy flow
    let result = runner
        .get("http://127.0.0.1:63003/foo/bar")
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    // test https request proxy flow
    let result = runner
        .get("https://127.0.0.1:63004/foo/bar")
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);
}

fn generate_tls_cert_server() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
) {
    // Create an issuer CA cert.
    let alg: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key_pair = KeyPair::generate_for(alg).expect("generate CA server key pair");
    let mut ca_params =
        rcgen::CertificateParams::new(vec!["Example CA".to_owned()]).expect("create CA Params");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .expect("create ca (server) self-signed cert");
    let ca_cert_der = ca_cert.der().clone();

    // Create a server end entity cert issued by the CA.
    let mut server_ee_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("create server EE Params");
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_ee_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example Server");
    let server_key_pair = KeyPair::generate_for(alg).expect("generate tls server key pair");
    let server_cert = server_ee_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .expect("create server self-signed cert");
    let server_cert_der = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    (ca_cert_der, server_cert_der, server_key_der)
}
