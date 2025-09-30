use rama::{
    Layer as _, Service as _,
    http::{
        Uri, client::EasyHttpWebClient, headers::Authorization,
        layer::set_header::SetRequestHeaderLayer, tls::CertIssuerHttpClient,
    },
    net::{
        tls::{
            ApplicationProtocol, DataEncoding,
            server::{
                CacheKind, SelfSignedData, ServerAuth, ServerAuthData, ServerCertIssuerData,
                ServerConfig,
            },
        },
        user::Bearer,
    },
    tls::boring::{
        client::TlsConnectorDataBuilder,
        core::x509::{X509, store::X509StoreBuilder},
    },
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use std::sync::Arc;

#[must_use]
pub fn new_server_config(alpn: Option<Vec<ApplicationProtocol>>) -> ServerConfig {
    if let Ok(uri_raw) = std::env::var("RAMA_TLS_REMOTE") {
        let mut tls_config = TlsConnectorDataBuilder::new_http_auto();

        if let Ok(remote_ca_raw) = std::env::var("RAMA_TLS_REMOTE_CA") {
            let mut store_builder = X509StoreBuilder::new().expect("build x509 store builder");
            store_builder
                .add_cert(
                    X509::from_pem(
                        &ENGINE
                            .decode(remote_ca_raw)
                            .expect("base64 decode RAMA_TLS_REMOTE_CA")[..],
                    )
                    .expect("load CA cert"),
                )
                .expect("add CA cert to store builder");
            let store = store_builder.build();
            tls_config.set_server_verify_cert_store(store);
        }

        let client = EasyHttpWebClient::builder()
            .with_default_transport_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_boringssl(Some(Arc::new(tls_config)))
            .build();

        let uri: Uri = uri_raw.parse().expect("RAMA_TLS_REMOTE to be a valid URI");
        let client = if let Ok(auth_raw) = std::env::var("RAMA_TLS_REMOTE_AUTH") {
            CertIssuerHttpClient::new_with_client(
                uri,
                SetRequestHeaderLayer::overriding_typed(Authorization::new(
                    Bearer::new(auth_raw).expect("RAMA_TLS_REMOTE_AUTH to be a valid Bearer token"),
                ))
                .into_layer(client)
                .boxed(),
            )
        } else {
            CertIssuerHttpClient::new_with_client(uri, client.boxed())
        };

        return ServerConfig {
            application_layer_protocol_negotiation: alpn,
            ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
                kind: client.into(),
                cache_kind: CacheKind::default(),
            }))
        };
    }

    let Ok(tls_key_pem_raw) = std::env::var("RAMA_TLS_KEY") else {
        return ServerConfig {
            application_layer_protocol_negotiation: alpn,
            ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()))
        };
    };
    let tls_key_pem_raw = std::str::from_utf8(
        &ENGINE
            .decode(tls_key_pem_raw)
            .expect("base64 decode RAMA_TLS_KEY")[..],
    )
    .expect("base64-decoded RAMA_TLS_KEY valid utf-8")
    .try_into()
    .expect("tls_key_pem_raw => NonEmptyStr (RAMA_TLS_KEY)");
    let tls_crt_pem_raw = std::env::var("RAMA_TLS_CRT").expect("RAMA_TLS_CRT");
    let tls_crt_pem_raw = std::str::from_utf8(
        &ENGINE
            .decode(tls_crt_pem_raw)
            .expect("base64 decode RAMA_TLS_CRT")[..],
    )
    .expect("base64-decoded RAMA_TLS_CRT valid utf-8")
    .try_into()
    .expect("tls_crt_pem_raw => NonEmptyStr (RAMA_TLS_CRT)");
    ServerConfig {
        application_layer_protocol_negotiation: alpn,
        ..ServerConfig::new(ServerAuth::Single(ServerAuthData {
            private_key: DataEncoding::Pem(tls_key_pem_raw),
            cert_chain: DataEncoding::Pem(tls_crt_pem_raw),
            ocsp: None,
        }))
    }
}
