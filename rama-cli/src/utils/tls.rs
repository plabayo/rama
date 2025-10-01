use rama::{
    http::tls::CertIssuerHttpClient,
    net::tls::{
        ApplicationProtocol, DataEncoding,
        server::{
            CacheKind, SelfSignedData, ServerAuth, ServerAuthData, ServerCertIssuerData,
            ServerConfig,
        },
    },
    telemetry::tracing,
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;

#[must_use]
pub fn new_server_config(alpn: Option<Vec<ApplicationProtocol>>) -> ServerConfig {
    match CertIssuerHttpClient::try_from_env() {
        Ok(issuer) => {
            return ServerConfig {
                application_layer_protocol_negotiation: alpn,
                ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
                    kind: issuer.into(),
                    cache_kind: CacheKind::default(),
                }))
            };
        }
        Err(err) => {
            tracing::debug!("failed to create CertIssuerHttpClient from env: {err}");
        }
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
