use crate::harness::{Test, ensure};
use rama_core::{Layer as _, Service as _, ServiceInput};
use rama_crypto::cert::{GeneratedServerAuthConfig, generate_server_auth};
use rama_net::{address::Host, stream::service::EchoService};
use rama_tls::{
    client::{DistrustedServerKeys, TlsClientConfig, TlsServerTrust},
    server::{ServerAuthData, TlsServerConfig},
};
use rama_tls_boring::{
    client::{TlsConnectorData, tls_connect},
    server::TlsAcceptorLayer,
};
use rama_tls_rustls::{
    client::RustlsTlsConnectorConfig,
    dep::{rustls::pki_types::ServerName, tokio_rustls::TlsConnector},
};
use std::sync::Arc;

pub(crate) static TESTS: &[Test] = &[
    (
        "platform_verification_and_root_denial",
        platform_verification_and_root_denial,
    ),
    (
        "relay_platform_verification_and_root_denial",
        relay_platform_verification_and_root_denial,
    ),
];

fn platform_verification_and_root_denial() -> Result<(), String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(async {
            for boring in [true, false] {
                for mode in ["untrusted", "trusted", "denied"] {
                    let (chain, private_key) =
                        generate_server_auth(GeneratedServerAuthConfig::default())
                            .map_err(|e| e.to_string())?;
                    let root = chain.last().unwrap();
                    let trust = if mode == "untrusted" {
                        TlsServerTrust::platform_verifier()
                    } else {
                        TlsServerTrust::platform_verifier()
                            .try_with_additional_anchors([root.clone()])
                            .map_err(|e| e.to_string())?
                    };
                    let mut config = TlsClientConfig::new()
                        .with_server_name(Host::from_static("localhost"))
                        .with_server_trust(trust);
                    if mode == "denied" {
                        config.set_server_cert_chain_policy(
                            DistrustedServerKeys::new()
                                .try_with_key_of(root)
                                .map_err(|e| e.to_string())?,
                        );
                    }
                    let server = TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(
                        ServerAuthData {
                            cert_chain: vec![chain[0].clone()],
                            private_key,
                            ocsp: None,
                        },
                    ))
                    .into_layer(EchoService::new());
                    let (client_io, server_io) = tokio::io::duplex(65536);
                    let server_task =
                        tokio::spawn(
                            async move { server.serve(ServiceInput::new(server_io)).await },
                        );
                    let connected = if boring {
                        let data =
                            TlsConnectorData::try_from(&config).map_err(|e| e.to_string())?;
                        tls_connect(ServiceInput::new(client_io), Some(data))
                            .await
                            .is_ok()
                    } else {
                        let data = rama_tls_rustls::dep::rustls::ClientConfig::try_from(
                            RustlsTlsConnectorConfig::from_extensions(config.as_extensions()),
                        )
                        .map_err(|e| e.to_string())?;
                        TlsConnector::from(Arc::new(data))
                            .connect(ServerName::try_from("localhost").unwrap(), client_io)
                            .await
                            .is_ok()
                    };
                    drop(server_task.await);
                    ensure(
                        connected == (mode == "trusted"),
                        format!("boring={boring}, mode={mode}: connected={connected}"),
                    )?;
                }
            }
            Ok(())
        })
}

fn relay_platform_verification_and_root_denial() -> Result<(), String> {
    use rama_core::io::BridgeIo;
    use rama_tls::client::ServerVerifyMode;
    use rama_tls_boring::{
        core::{pkey::PKey, x509::X509},
        proxy::{TlsMitmEgressServerAuth, TlsMitmRelay, cert_issuer::StaticBoringMitmCertIssuer},
    };
    use rama_utils::collections::NonEmptyVec;

    let run = async {
        for mode in ["untrusted", "trusted", "denied"] {
            let (chain, private_key) = generate_server_auth(GeneratedServerAuthConfig::default())?;
            let root = chain.last().unwrap();
            let issuer = StaticBoringMitmCertIssuer::new(
                NonEmptyVec::new(X509::from_der(&chain[0])?),
                PKey::private_key_from_der(private_key.secret_der())?,
            );
            let mut auth = TlsMitmEgressServerAuth::new()
                .with_platform_verifier()
                .with_server_name(Host::from_static("localhost"));
            if mode != "untrusted" {
                auth.try_set_extra_server_trust_anchors([root.clone()])?;
            }
            if mode == "denied" {
                auth.set_server_cert_chain_policy(
                    DistrustedServerKeys::new().try_with_key_of(root)?,
                );
            }
            let relay = TlsMitmRelay::new(issuer)
                .with_keylog_intent(rama_tls::KeyLogIntent::Disabled)
                .with_egress_server_auth(auth);
            let server =
                TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                    cert_chain: vec![chain[0].clone()],
                    private_key,
                    ocsp: None,
                }))
                .into_layer(EchoService::new());
            let (client_io, ingress) = tokio::io::duplex(65536);
            let (egress, upstream) = tokio::io::duplex(65536);
            let server_task =
                tokio::spawn(async move { server.serve(ServiceInput::new(upstream)).await });
            // Exercise the public direct entrypoint, where the relay resolves
            // its own upstream policy without explicit caller connector data.
            let relay_task = tokio::spawn(async move {
                relay
                    .handshake(
                        BridgeIo(ServiceInput::new(ingress), ServiceInput::new(egress)),
                        None,
                    )
                    .await
                    .is_ok()
            });
            let guest = TlsClientConfig::new()
                .with_server_verify(ServerVerifyMode::Disable)
                .with_server_name(Host::from_static("localhost"));
            drop(
                tls_connect(
                    ServiceInput::new(client_io),
                    Some(TlsConnectorData::try_from(&guest)?),
                )
                .await,
            );
            let accepted = relay_task.await?;
            drop(server_task.await);
            ensure(
                accepted == (mode == "trusted"),
                format!("relay mode={mode}: accepted={accepted}"),
            )?;
        }
        Ok::<(), rama_core::error::BoxError>(())
    };
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(run)
        .map_err(|e| e.to_string())
}
