use std::sync::Arc;

use rama_core::{Layer, Service as _, ServiceInput, telemetry::tracing};
use rama_net::stream::service::EchoService;
use rama_tls::{
    SupportedGroup,
    client::{ServerVerifyMode, TlsClientConfig},
    server::{SelfSignedData, TlsServerConfig},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

use crate::{
    client::{BoringClientConfigExt as _, TlsConnectorData, tls_connect},
    server::TlsAcceptorLayer,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_assumed_default_group_id_support() {
    let server = Arc::new(
        TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .try_with_self_signed(SelfSignedData::default())
                .expect("self-signed"),
        )
        .into_layer(EchoService::new()),
    );

    for group in [
        // based on rama-boring-sys@patched: kDefaultSupportedGroupIds
        SupportedGroup::X25519MLKEM768,
        SupportedGroup::X25519,
        SupportedGroup::MLKEM1024,
        SupportedGroup::SECP256R1,
        SupportedGroup::SECP384R1,
        SupportedGroup::SECP521R1,
        SupportedGroup::X25519KYBER768DRAFT00,
        SupportedGroup::X25519KYBER512DRAFT00,
    ] {
        tracing::info!("test group: {group:?}");

        let (stream_client, stream_server) = tokio::io::duplex(usize::MAX);
        let handle = tokio::spawn({
            let server = server.clone();
            async move {
                server
                    .serve(ServiceInput::new(stream_server))
                    .await
                    .unwrap();
            }
        });

        let config = TlsConnectorData::try_from(
            &TlsClientConfig::new()
                .with_supported_groups(vec![group])
                .with_server_verify(ServerVerifyMode::Disable),
        )
        .unwrap();
        let mut stream = tls_connect(ServiceInput::new(stream_client), Some(config))
            .await
            .unwrap_or_else(|err| {
                panic!("failed to TLS connect with group {group:?}: {err}");
            });

        stream.write_all(b"Hello, Tls!").await.unwrap();
        let mut buffer = [0u8; 11];
        stream.read_exact(&mut buffer[..]).await.unwrap();
        assert_eq!(b"Hello, Tls!", &buffer[..]);

        drop(stream);
        handle.await.unwrap();
    }
}
