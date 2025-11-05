use std::sync::Arc;

use rama_boring::ssl::SslCurve;
use rama_core::{Layer, Service as _, ServiceInput, telemetry::tracing};
use rama_net::{
    address::Host,
    stream::service::EchoService,
    tls::{
        client::ServerVerifyMode,
        server::{SelfSignedData, ServerAuth, ServerConfig},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

use crate::{
    client::{TlsConnectorDataBuilder, tls_connect},
    server::TlsAcceptorLayer,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_assumed_default_group_id_support() {
    let server = Arc::new(
        TlsAcceptorLayer::new({
            let tls_server_config =
                ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData::default()));
            tls_server_config
                .try_into()
                .expect("create tls server config")
        })
        .into_layer(EchoService::new()),
    );

    for curve in [
        // based on rama-boring-sys@patched: kDefaultSupportedGroupIds
        SslCurve::X25519_MLKEM768,
        SslCurve::X25519,
        SslCurve::MLKEM1024,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::SECP521R1,
        SslCurve::X25519_KYBER768_DRAFT00,
        SslCurve::X25519_KYBER512_DRAFT00,
    ] {
        tracing::info!("test curve: {curve:?}");

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

        let mut stream = tls_connect(
            Host::EXAMPLE_NAME,
            ServiceInput::new(stream_client),
            Some(
                TlsConnectorDataBuilder::new()
                    .with_curves(vec![curve])
                    .with_server_verify_mode(ServerVerifyMode::Disable)
                    .build()
                    .unwrap(),
            ),
        )
        .await
        .unwrap_or_else(|err| {
            panic!("failed to TLS connect with curve {curve:?}: {err}");
        });

        stream.write_all(b"Hello, Tls!").await.unwrap();
        let mut buffer = [0u8; 11];
        stream.read_exact(&mut buffer[..]).await.unwrap();
        assert_eq!(b"Hello, Tls!", &buffer[..]);

        drop(stream);
        handle.await.unwrap();
    }
}
