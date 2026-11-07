//! Common HTTP establishment still verifies ALPN for an early custom transport.

use super::*;
use rama::Service;
use rama_http_backend::client::{Http3Transport, http_connect};
use rama_http_core::h3::transport::BoxedConnection;
use rama_net::{address::HostWithPort, client::ConnectRequest, tls::ApplicationProtocol};

#[tokio::test]
async fn custom_early_transport_rejects_wrong_http_alpn_before_delivering_a_response() {
    for provider in Provider::enabled() {
        timeout(LIMIT, mismatched_alpn(provider)).await.unwrap();
    }
}

async fn mismatched_alpn(provider: Provider) {
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;
    fixture.gate.hold();
    let (connection, server) = fixture.early_pair().await;
    let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(443));
    input
        .extensions()
        .insert(EarlyDataPermit::with_recovery_owner());
    let service = http_connect::<_, _, Body>(
        Http3Transport {
            connection: BoxedConnection::new(connection.clone()),
            config: Arc::new(Config {
                application_protocol: ApplicationProtocol::from(b"wrong-http-alpn"),
                ..early_config()
            }),
        },
        input,
        WeakScope::detached(),
    )
    .await
    .unwrap()
    .conn;
    let sending = Task::spawn(async move {
        let mut request = request(Method::GET, "");
        *request.version_mut() = rama::http::Version::HTTP_3;
        service.serve(request).await
    });
    let (mut h3, driver) = server::handshake(server, Config::default()).unwrap();
    let _driver = Task::spawn(driver.run());
    let _pending = h3.accept().await.unwrap();
    assert!(
        !sending.0.as_ref().unwrap().is_finished(),
        "response waits for verification"
    );
    fixture.gate.release();
    let error = sending.join().await.unwrap_err();
    assert!(
        rama_core::error::error_chain(error.as_ref())
            .any(|cause| cause.to_string().contains("configured ALPN")),
        "{error:?}"
    );
    connection.closed().await;
}
