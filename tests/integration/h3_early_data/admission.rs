//! The one early lease does not depend on remembered stream credit.

use super::*;
use rama_core::extensions::ExtensionsMut as _;

#[tokio::test]
async fn early_lease_waits_for_zero_remembered_credit_without_reacquiring_its_permit() {
    for provider in Provider::enabled() {
        timeout(LIMIT, zero_credit(provider)).await.unwrap();
    }
}

async fn zero_credit(provider: Provider) {
    let fixture = Fixture::with_request_credit(provider, Version::V1, 0).await;
    let (warm_client, warm_server) = fixture.full_pair().await;
    // The ticket remembers initial zero credit, even though this connection
    // subsequently grants a request stream to complete warmup.
    warm_server.set_max_concurrent_bi_streams(1u32);
    assert_eq!(round_trip(&warm_client, &warm_server).await, "served");
    warm_client.close(0u32, b"warm complete");
    fixture.gate.hold();
    let (connection, server) = fixture.early_pair().await;
    let (sender, driver) = client::handshake::<Body, _>(
        connection.clone(),
        Config {
            max_requests: 1,
            ..early_config()
        },
        WeakScope::never(),
    )
    .unwrap();
    let _driver = Task::spawn(driver.run());
    let admission = sender.connection_admission();
    let mut request = request(Method::GET, "");
    let lease = admission
        .try_acquire(request.extensions())
        .unwrap()
        .expect("permit-only early lease");
    lease.bind(request.extensions_mut());
    let mut sending_sender = sender.clone();
    let sending = Task::spawn(async move {
        let _lease = lease;
        sending_sender.send_request(request).await
    });
    sleep(PROBE).await;
    assert!(!sending.0.as_ref().unwrap().is_finished());
    assert!(
        timeout(PROBE, server.accept_bi()).await.is_err(),
        "zero remembered credit was respected"
    );
    fixture.gate.release();
    connection.handshake_confirmed().await.unwrap();
    server.set_max_concurrent_bi_streams(1u32);
    let (mut h3, driver) = server::handshake(server, Config::default()).unwrap();
    let _driver = Task::spawn(driver.run());
    serve(h3.accept().await.unwrap()).await;
    let response = sending.join().await.unwrap();
    assert!(
        !response
            .extensions()
            .contains::<rama::http::proto::ext::early_data::EarlyDataAttempt>()
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "served"
    );
    assert!(
        !admission.in_use(),
        "verified and drained connections become idle"
    );
    assert!(connection.close_reason().is_none());
    drop(sender);
}
