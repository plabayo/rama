//! Existing early streams drain independently of new-request admission.
use super::*;
use rama::http::proto::ext::early_data::EarlyDataAttempt;

#[derive(Clone, Copy, Debug)]
enum Drain {
    AcceptedGoaway,
    AnsweredClose,
    ExcludedGoaway,
}

#[tokio::test]
async fn early_responses_survive_accepted_goaway_and_confirmed_close() {
    for provider in Provider::enabled() {
        for drain in [
            Drain::AcceptedGoaway,
            Drain::AnsweredClose,
            Drain::ExcludedGoaway,
        ] {
            timeout(LIMIT, response_after_drain(provider, drain))
                .await
                .unwrap();
        }
    }
}

async fn response_after_drain(provider: Provider, drain: Drain) {
    let mut processed = 0;
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;
    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let (mut sender, driver) =
        client::handshake::<Body, _>(client.clone(), early_config(), WeakScope::never()).unwrap();
    let observer = sender.clone();
    let _client_driver = Task::spawn(driver.run());
    let (mut receiver, driver) = server::handshake(server.clone(), Config::default()).unwrap();
    let _server_driver = Task::spawn(driver.run());
    let mut sending = pin!(sender.send_request(request(Method::GET, "")));
    timeout(PROBE, &mut sending).await.unwrap_err();
    assert_eq!(client.early_data_accepted(), None);
    // Stop polling the request while the transport and control drivers progress.
    if matches!(drain, Drain::ExcludedGoaway) {
        receiver.shutdown().unwrap(); // limit 0 excludes the sent stream 0.
        fixture.gate.release();
        while !observer.is_draining() {
            tokio::task::yield_now().await;
        }
        assert!(sending.await.unwrap_err().is_rejected());
        assert!(receiver.accept().await.is_err());
        assert_eq!(processed, 0);
        return;
    }
    let stream = receiver.accept().await.unwrap();
    fixture.gate.release();
    let (request, response) = stream.resolve().await.unwrap();
    assert!(
        request
            .extensions()
            .contains::<rama::http::proto::ext::early_data::EarlyDataReceived>()
    );
    request.into_body().collect().await.unwrap();
    processed += 1;
    respond(response).await;
    client.handshake_confirmed().await.unwrap();
    match drain {
        Drain::AcceptedGoaway => {
            receiver.shutdown().unwrap(); // limit 4 permits the accepted stream 0.
            while !observer.is_draining() {
                tokio::task::yield_now().await;
            }
        }
        Drain::AnsweredClose => {
            server.close(0x100u32, b"answered before graceful close");
            client.closed().await;
            assert!(client.is_handshake_confirmed());
        }
        Drain::ExcludedGoaway => unreachable!(),
    }
    let response = sending.await.expect("accepted early response must drain");
    assert_eq!(processed, 1);
    assert!(receiver.accept().await.is_err());
    assert!(response.extensions().contains::<EarlyDataAttempt>());
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "served"
    );
}
