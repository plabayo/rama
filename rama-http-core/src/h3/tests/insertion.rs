//! Current-field insertion preferences work through ordinary request/response extensions.

use super::*;
use crate::h3::{
    connection::{Shared, initial_control},
    control::Role,
    headers,
    qpack::{Encoder, EncoderConfig, ErrorScope},
    quic::Writer,
};
use rama_core::extensions::Extensions;
use rama_http_types::proto::h3::FrameType;
use rama_http_types::proto::h3::qpack::encoding::{
    FieldPreferences, HeaderPreferences, InsertionPreferences, Representation,
};
use std::future::poll_fn;

#[tokio::test(start_paused = true)]
async fn insertion_preferences_round_trip_on_fresh_connections_in_both_directions() {
    tokio::time::timeout(LIMIT, async {
        for startup in [Startup::Immediate, Startup::OnDemand] {
            let pair = Pair::in_memory(None, None).await;
            let mut config = Config::default();
            config.encoder.defer_dynamic_first_section = true;
            config.critical_streams.encoder = startup;
            let (mut server, driver) =
                server::handshake(pair.server.clone(), config.clone()).unwrap();
            spawn(driver.run());
            let (mut client, driver) =
                client::handshake::<Body>(pair.client.clone(), config, Executor::new()).unwrap();
            spawn(driver.run());
            let mut preferences = HeaderPreferences::default();
            preferences.headers.append(
                "x-current",
                FieldPreferences {
                    representation: Representation::LiteralName,
                    insertion: Some(InsertionPreferences::default()),
                    ..FieldPreferences::default()
                },
            );
            let response_preferences = preferences.clone();
            let serving = spawn(async move {
                let (request, respond) = server.accept().await.unwrap().resolve().await.unwrap();
                assert_eq!(request.headers()["x-current"], "request-owned");
                let response = Response::builder()
                    .header("x-current", "response-owned")
                    .body(Body::empty())
                    .unwrap();
                response.extensions().insert(response_preferences);
                respond.send_response(response).await.unwrap();
            });
            let request = Request::get("https://localhost/")
                .header("x-current", "request-owned")
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(preferences);
            let response = client.send_request(request).await.unwrap();
            assert_eq!(response.headers()["x-current"], "response-owned");
            response.into_body().collect().await.unwrap();
            serving.await.unwrap();
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn required_response_insertions_wait_for_late_peer_settings() {
    tokio::time::timeout(LIMIT, async {
        for informational in [false, true] {
            let pair = Pair::in_memory(None, None).await;
            let mut config = Config::default();
            config.encoder.defer_dynamic_first_section = true;
            let (mut server, driver) = server::handshake(pair.server.clone(), config).unwrap();
            spawn(driver.run());
            let (send, mut receive) = pair.client.open_bi().await.unwrap();
            let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
            let fields = encoder
                .encode(
                    u64::from(send.id()),
                    [
                        (":method", "GET"),
                        (":scheme", "https"),
                        (":authority", "localhost"),
                        (":path", "/"),
                    ],
                )
                .unwrap();
            let mut writer = Writer::new(send);
            writer.queue(FrameType::HEADERS, fields).unwrap();
            poll_fn(|cx| writer.poll_finish(cx)).await.unwrap();
            let (_, mut respond) = server.accept().await.unwrap().resolve().await.unwrap();
            let mut preferences = HeaderPreferences::default();
            preferences.headers.append(
                "x-current",
                FieldPreferences {
                    representation: Representation::LiteralName,
                    insertion: Some(InsertionPreferences::default()),
                    ..FieldPreferences::default()
                },
            );
            let sending = async move {
                if informational {
                    let response = Response::builder()
                        .status(103)
                        .header("x-current", "response-owned")
                        .body(())
                        .unwrap();
                    response.extensions().insert(preferences);
                    respond.send_informational(response).await?;
                    respond.send_response(Response::new(Body::empty())).await
                } else {
                    let response = Response::builder()
                        .header("x-current", "response-owned")
                        .body(Body::empty())
                        .unwrap();
                    response.extensions().insert(preferences);
                    respond.send_response(response).await
                }
            };
            tokio::pin!(sending);
            // The client deliberately has not opened its control stream. Neither
            // informational nor final required insertions may assume capacity0.
            tokio::time::timeout(Duration::from_secs(1), sending.as_mut())
                .await
                .unwrap_err();
            let mut control = pair.client.open_uni().await.unwrap();
            control
                .write_all(&initial_control(&Config::default(), Role::Client, false).unwrap())
                .await
                .unwrap();
            let (sent, bytes) = tokio::join!(sending, receive.read_to_end(4096));
            sent.unwrap();
            assert!(!bytes.unwrap().is_empty());
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn ordinary_header_preferences_do_not_wait_for_peer_settings() {
    let shared = Shared::new(Config::default(), Role::Client, Extensions::new()).unwrap();
    let extensions = Extensions::new();
    tokio::time::timeout(
        Duration::ZERO,
        headers::wait_for_insertion_settings(&shared, &extensions),
    )
    .await
    .unwrap()
    .unwrap();
    let mut preferences = HeaderPreferences::default();
    preferences.headers.append(
        "x-current",
        FieldPreferences {
            representation: Representation::LiteralName,
            ..FieldPreferences::default()
        },
    );
    extensions.insert(preferences);
    tokio::time::timeout(
        Duration::ZERO,
        headers::wait_for_insertion_settings(&shared, &extensions),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn rejected_insertion_credit_does_not_poison_an_ordinary_next_request() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut server, driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        spawn(driver.run());
        let serving = spawn(async move {
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap();
                let Ok((request, response)) = incoming.resolve().await else {
                    continue;
                };
                assert_eq!(request.headers()["x-current"], "ordinary");
                response
                    .send_response(Response::new(Body::empty()))
                    .await
                    .unwrap();
                return;
            }
            panic!("ordinary request was not admitted after local insertion rejection");
        });
        let mut config = Config::default();
        config.encoder.defer_dynamic_first_section = true;
        config.encoder.max_encoder_stream_bytes = 0;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), config, Executor::new()).unwrap();
        spawn(driver.run());
        let mut preferences = HeaderPreferences::default();
        preferences.headers.append(
            "x-current",
            FieldPreferences {
                representation: Representation::LiteralName,
                insertion: Some(InsertionPreferences::default()),
                ..FieldPreferences::default()
            },
        );
        let request = Request::get("https://localhost/")
            .header("x-current", "prefetch")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(preferences);
        let error = client.send_request(request).await.unwrap_err();
        assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
        assert_eq!(error.scope(), ErrorScope::Stream);
        client.ready().await.unwrap();
        let response = client
            .send_request(
                Request::get("https://localhost/")
                    .header("x-current", "ordinary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        response.into_body().collect().await.unwrap();
        serving.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn required_request_insertions_wait_for_late_peer_settings() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let mut config = Config::default();
        config.encoder.defer_dynamic_first_section = true;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), config, Executor::new()).unwrap();
        spawn(driver.run());
        let mut preferences = HeaderPreferences::default();
        preferences.headers.append(
            "x-current",
            FieldPreferences {
                representation: Representation::LiteralName,
                insertion: Some(InsertionPreferences::default()),
                ..FieldPreferences::default()
            },
        );
        let request = Request::get("https://localhost/")
            .header("x-current", "request-owned")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(preferences);
        let sending = client.send_request(request);
        tokio::pin!(sending);
        tokio::time::timeout(Duration::from_secs(1), sending.as_mut())
            .await
            .unwrap_err();
        // The raw server has deliberately sent no HTTP/3 control data yet.
        let mut control = pair.server.open_uni().await.unwrap();
        control
            .write_all(&initial_control(&Config::default(), Role::Server, false).unwrap())
            .await
            .unwrap();
        let answering = async {
            let (send, mut receive) = pair.server.accept_bi().await.unwrap();
            assert!(!receive.read_to_end(4096).await.unwrap().is_empty());
            let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
            let section = encoder
                .encode(u64::from(send.id()), [(":status", "200")])
                .unwrap();
            let mut writer = Writer::new(send);
            writer.queue(FrameType::HEADERS, section).unwrap();
            poll_fn(|cx| writer.poll_finish(cx)).await.unwrap();
            writer
        };
        let (response, mut writer) = tokio::join!(sending, answering);
        response.unwrap().into_body().collect().await.unwrap();
        writer.acknowledged().await.unwrap();
        writer.mark_acknowledged();
        pair.close().await;
    })
    .await
    .unwrap();
}
