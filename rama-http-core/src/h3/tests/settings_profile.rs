use super::{LIMIT, Pair};
use crate::h3::{
    client,
    connection::Config,
    observation::{H3Observer, SettingsObservation},
    server,
};
use rama_core::{
    extensions::ExtensionsRef as _,
    rt::{Executor, spawn},
};
use rama_http_types::{
    Body, Request, Response,
    proto::h3::{Code, SettingId, Settings},
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

#[tokio::test(start_paused = true)]
async fn settings_profile_reaches_peer_in_literal_order() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let mut config = Config::default();
        let mut settings = Settings::new();
        for (id, value) in [
            (SettingId::FIRST_RESERVED, 17),
            (
                SettingId::QPACK_BLOCKED_STREAMS,
                config.decoder.max_blocked_streams,
            ),
            (SettingId::new(0xface), 29),
            (SettingId::H3_DATAGRAM, 1),
            (
                SettingId::QPACK_MAX_TABLE_CAPACITY,
                config.decoder.max_table_capacity,
            ),
        ] {
            settings.set(id, value).unwrap();
        }
        let expected: Vec<_> = settings
            .entries()
            .iter()
            .map(|entry| (entry.id.value(), entry.value))
            .collect();
        config.settings_profile = Some(Arc::new(settings));
        let (mut server, driver) = server::handshake(
            pair.server.clone(),
            Config {
                observation: Some(Default::default()),
                ..Config::default()
            },
        )
        .unwrap();
        spawn(driver.run());
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), config, Executor::new()).unwrap();
        spawn(driver.run());

        let serve = spawn(async move {
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            let observer = request
                .extensions()
                .get_ref::<H3Observer>()
                .unwrap()
                .clone();
            let SettingsObservation::Received(observed) = observer
                .settings(Instant::now() + Duration::from_secs(1))
                .await
            else {
                panic!("profile SETTINGS were not received");
            };
            let actual: Vec<_> = observed
                .settings
                .as_ref()
                .unwrap()
                .iter()
                .map(|entry| (entry.id, entry.value))
                .collect();
            assert_eq!(actual, expected);
            response
                .send_response(Response::new(Body::empty()))
                .await
                .unwrap();
        });
        client
            .send_request(
                Request::builder()
                    .uri("https://localhost/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        serve.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn settings_profile_capability_mismatch_fails_before_h3_handshake() {
    let pair = Pair::in_memory(None, None).await;
    let mut settings = Settings::new();
    let mut config = Config::default();
    settings
        .set(
            SettingId::QPACK_MAX_TABLE_CAPACITY,
            config.decoder.max_table_capacity,
        )
        .unwrap();
    settings
        .set(
            SettingId::QPACK_BLOCKED_STREAMS,
            config.decoder.max_blocked_streams,
        )
        .unwrap();
    // QUIC DATAGRAM is available and enabled locally, but the profile omits it.
    config.settings_profile = Some(Arc::new(settings));
    let Err(error) = client::handshake::<Body>(pair.client.clone(), config, Executor::new()) else {
        panic!("incompatible profile returned a sender");
    };
    assert_eq!(error.code(), Code::H3_INTERNAL_ERROR);
    pair.close().await;
}
