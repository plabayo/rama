use std::{sync::Arc, time::Duration};

use rama_core::rt::{Executor, spawn};
use rama_http_types::{
    Body,
    proto::h3::{SettingId, Settings},
};

use super::{LIMIT, Pair};
use crate::h3::{Error, client, connection::Config, server};

fn config() -> Config {
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
    config.settings_profile = Some(Arc::new(settings));
    config
}

async fn read(
    server_waits: bool,
    client: &client::SendRequest<Body>,
    server: &server::Connection,
) -> Result<Settings, Error> {
    if server_waits {
        server.peer_settings().await
    } else {
        client.peer_settings().await
    }
}

#[tokio::test(start_paused = true)]
async fn peer_settings_snapshot_waits_preserves_order_and_survives_cancelled_waiter() {
    tokio::time::timeout(LIMIT, async {
        for server_waits in [false, true] {
            let pair = Pair::in_memory(None, None).await;
            let config = config();
            assert!(config.observation.is_none());
            let expected = config.settings_profile.as_ref().unwrap().entries().to_vec();
            let (client, client_driver) =
                client::handshake::<Body>(pair.client.clone(), config.clone(), Executor::new())
                    .unwrap();
            let (server, server_driver) = server::handshake(pair.server.clone(), config).unwrap();
            let (local, peer) = if server_waits {
                (server_driver, client_driver)
            } else {
                (client_driver, server_driver)
            };
            spawn(local.run());
            tokio::time::timeout(
                Duration::from_millis(1),
                read(server_waits, &client, &server),
            )
            .await
            .unwrap_err();
            spawn(peer.run());
            let (first, second) = tokio::join!(
                read(server_waits, &client, &server),
                read(server_waits, &client, &server),
            );
            assert_eq!(first.unwrap().entries(), expected);
            assert_eq!(second.unwrap().entries(), expected);
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn peer_settings_snapshot_wakes_on_close_before_settings() {
    tokio::time::timeout(LIMIT, async {
        for server_waits in [false, true] {
            let pair = Pair::in_memory(None, None).await;
            let (client, client_driver) =
                client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                    .unwrap();
            let (server, server_driver) =
                server::handshake(pair.server.clone(), Config::default()).unwrap();
            if server_waits {
                spawn(server_driver.run());
                pair.client.close(0u32, b"no settings");
                drop(client_driver);
            } else {
                spawn(client_driver.run());
                pair.server.close(0u32, b"no settings");
                drop(server_driver);
            }
            read(server_waits, &client, &server).await.unwrap_err();
            pair.close().await;
        }
    })
    .await
    .unwrap();
}
