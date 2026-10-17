use super::*;
use crate::client::handshake::PreparedClient;

#[tokio::test]
async fn full_offers_retain_tickets_without_reading_the_store() {
    for version in VERSIONS {
        let server = Server::new(version);
        let store = Arc::new(RecordingStore::default());
        let connector = connector(&server, Some(store.clone()))
            .with_base_config(trusting_config().with_client_handshake(ClientHandshake::Full));

        // Full is a per-connection offer, not a fresh/disabled ticket store.
        for _ in 0..2 {
            assert_eq!(
                connect(&connector, &server, "a.test", no_overrides).await,
                FULL
            );
        }
        assert!(store.taken.lock().is_empty());
        assert!(
            !store.put.lock().is_empty(),
            "full offers retain new tickets"
        );

        // A request can override the base policy and use those live tickets.
        assert_eq!(
            connect(&connector, &server, "a.test", |input| {
                input.insert(ClientHandshake::Auto);
            })
            .await,
            RESUMED,
        );
        let taken = store.taken.lock().len();
        assert!(taken > 0);
        let written = store.put.lock().len();
        assert_eq!(
            connect(&connector, &server, "a.test", |input| {
                input.insert(ClientHandshake::Full);
            })
            .await,
            FULL,
        );
        assert_eq!(store.taken.lock().len(), taken);
        assert!(store.put.lock().len() > written);
        assert_eq!(
            connect(&connector, &server, "a.test", |input| {
                input.insert(ClientHandshake::Auto);
            })
            .await,
            RESUMED,
        );
    }
}

#[test]
fn unsupported_required_tcp_offer_does_not_fall_back() {
    let config = trusting_config()
        .with_server_name(Host::from_static("a.test"))
        .with_client_handshake(ClientHandshake::Resumed);
    let data = TlsConnectorData::try_from(&config).unwrap();
    let error = PreparedClient::try_from(data).unwrap_err();
    assert!(error.to_string().contains("required session offers"));
}
