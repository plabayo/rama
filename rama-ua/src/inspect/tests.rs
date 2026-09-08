use rama_core::{Layer, Service, service::service_fn};
use rama_http::{
    Body, Request, Response, Version,
    body::util::BodyExt,
    inspect::capture::{CaptureConfig, CaptureHttpLayer, CaptureObserver, ConnectionId},
};
use rama_inspect::storage::{MemoryStore, Storage, StorageLimits};
#[cfg(all(feature = "embed-profiles", feature = "tls"))]
use rama_tls::{ProtocolVersion, SecureTransport, client::NegotiatedTlsParameters};

use super::*;

#[derive(Debug)]
struct Observer(ProfileInspector);

impl CaptureObserver for Observer {
    fn request(&self, parts: &rama_http::request::Parts, metadata: &CaptureMetadata) {
        #[cfg(feature = "tls")]
        TlsObservation::capture(&parts.extensions, &metadata.connection);
        self.0.observe(parts, metadata);
    }

    fn response(&self, parts: &rama_http::response::Parts, metadata: &CaptureMetadata) {
        #[cfg(feature = "tls")]
        TlsObservation::capture(&parts.extensions, &metadata.upstream);
        #[cfg(not(feature = "tls"))]
        let _ = (parts, metadata);
    }
}

fn store(database: UserAgentDatabase) -> CaptureStore {
    CaptureStore::with_storage(
        Storage::new(MemoryStore::new(StorageLimits::default())),
        CaptureConfig {
            observer: Arc::new(Observer(ProfileInspector::new(Arc::new(database)))),
            ..CaptureConfig::default()
        },
        Default::default(),
    )
}

#[test]
fn profile_export_does_not_guess_an_unobserved_request_initiator() {
    let (parts, _) = Request::builder()
        .uri("http://example.test/data")
        .header("user-agent", "curl/8.7.1")
        .body(())
        .unwrap()
        .into_parts();
    let initiator = captured_request_initiator(&parts, false);
    let mut profile = UserAgentProfileInput::new("curl/8.7.1");
    fill_profile(&mut profile, parts, initiator, None);
    assert!(profile.h1_settings.is_some());
    assert!(profile.h1_headers_navigate.is_none());
    assert!(profile.h1_headers_fetch.is_none());
    assert!(profile.h1_headers_xhr.is_none());
    assert!(profile.h1_headers_form.is_none());
    assert!(profile.h2_settings.is_none());
}

#[test]
fn h2_upgrade_initiator_belongs_to_the_supplied_protocol_observation() {
    let (parts, _) = Request::builder()
        .uri("https://example.test/socket")
        .method("CONNECT")
        .version(Version::HTTP_2)
        .header("user-agent", "custom/1")
        .extension(RequestInitiator::Ws)
        .body(())
        .unwrap()
        .into_parts();
    let metadata = CaptureMetadata::default();
    ProfileInspector::new(Arc::new(UserAgentDatabase::default())).observe(&parts, &metadata);
    let observed = metadata.exchange.get_ref::<UserAgentObservation>().unwrap();
    assert_eq!(observed.request_initiator, Some(RequestInitiator::Ws));
    assert!(observed.h2_settings.is_some());
}

#[tokio::test]
async fn exports_merge_only_observed_fields_and_respect_selected_connections() {
    let store = store(UserAgentDatabase::default());
    let connection = store
        .begin_connection_if_enabled(None, rama_net::Protocol::HTTP, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
        }));
    for (version, ua) in [
        (Version::HTTP_11, Some("custom/1")),
        (Version::HTTP_2, Some("custom/1")),
        (Version::HTTP_11, None),
    ] {
        let mut request = Request::builder()
            .uri("http://example.test/")
            .version(version)
            .extension(ConnectionId(connection))
            .header("sec-fetch-mode", "navigate");
        if let Some(ua) = ua {
            request = request.header("user-agent", ua);
        }
        service
            .serve(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let first = export_profiles(&store, &[1, 3, 999].into(), &BTreeSet::new())
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert!(first[0].h1_headers_navigate.is_some());
    assert!(first[0].h2_settings.is_none());
    let combined = export_profiles(&store, &[1].into(), &[connection].into())
        .await
        .unwrap();
    assert_eq!(combined.len(), 1);
    assert_eq!(combined[0].uastr, "custom/1");
    assert!(combined[0].h1_headers_navigate.is_some());
    assert!(combined[0].h2_headers_navigate.is_some());
    #[cfg(feature = "tls")]
    assert!(combined[0].tls_client_hello.is_none());
    let json = serde_json::to_value(&combined[0]).unwrap();
    assert!(json.get("connection_id").is_none());
    assert!(json.get("fingerprints").is_none());
}

#[cfg(all(feature = "embed-profiles", feature = "tls"))]
#[tokio::test]
async fn captured_tls_and_native_fingerprints_are_shared_per_connection() {
    const UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
    let database = UserAgentDatabase::try_embedded().unwrap();
    let hello = database
        .get_exact_header_str(UA)
        .unwrap()
        .tls
        .client_hello
        .clone();
    let store = store(database);
    let connection = store
        .begin_connection_if_enabled(None, rama_net::Protocol::HTTPS, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
        }));
    for _ in 0..2 {
        service
            .serve(
                Request::builder()
                    .uri("https://example.test/")
                    .header("user-agent", UA)
                    .header("sec-fetch-mode", "navigate")
                    .extension(ConnectionId(connection))
                    .extension(SecureTransport::with_client_hello(hello.clone()))
                    .extension(NegotiatedTlsParameters {
                        protocol_version: ProtocolVersion::TLSv1_3,
                        application_layer_protocol: Some(
                            rama_net::tls::ApplicationProtocol::HTTP_2,
                        ),
                        peer_certificate_chain: None,
                    })
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let first = store.details(1).await.unwrap();
    let second = store.details(2).await.unwrap();
    let tls = first
        .metadata
        .connection
        .get_ref::<TlsObservation>()
        .unwrap();
    assert!(std::ptr::eq(
        tls,
        second.metadata.connection.get_ref().unwrap()
    ));
    assert!(tls.ja3.is_some() && tls.ja4.is_some() && tls.peetprint.is_some());
    assert!(first.summary.ja4h.is_some());
    let observed = first
        .metadata
        .exchange
        .get_ref::<UserAgentObservation>()
        .unwrap();
    assert!(observed.known_fingerprint.is_some());
    let profiles = export_profiles(&store, &[1, 2].into(), &BTreeSet::new())
        .await
        .unwrap();
    let profile = &profiles[0];
    assert!(profile.tls_client_hello.is_some());
    assert!(profile.h1_headers_navigate.is_some());
    assert!(profile.h2_settings.is_none());
    let fingerprint = first
        .metadata
        .request_fingerprint(&Request::new(()).into_parts().0)
        .unwrap();
    assert!(Arc::ptr_eq(
        first.summary.ja4h.as_ref().unwrap(),
        &fingerprint
    ));
    let json = serde_json::to_value(&first.summary).unwrap();
    assert!(json.get("ja3").is_none());
    assert!(json.get("ingress_tls").is_none());
}

#[tokio::test]
async fn profile_cursor_pins_groups_and_keeps_the_first_observed_headers() {
    let store = store(UserAgentDatabase::default());
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
        }));
    for (ua, choice) in [
        ("z-agent", "first"),
        ("a-agent", "first"),
        ("z-agent", "later"),
    ] {
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/")
                    .header("user-agent", ua)
                    .header("sec-fetch-mode", "navigate")
                    .header("x-choice", choice)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let mut export = ProfileExport::new(&store, &[1, 2, 3].into(), &BTreeSet::new());
    store.clear().await;
    for ua in ["a-agent", "z-agent"] {
        let profile = export.next_profile().await.unwrap().unwrap();
        assert_eq!(profile.uastr, ua);
        assert_eq!(profile.h1_headers_navigate.unwrap()["x-choice"], "first");
    }
    assert!(export.next_profile().await.unwrap().is_none());
}
