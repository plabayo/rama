use crate::profile::{
    analysis::profile::ProfileAnalysisLimits,
    format::{
        archive::{ProfileArchiveLimits, ProfileArchiveWriter, load_profile_archive_snapshot},
        canonical::CanonicalDomain,
    },
    model::time::profile_utc_day,
};
use rama_core::{Layer, Service, service::service_fn};
use rama_http::{
    Body, Request, Response, Version,
    body::util::BodyExt,
    inspect::capture::{CaptureConfig, CaptureHttpLayer, CaptureObserver, ConnectionId},
};
use rama_inspect::storage::{MemoryStore, Storage, StorageLimits};
use rama_net::Protocol;
#[cfg(feature = "tls")]
use rama_tls::{
    CipherSuite, CompressionAlgorithm, ProtocolVersion, SecureTransport,
    client::{ClientHello, ClientHelloExtension, NegotiatedTlsParameters},
};
use std::{
    convert::Infallible,
    time::{Duration, SystemTime},
};

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

pub(super) fn store(database: UserAgentDatabase) -> CaptureStore {
    CaptureStore::with_storage(
        Storage::new(MemoryStore::new(StorageLimits::default())),
        CaptureConfig {
            observer: Arc::new(Observer(ProfileInspector::new(Arc::new(database)))),
            ..CaptureConfig::default()
        },
        Default::default(),
    )
}

/// A database whose only profile carries a compiled TCP TLS component.
#[cfg(feature = "tls")]
fn tls_profile_database(ua: &str) -> (UserAgentDatabase, ClientHello) {
    let hello = ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![CipherSuite::from(0x1301), CipherSuite::from(0xc02b)],
        vec![CompressionAlgorithm::from(0)],
        vec![ClientHelloExtension::SupportedVersions(vec![
            ProtocolVersion::TLSv1_3,
        ])],
    );
    let mut row = UserAgentProfileInput::new(ua);
    row.tls_client_hello = Some(hello.clone());
    (
        [row.try_into_profile().unwrap()].into_iter().collect(),
        hello,
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
fn speculative_navigation_is_not_the_navigation_profile() {
    let navigation = |purpose: Option<&str>| {
        let mut request = Request::builder()
            .uri("https://example.test/")
            .header("sec-fetch-site", "same-origin")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document");
        if let Some(purpose) = purpose {
            request = request.header("sec-purpose", purpose);
        }
        request.body(()).unwrap().into_parts().0
    };
    assert_eq!(
        captured_request_initiator(&navigation(None), false),
        Some(RequestInitiator::Navigate)
    );
    for purpose in [
        "prefetch",
        "prefetch;prerender",
        "prefetch;anonymous-client-ip",
    ] {
        let parts = navigation(Some(purpose));
        assert_eq!(captured_request_initiator(&parts, false), None, "{purpose}");
        let mut profile = UserAgentProfileInput::new("browser/1");
        fill_profile(&mut profile, parts, None, None);
        assert!(profile.h1_headers_navigate.is_none(), "{purpose}");
    }
    // An invalid value is no speculation signal.
    assert_eq!(
        captured_request_initiator(&navigation(Some("\"prefetch\"")), false),
        Some(RequestInitiator::Navigate)
    );
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
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
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

#[cfg(feature = "tls")]
#[tokio::test]
async fn captured_tls_and_native_fingerprints_are_shared_per_connection() {
    const UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
    let (database, hello) = tls_profile_database(UA);
    let store = store(database);
    let connection = store
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
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
                        server_name: None,
                        resumed: None,
                        algorithms: Default::default(),
                        server_hello: None,
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
    let day = profile_utc_day(
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(second.summary.started_at.as_second().try_into().unwrap()),
    )
    .unwrap();
    let mut export = ProfileExport::new(&store, &[1, 2].into(), &BTreeSet::new());
    let compiled = export
        .next_evidence(day, 14, [3; 32], ProfileAnalysisLimits::default())
        .await
        .unwrap()
        .unwrap()
        .analyze(false, day, 14, ProfileAnalysisLimits::default())
        .unwrap();
    let connections: u64 = compiled
        .analysis
        .scopes
        .iter()
        .filter(|scope| scope.flow.is_none() && scope.observations.domain == CanonicalDomain::Joint)
        .map(|scope| scope.observations.counts.total)
        .sum();
    assert_eq!(connections, 1);
    let requests: u64 = compiled
        .analysis
        .scopes
        .iter()
        .filter(|scope| scope.flow.is_some() && scope.observations.domain == CanonicalDomain::Joint)
        .map(|scope| scope.observations.counts.total)
        .sum();
    assert_eq!(requests, 2);
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
            Ok::<_, Infallible>(Response::new(Body::empty()))
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

#[test]
fn h3_observation_never_populates_tcp_protocol_slots() {
    for initiator in [
        RequestInitiator::Navigate,
        RequestInitiator::Fetch,
        RequestInitiator::Xhr,
        RequestInitiator::Form,
        RequestInitiator::Ws,
    ] {
        let (parts, ()) = Request::builder()
            .version(Version::HTTP_3)
            .header("user-agent", "custom/1")
            .header("accept", "text/html")
            .body(())
            .unwrap()
            .into_parts();
        let mut profile = UserAgentProfileInput::new("custom/1");
        fill_profile(&mut profile, parts, Some(initiator), None);
        assert!(profile.h1_settings.is_none());
        assert!(profile.h1_headers_navigate.is_none());
        assert!(profile.h1_headers_fetch.is_none());
        assert!(profile.h1_headers_xhr.is_none());
        assert!(profile.h1_headers_form.is_none());
        assert!(profile.h1_headers_ws.is_none());
        assert!(profile.h2_settings.is_none());
        assert!(profile.h2_headers_navigate.is_none());
    }
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn h3_observation_export_keeps_tcp_tls_and_headers_empty() {
    let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
    let (database, hello) = tls_profile_database(ua);
    let store = store(database);
    let connection = store
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
    service
        .serve(
            Request::builder()
                .uri("https://example.test/")
                .version(Version::HTTP_3)
                .header("user-agent", ua)
                .header("sec-fetch-mode", "navigate")
                .extension(ConnectionId(connection))
                .extension(SecureTransport::with_client_hello(hello))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let profiles = export_profiles(&store, &[1].into(), &BTreeSet::new())
        .await
        .unwrap();
    assert_eq!(profiles.len(), 1);
    assert!(profiles[0].tls_client_hello.is_none());
    assert!(profiles[0].h1_headers_navigate.is_none());
    assert!(profiles[0].h2_headers_navigate.is_none());
}

#[tokio::test]
async fn selected_evidence_counts_each_request_and_keeps_retry_atomic() {
    let store = store(UserAgentDatabase::default());
    let connection = store
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
    for value in ["application/json", "text/plain", "application/json"] {
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/")
                    .header("user-agent", "counted-library/1")
                    .header("accept", value)
                    .header("cookie", "never-export-private-cookie")
                    .extension(ConnectionId(connection))
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
    let last = store.exchange_capture(3).unwrap().snapshot();
    let day = profile_utc_day(
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(last.started_at.as_second().try_into().unwrap()),
    )
    .unwrap();
    let mut export = ProfileExport::new(&store, &[1, 2, 3].into(), &BTreeSet::new());
    let limits = ProfileAnalysisLimits::default();
    export
        .next_evidence(day - 1, 14, [3; 32], limits)
        .await
        .unwrap_err();
    let entry = export
        .next_evidence(day, 14, [3; 32], limits)
        .await
        .unwrap()
        .unwrap();
    let analysis = entry
        .clone()
        .analyze(false, day, 14, limits)
        .unwrap()
        .analysis;
    let total: u64 = analysis
        .scopes
        .iter()
        .filter(|scope| scope.flow.is_some() && scope.observations.domain == CanonicalDomain::Joint)
        .map(|scope| scope.observations.counts.total)
        .sum();
    assert_eq!(total, 3);
    assert!(analysis.scopes.iter().all(|scope| scope.flow.is_some()));
    let archive =
        ProfileArchiveWriter::new(Vec::new(), false, day, 14, ProfileArchiveLimits::default())
            .unwrap()
            .write_profile(entry)
            .unwrap()
            .finish()
            .unwrap();
    assert!(
        !archive
            .windows(b"never-export-private-cookie".len())
            .any(|bytes| bytes == b"never-export-private-cookie")
    );
    assert_eq!(
        load_profile_archive_snapshot(&archive, false, ProfileArchiveLimits::default())
            .unwrap()
            .len(),
        1
    );
    assert!(
        export
            .next_evidence(day, 14, [3; 32], limits)
            .await
            .unwrap()
            .is_none()
    );
    let mut expired = ProfileExport::new(&store, &[1, 2, 3].into(), &BTreeSet::new());
    assert!(
        expired
            .next_evidence(day + 14, 14, [3; 32], limits)
            .await
            .unwrap()
            .is_none()
    );
}
