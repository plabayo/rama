use crate::{
    cmd::serve::proxy::capture::{CaptureHttpLayer, ConnectionId, test_store},
    utils::{
        http::HttpVersions,
        http3::{Http3Args, HttpListeners, OBSERVATION_LIMITS},
    },
};
use rama::{
    Layer, Service,
    http::{
        Request, Version,
        body::util::BodyExt as _,
        client::{EasyHttpWebClient, Http3Connector},
        conn::TargetHttpVersion,
        server::HttpServer,
    },
    net::{Protocol, address::SocketAddress},
    quic::{Endpoint, tls::BoringTlsProvider},
    rt::Executor,
    service::service_fn,
    tls::{
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
    ua::profile::{
        evidence::ProfileEvidence,
        format::{archive::load_profile_archive_snapshot, canonical::CanonicalDomain},
        model::identity::ProfileKey,
        selection::database::UserAgentDatabase,
    },
};
use std::{convert::Infallible, time::Duration};
use tokio::{io::AsyncReadExt as _, sync::Semaphore};

use super::*;

fn entry() -> ProfileArchiveEntry {
    ProfileArchiveEntry {
        evidence: ProfileEvidence {
            format_version: 1,
            profile: ProfileKey::new(format!("synthetic-download-{}", "x".repeat(kib(8))))
                .canonical(kib(16))
                .unwrap(),
            scopes: Box::default(),
        },
        sampler_seed: [3; 32],
    }
}

async fn staged(limit: Arc<Semaphore>) -> StagedProfiles {
    tokio::task::spawn_blocking(move || {
        StagedProfiles::create(
            Some(limit.try_acquire_owned().unwrap()),
            100,
            14,
            ProfileArchiveLimits::default(),
        )
        .unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn profile_download_streams_valid_json_and_retains_admission_until_drop() {
    let limit = Arc::new(Semaphore::new(1));
    let staged = staged(limit.clone()).await;
    let path = staged.staging.path().to_owned();
    let entry = entry();
    let expected =
        ProfileArchiveWriter::new(Vec::new(), false, 100, 14, ProfileArchiveLimits::default())
            .unwrap()
            .write_profile(entry.clone())
            .unwrap()
            .finish()
            .unwrap();
    assert!(expected.len() > kib(16));
    let mut download =
        tokio::task::spawn_blocking(move || staged.write(entry).unwrap().finish().unwrap())
            .await
            .unwrap();
    assert_eq!(download.length, expected.len() as u64);
    assert_eq!(limit.available_permits(), 0);
    assert!(path.exists());
    let mut bytes = Vec::new();
    download.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(
        UserAgentDatabase::try_from_json_slice(&bytes)
            .unwrap()
            .len(),
        1
    );
    drop(download);
    assert!(!path.exists());
    assert_eq!(limit.available_permits(), 1);
}

#[tokio::test]
async fn invalid_profiles_remove_staged_output_and_release_admission() {
    let limit = Arc::new(Semaphore::new(1));
    let staged = staged(limit.clone()).await;
    let path = staged.staging.path().to_owned();
    let mut entry = entry();
    entry.evidence.profile.id.0[0] ^= 1;
    let error = tokio::task::spawn_blocking(move || staged.write(entry).err().unwrap())
        .await
        .unwrap();
    assert_eq!(
        error.downcast_ref::<IoError>().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    assert!(!path.exists());
    assert_eq!(limit.available_permits(), 1);
}

#[tokio::test]
#[ignore = "requires local UDP integration"]
async fn real_h3_inspector_export_preserves_connection_and_request_evidence() {
    let capture = test_store(1, 3, 0, Arc::new(UserAgentDatabase::default())).unwrap();
    let id = capture
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    let service = CaptureHttpLayer::new(Some(capture.clone())).into_layer(service_fn(
        async |request: Request| {
            assert_eq!(request.version(), Version::HTTP_3);
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap();
    let listeners = HttpListeners::bind_observed(
        Executor::default(),
        SocketAddress::local_ipv4(0),
        "h3".parse::<HttpVersions>().unwrap(),
        Some(&tls),
        &Http3Args {
            h3_bind: None,
            h3_mtu_upper_bound: None,
        },
    )
    .await
    .unwrap();
    assert!(listeners.tcp.is_none());
    let endpoint = listeners.http3.unwrap();
    let address = endpoint.local_addr().unwrap();
    let mut http = HttpServer::new_http3(Executor::default());
    http.http3_mut().observation = Some(Box::new(OBSERVATION_LIMITS));
    let service = http.service(Arc::new(service));
    let server = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            connection.extensions().insert(ConnectionId(id));
            service.serve(connection).await
        }
    });
    let client_endpoint = Endpoint::bind_client(Executor::default(), SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let h3 = Http3Connector::builder(Executor::default())
        .with_endpoint(client_endpoint.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build()
        .await
        .unwrap();
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(Executor::default())
        .with_http3_support(h3)
        .with_default_connection_pool()
        .build_client();
    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..3 {
            let request = Request::builder()
                .uri(format!("https://{address}/report"))
                .version(Version::HTTP_3)
                .header("user-agent", "synthetic-inspector/1")
                .header("accept", "text/html")
                .header("cookie", "excluded-wire-cookie")
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            let response = client.serve(request).await.unwrap();
            assert_eq!(response.version(), Version::HTTP_3);
            response.into_body().collect().await.unwrap();
        }
    })
    .await
    .unwrap();
    drop(client);
    client_endpoint.close(0_u32, b"test complete");
    endpoint.close(0_u32, b"test complete");
    tokio::time::timeout(Duration::from_secs(10), async {
        client_endpoint.shutdown().await;
        endpoint.shutdown().await;
        let _closed = server.await.unwrap();
    })
    .await
    .unwrap();
    let mut archive = download(&capture, &BTreeSet::new(), &BTreeSet::from([id]), None)
        .await
        .unwrap();
    let mut bytes = Vec::new();
    archive.read_to_end(&mut bytes).await.unwrap();
    assert!(
        !bytes
            .windows(b"excluded-wire-cookie".len())
            .any(|part| part == b"excluded-wire-cookie")
    );
    let profiles =
        load_profile_archive_snapshot(&bytes, false, ProfileArchiveLimits::default()).unwrap();
    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0].analysis;
    assert!(profile.components.h3.is_some());
    assert!(profile.components.h1.is_none());
    assert!(profile.components.h2.is_none());
    assert!(profile.components.quic.is_some());
    let joint: Vec<_> = profile
        .scopes
        .iter()
        .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
        .collect();
    assert_eq!(joint.len(), 2);
    assert_eq!(
        joint
            .iter()
            .filter(|scope| scope.flow.is_none())
            .map(|scope| scope.observations.counts.total)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        joint
            .iter()
            .filter(|scope| scope.flow.is_some())
            .map(|scope| scope.observations.counts.total)
            .sum::<u64>(),
        3
    );
}
