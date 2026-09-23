#![expect(clippy::unwrap_used, reason = "benchmark fixtures must be valid")]

use rama::{
    Service,
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
    http::{
        HeaderMap, HeaderValue, Version,
        conn::{HttpOrigin, TargetHttpVersion},
        core::h2::server,
        header,
        layer::{alt_svc::AltSvcCache, http_service::HttpServiceConnector},
        proto::h2::alt_svc::AltSvcObserverExtension,
    },
    net::{
        Protocol,
        client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
        tls::ApplicationProtocol,
    },
    service::service_fn,
    tls::{
        ProtocolVersion,
        client::{NegotiatedTlsParameters, TlsServerAuthentication},
    },
};
use std::{hint::black_box, time::Duration};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

fn fixture() -> (AltSvcCache, HttpOrigin, HeaderMap) {
    let origin = HttpOrigin::new(Protocol::HTTPS, "example.com:443".parse().unwrap()).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ALT_SVC,
        HeaderValue::from_static("h2=\":8443\", h3=\":443\""),
    );
    let cache = AltSvcCache::default();
    cache.record(&origin, &headers, Duration::ZERO);
    (cache, origin, headers)
}

#[divan::bench]
fn shared_lookup(b: divan::Bencher) {
    let (cache, origin, _) = fixture();
    b.bench_local(|| black_box(cache.lookup(black_box(&origin))));
}

/// Identical fields still renew receipt order, lifetime and advertisement
/// identity. Keep this cost visible: skipping replacement breaks stale-421
/// isolation and header-versus-frame ordering.
#[divan::bench]
fn replacement(b: divan::Bencher) {
    let (cache, origin, headers) = fixture();
    b.bench_local(|| cache.record(black_box(&origin), black_box(&headers), Duration::ZERO));
}

#[derive(Clone, Debug)]
struct Connection(Extensions);

impl ExtensionsRef for Connection {
    fn extensions(&self) -> &Extensions {
        &self.0
    }
}

/// Repeatedly select the same pooled connection. The allocation profiler catches
/// retained metadata allocations that would otherwise grow with every request.
#[divan::bench(args = [false, true])]
fn pooled_selection(b: divan::Bencher, discovery: bool) {
    let (cache, origin, _) = fixture();
    let extensions = Extensions::new();
    extensions.insert(TargetHttpVersion(Version::HTTP_2));
    extensions.insert(TlsServerAuthentication(Some(
        origin.authority().host.clone(),
    )));
    extensions.insert(NegotiatedTlsParameters {
        protocol_version: ProtocolVersion::TLSv1_3,
        application_layer_protocol: Some(ApplicationProtocol::HTTP_2),
        peer_certificate_chain: None,
        server_name: None,
        resumed: None,
    });
    let connection = Connection(extensions);
    let connector = HttpServiceConnector::new(service_fn(move |input: ConnectRequest| {
        let conn = connection.clone();
        // Model the H2 driver's ownership of the connection-level observer.
        if !conn.extensions().contains::<AltSvcObserverExtension>()
            && let Some(observer) = input.extensions().get_arc::<AltSvcObserverExtension>()
        {
            conn.extensions().insert_arc(observer);
        }
        async move { Ok::<_, ConnectionError>(EstablishedClientConnection { conn, input }) }
    }))
    .maybe_with_cache(discovery.then_some(cache))
    .with_protocols([ApplicationProtocol::HTTP_2]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let input = || {
        ConnectRequest::new(origin.authority().clone()).with_application_protocol(Protocol::HTTPS)
    };
    runtime.block_on(connector.serve(input())).unwrap();
    b.with_inputs(input)
        .bench_local_values(|input| black_box(runtime.block_on(connector.serve(input)).unwrap()));
}

/// Compare ordinary H2 setup with explicitly enabled advertisement emission.
/// The enabled case includes the queue that used to be allocated unconditionally.
#[divan::bench(args = [false, true])]
fn h2_server_setup(b: divan::Bencher, emission: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    b.bench_local(|| {
        runtime.block_on(async {
            let (io, mut peer) = h2_support::mock::new();
            let server = async move {
                let mut connection = server::Builder::new()
                    .with_alt_svc(emission)
                    .handshake::<_, Bytes>(io)
                    .await
                    .unwrap();
                assert!(connection.accept().await.is_none());
            };
            let peer = async move {
                peer.assert_server_handshake().await;
            };
            tokio::join!(server, peer);
        });
    });
}
