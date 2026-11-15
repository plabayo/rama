//! One complete captured-browser path through DNS, real ECH and pooled HTTP/2.
use super::*;
use rama::{
    graceful::WeakScope,
    http::{
        Body, Request, Response, Version,
        client::{HttpConnector, HttpPooledConnectorConfig},
    },
    net::tls::TargetEchConfig,
    tls::{boring::client::profile::compiler::ConnectionProfileCompiler, client::TlsDerivedPolicy},
    ua::{
        layer::emulate::ProfileEmulateHttpConnectModifier,
        profile::{
            model::identity::{ConnectionContext, FlowKey},
            selection::{
                DrawKey, ProfileSeed,
                capabilities::CapabilitySet,
                database::UserAgentDatabase,
                variants::{ConnectionSelection, ProfileSelector, SelectionRequest, VariantPins},
            },
        },
    },
};
use std::convert::Infallible;

#[tokio::test]
async fn discovered_ech_survives_browser_compilation_and_pool_reuse() {
    let database = UserAgentDatabase::try_embedded().unwrap();
    let user_agent = database
        .iter_ua_str()
        .filter(|ua| ua.contains("Chrome/"))
        .max()
        .expect("embedded Chrome profile")
        .to_owned();
    let selected = Arc::new(
        database
            .select(
                &SelectionRequest {
                    client: ProfileSelector {
                        user_agent: Some(user_agent.into()),
                        ..Default::default()
                    },
                    required: CapabilitySet {
                        h2: true,
                        tls_tcp: true,
                        ..Default::default()
                    },
                    flow: FlowKey::Http {
                        version: Version::HTTP_2,
                        method: rama::http::Method::GET,
                        initiator: None,
                        fetch: None,
                        connection: ConnectionContext::default(),
                    },
                    pins: VariantPins::default(),
                },
                ProfileSeed([4; 32]),
                DrawKey([5; 32]),
            )
            .unwrap(),
    );
    let context =
        selected.emulation_context(ProfileSeed([4; 32]), DrawKey([6; 32]), DrawKey([7; 32]));
    let (server, ca) = retry_test_server(ORIGIN, 1);
    let dials = Arc::new(AtomicUsize::new(0));
    let transport = rama::service::service_fn({
        let dials = dials.clone();
        move |input: ConnectRequest| {
            dials.fetch_add(1, Ordering::SeqCst);
            assert!(
                input.extensions().contains::<TlsDerivedPolicy>(),
                "the browser TLS recipe must actually be compiled"
            );
            assert!(
                input
                    .extensions()
                    .get_ref::<TargetEchConfig>()
                    .unwrap()
                    .matches_target(&input.connector_target().unwrap())
            );
            let server = server.clone();
            async move {
                let (client, peer) = tokio::io::duplex(65536);
                tokio::spawn(async move {
                    let stream = boring_tokio::accept(&server, peer).await.unwrap();
                    assert!(stream.ssl().ech_accepted());
                    let service = rama::service::service_fn(async |request: Request| {
                        assert_eq!(request.version(), Version::HTTP_2);
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    });
                    drop(
                        rama::http::server::HttpServer::auto(WeakScope::detached())
                            .service(service)
                            .serve(ServiceInput::new(stream))
                            .await,
                    );
                });
                Ok::<_, ConnectionError>(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(client),
                })
            }
        }
    });
    let tls = TlsClientConfig::new()
        .try_with_server_trust_anchors([ca])
        .unwrap();
    let profile_tls = ProfileEmulateHttpConnectModifier::new(
        TlsConnector::secure(transport).with_base_config(tls.clone()),
    )
    .with_connection_compiler(ConnectionProfileCompiler::new(tls.clone()));
    let pooled = HttpPooledConnectorConfig::default().build_connector(
        HttpConnector::<_, Body>::new(profile_tls, WeakScope::detached()),
    );
    let connector = HttpsServiceLayer::new()
        .with_resolver(SlowAlternativeDns)
        .with_ech_capable(true)
        .with_tls(tls)
        .layer(HttpServiceConnector::new(pooled));

    for _ in 0..2 {
        let input = ConnectRequest::new("origin.example:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        context.clone().publish(input.extensions());
        input.extensions().insert(EchRequirement::Required);
        assert!(!input.extensions().contains::<TargetEchConfig>());
        let connection = tokio::time::timeout(Duration::from_secs(5), connector.serve(input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            connection.conn.extensions().get_ref::<TlsEchAccepted>(),
            Some(&TlsEchAccepted(true))
        );
        assert!(
            connection
                .conn
                .extensions()
                .contains::<ConnectionSelection>()
        );
        let response = connection
            .conn
            .serve(
                Request::builder()
                    .version(Version::HTTP_2)
                    .uri("https://origin.example/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
    }
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "the second profile request must reuse the accepted ECH connection"
    );
}
