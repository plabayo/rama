//! Early requests through the HTTP/3 connector survive rejected early data.

use super::*;
use crate::client::HttpConnector;
use rama_core::{
    Service as _,
    bytes::Bytes,
    extensions::ExtensionsRef as _,
    rt::{Executor, spawn},
    telemetry::tracing::{
        Event, Metadata, Subscriber,
        field::{Field, Visit},
        span::{Attributes, Id, Record},
        subscriber,
    },
};
use rama_http_core::h3::{connection::Config, server as h3_server};
use rama_http_types::{Body, Method, Request, Response, body::util::BodyExt as _};
use rama_net::{Protocol, address::HostWithPort, client::ConnectorTarget};
use rama_quic::{ServerConfig, tls::TlsOptions};
use rama_tls::server::{LeafCertRequest, ServerAuthData, TlsServerConfig};
use std::{
    fmt,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::time::timeout;

const FALLBACK_TRACE: &str = "HTTP/3 early data rejected: resend on a new connection";

#[tokio::test]
async fn rejected_early_data_resends_the_request_on_a_new_connection() {
    let traces = Arc::new(Traces::default());
    let _subscriber = subscriber::set_default(traces.clone());
    timeout(Duration::from_secs(15), async {
        let identity = ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
        let server_tls = TlsServerConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .with_server_auth(identity.clone());
        let server_config = || {
            ServerConfig::try_from_rama_tls(
                &server_tls,
                TlsOptions::default().with_early_data(true),
            )
            .unwrap()
        };
        let server = Endpoint::bind_server(
            Executor::new(),
            server_config(),
            SocketAddress::local_ipv4(0),
        )
        .await
        .unwrap();
        let port = server.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let serving = spawn(serve(server.clone(), connections.clone()));

        let tls = TlsClientConfig::new()
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let quic = Http3Connector::builder(Executor::new())
            .with_tls_config(tls)
            .with_config(Config {
                early_requests: true,
                ..Config::default()
            })
            .build_lazy()
            .unwrap();
        let connector = HttpConnector::<_, Body>::new(quic, Executor::new());

        // A full handshake leaves the client a ticket for early data.
        let (_, body) = send(&connector, port, Method::GET, "").await;
        assert_eq!(body, "GET ");
        assert_eq!(connections.load(Ordering::Acquire), 1);

        // Fresh server ticket keys reject the early data the next attempt offers.
        server.set_server_config(Some(server_config()));
        let (service, body) = send(&connector, port, Method::GET, "").await;
        assert_eq!(body, "GET ");
        let early = service.quic_connection().unwrap();
        assert!(early.early_data_keys_enabled());
        assert_eq!(early.early_data_accepted(), Some(false));
        assert_eq!(connections.load(Ordering::Acquire), 3);
        assert_eq!(traces.matching.load(Ordering::Acquire), 1);

        // A request that waited for the decision moves to the new connection unchanged.
        server.set_server_config(Some(server_config()));
        let (service, body) = send(&connector, port, Method::POST, "payload").await;
        assert_eq!(body, "POST payload");
        assert_eq!(
            service.quic_connection().unwrap().early_data_accepted(),
            Some(false)
        );
        assert_eq!(connections.load(Ordering::Acquire), 5);
        assert_eq!(traces.matching.load(Ordering::Acquire), 2);

        serving.abort();
        server.close(0u32, b"fixture complete");
    })
    .await
    .unwrap();
}

async fn send(
    connector: &HttpConnector<Http3Connector, Body>,
    port: u16,
    method: Method,
    body: &'static str,
) -> (HttpClientService<Body>, Bytes) {
    let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(port))
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(ConnectorTarget(HostWithPort::local_ipv4(port)));
    let service = connector.serve(input).await.unwrap().conn;
    let request = Request::builder()
        .method(method)
        .uri(format!("https://localhost:{port}/"))
        .version(Version::HTTP_3)
        .body(Body::from(body))
        .unwrap();
    let response = service.serve(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (service, body)
}

async fn serve(server: Endpoint, connections: Arc<AtomicUsize>) {
    while let Some(incoming) = server.accept().await {
        let Ok(Ok((connection, _))) = incoming.accept().map(|connecting| connecting.into_0rtt())
        else {
            continue;
        };
        connections.fetch_add(1, Ordering::AcqRel);
        spawn(async move {
            let Ok((mut h3, driver)) = h3_server::handshake(connection, Config::default()) else {
                return;
            };
            spawn(driver.run());
            while let Ok(stream) = h3.accept().await {
                let Ok((request, response)) = stream.resolve().await else {
                    continue;
                };
                let method = request.method().clone();
                let Ok(body) = request.into_body().collect().await else {
                    continue;
                };
                let echo = format!("{method} {}", String::from_utf8_lossy(&body.to_bytes()));
                _ = response
                    .send_response(Response::new(Body::from(echo)))
                    .await;
            }
        });
    }
}

/// Counts the connector's fallback traces, emitted on the test's own thread.
#[derive(Default)]
struct Traces {
    matching: AtomicUsize,
}

struct Message(bool);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" && format!("{value:?}") == FALLBACK_TRACE {
            self.0 = true;
        }
    }
}

impl Subscriber for Traces {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut message = Message(false);
        event.record(&mut message);
        if message.0 {
            self.matching.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}
