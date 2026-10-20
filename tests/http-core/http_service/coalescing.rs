//! Opt-in HTTP/3 coalescing of configured origins onto one verified connection.

use super::{Reply, Server, TEST_TIMEOUT, client_with_http3, close_client_endpoint};
use rama::{
    Service,
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::h3::Http3Coalescing,
        conn::{HttpOrigin, HttpServiceCandidate, HttpServiceCandidates},
    },
    net::{
        Protocol,
        address::{Domain, HostWithPort},
        tls::ApplicationProtocol,
    },
    tls::{
        client::TlsClientConfig,
        server::{CertificateIdentity, LeafCertRequest, ServerAuthData},
    },
};
use std::{
    fmt::Debug,
    sync::{Arc, atomic::Ordering},
};
use tokio::time::timeout;

const A: &str = "a.example";
const B: &str = "b.example";

struct Fixture {
    server: Server,
    tls: TlsClientConfig,
    group: Arc<Http3Coalescing>,
}

impl Fixture {
    async fn start(names: &[&'static str]) -> Self {
        let auth = ServerAuthData::new_self_signed_leaf(LeafCertRequest {
            identities: names
                .iter()
                .map(|name| CertificateIdentity::Dns(Domain::from_static(name)))
                .collect(),
            ..LeafCertRequest::default()
        })
        .unwrap();
        let tls = TlsClientConfig::default_http()
            .try_with_server_trust_anchors(auth.cert_chain.clone())
            .unwrap();
        let server = Server::start(auth, Version::HTTP_3).await;
        let group =
            Arc::new(Http3Coalescing::try_new([A, B].map(|name| origin(&server, name))).unwrap());
        Self { server, tls, group }
    }

    // Each origin is configured at the same literal endpoint; its own name never resolves.
    fn request(&self, name: &'static str, coalesce: bool) -> Request {
        let origin = origin(&self.server, name);
        let request = Request::builder()
            .version(Version::HTTP_3)
            .uri(format!("https://{}/", origin.authority()))
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(HttpServiceCandidates::new(
            origin,
            vec![HttpServiceCandidate::new(
                ApplicationProtocol::HTTP_3,
                self.server.address.into(),
            )],
        ));
        if coalesce {
            request.extensions().insert_arc(self.group.clone());
        }
        request
    }
}

fn origin(server: &Server, name: &'static str) -> HttpOrigin {
    HttpOrigin::new(
        Protocol::HTTPS,
        HostWithPort::new(Domain::from_static(name).into(), server.address.port()),
    )
    .unwrap()
}

async fn send<S: Service<Request, Output = Response, Error: Debug>>(
    client: &S,
    request: Request,
) -> Result<StatusCode, S::Error> {
    let response = timeout(TEST_TIMEOUT, client.serve(request))
        .await
        .unwrap()?;
    let status = response.status();
    timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap();
    Ok(status)
}

fn authorities(server: &Server) -> Vec<String> {
    server
        .observations
        .lock()
        .iter()
        .map(|observation| observation.authority.clone())
        .collect()
}

#[tokio::test]
async fn verified_origins_share_one_connection_only_when_opted_in() {
    for coalesce in [true, false] {
        let fixture = Fixture::start(&[A, B]).await;
        let (client, endpoint) = client_with_http3(fixture.tls.clone()).await;
        for name in [A, B, A] {
            assert_eq!(
                send(&client, fixture.request(name, coalesce))
                    .await
                    .unwrap(),
                StatusCode::OK
            );
        }
        let port = fixture.server.address.port();
        assert_eq!(
            authorities(&fixture.server),
            [A, B, A].map(|name| format!("{name}:{port}")),
            "request authorities are preserved"
        );
        assert_eq!(
            fixture.server.accepted.load(Ordering::SeqCst),
            if coalesce { 1 } else { 2 }
        );
        drop(client);
        close_client_endpoint(endpoint).await;
        fixture.server.close().await;
    }
}

#[tokio::test]
async fn origin_outside_the_certificate_never_rides_the_coalesced_connection() {
    let fixture = Fixture::start(&[A]).await;
    let (client, endpoint) = client_with_http3(fixture.tls.clone()).await;
    assert_eq!(
        send(&client, fixture.request(A, true)).await.unwrap(),
        StatusCode::OK
    );
    send(&client, fixture.request(B, true))
        .await
        .expect_err("the certificate does not cover B");
    assert_eq!(
        authorities(&fixture.server),
        [format!("{A}:{}", fixture.server.address.port())]
    );
    assert_eq!(
        fixture.server.accepted.load(Ordering::SeqCst),
        2,
        "B attempted its own handshake"
    );
    drop(client);
    close_client_endpoint(endpoint).await;
    fixture.server.close().await;
}

#[tokio::test]
async fn misdirected_request_retires_the_coalesced_connection() {
    let fixture = Fixture::start(&[A, B]).await;
    fixture.server.reply(Reply::default());
    fixture.server.reply(Reply {
        status: StatusCode::MISDIRECTED_REQUEST,
        ..Reply::default()
    });
    let (client, endpoint) = client_with_http3(fixture.tls.clone()).await;
    assert_eq!(
        send(&client, fixture.request(A, true)).await.unwrap(),
        StatusCode::OK
    );
    assert_eq!(
        send(&client, fixture.request(B, true)).await.unwrap(),
        StatusCode::MISDIRECTED_REQUEST
    );
    assert_eq!(fixture.server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(
        send(&client, fixture.request(A, true)).await.unwrap(),
        StatusCode::OK
    );
    assert_eq!(
        fixture.server.accepted.load(Ordering::SeqCst),
        2,
        "the misdirected connection is not reused"
    );
    assert_eq!(fixture.server.request_count(), 3, "B is not replayed");
    drop(client);
    close_client_endpoint(endpoint).await;
    fixture.server.close().await;
}
