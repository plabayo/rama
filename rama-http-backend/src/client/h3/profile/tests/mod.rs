// Fixture helpers fail immediately when native setup or an exchange fails.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use crate::client::Http3Connector;
use rama_core::{
    Service,
    rt::{Executor, spawn},
};
use rama_http_core::h3::{client as h3_client, connection::Config, server as h3_server};
use rama_http_types::{Body, Request, Response};
use rama_net::{
    Protocol,
    address::{HostWithPort, SocketAddress},
    client::{
        ConnectorTarget,
        pool::{ConnectionReuse, ReuseKey},
    },
};
use rama_quic::{
    Endpoint, ServerConfig,
    tls::{BoringTlsProvider, TlsOptions},
};
use rama_quic_proto::{
    VarInt,
    capture::CaptureLimits,
    profile::{GreaseParameter, QuicProfile, TransportParameterProfile},
};
use rama_tls::{
    client::TlsPoolId,
    server::{LeafCertRequest, ServerAuthData, TlsServerConfig},
};
use rama_ua::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::CapturedSlotKind,
        tls::{TlsCapture, TlsCaptureLimits},
    },
    model::identity::ConnectionContext,
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};

mod bindings;
mod providers;
mod selection;
mod wire;

struct Fixture {
    connector: Http3Connector,
    server: Endpoint,
    client_endpoint: Endpoint,
    task: Option<JoinHandle<Vec<TlsCapture>>>,
    capture: TlsCapture,
    port: u16,
    profile: QuicProfile,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.client_endpoint
            .close(VarInt::from_u32(0), b"fixture complete");
        self.server.close(VarInt::from_u32(0), b"fixture complete");
    }
}

impl Fixture {
    fn input(&self) -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(self.port))
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(ConnectorTarget(HostWithPort::local_ipv4(self.port)));
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        input.extensions().insert(self.profile.clone());
        input
    }

    fn install(&self, input: &ConnectRequest) {
        let (context, _) = selection::selected("native-h3-selection", &self.capture);
        context.publish(input.extensions());
    }
}

async fn request(transport: crate::client::Http3Transport) {
    let connection = transport.connection.clone();
    let (mut sender, driver) = h3_client::handshake::<Body>(
        transport.connection,
        Arc::unwrap_or_clone(transport.config),
        Executor::new(),
    )
    .unwrap();
    spawn(driver.run());
    let response = sender
        .send_request(
            Request::builder()
                .uri("https://localhost/profile-template")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    connection.close(VarInt::from_u32(0), b"request complete");
}

fn rejected(
    result: Result<(super::super::PreparedTls, Arc<Config>), rama_net::client::ConnectionError>,
) {
    let Err(error) = result else {
        panic!("invalid captured connection was accepted");
    };
    assert_eq!(
        error.kind(),
        rama_net::client::ConnectionErrorKind::InvalidInput
    );
}

async fn fixture() -> Fixture {
    let identity = ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
    let server_tls = TlsServerConfig::new()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
        .with_server_auth(identity.clone());
    let mut config = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
    config.set_capture(CaptureLimits::default());
    let server = Endpoint::bind_server(Executor::new(), config, SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let port = server.local_addr().unwrap().port();
    let (send, receive) = oneshot::channel();
    let accept = server.clone();
    let task = spawn(async move {
        let mut send = Some(send);
        let mut captures = Vec::new();
        for _ in 0..2 {
            let mut incoming = accept.accept().await.unwrap();
            let hello = incoming.client_hello().await.unwrap();
            let capture = TlsCapture::capture(
                ProfileCaptureCompleteness::Complete,
                TlsCaptureTransport::Quic,
                &hello,
                TlsCaptureLimits::default(),
            )
            .unwrap();
            if let Some(send) = send.take() {
                send.send(capture.clone()).unwrap();
            }
            captures.push(capture);
            let connection = incoming.accept().unwrap().await.unwrap();
            let (mut http, driver) = h3_server::handshake(connection, Config::default()).unwrap();
            spawn(driver.run());
            let (request, response) = http.accept().await.unwrap().resolve().await.unwrap();
            assert!(
                request
                    .uri()
                    .path()
                    .is_some_and(|path| path == "/profile-template")
            );
            response
                .send_response(Response::new(Body::empty()))
                .await
                .unwrap();
        }
        captures
    });
    let tls = TlsClientConfig::new()
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    let connector = Http3Connector::builder(Executor::new())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .with_tls_config(tls)
        .build_lazy()
        .unwrap();
    // Keep only connection-owned parameter values variable, not their lengths.
    let profile = QuicProfile::standard().with_transport_parameters(
        TransportParameterProfile::standard()
            .try_with_grease(GreaseParameter::None)
            .unwrap(),
    );
    let client_endpoint = connector
        .endpoint_for_profile(Some(&profile))
        .await
        .unwrap();
    let source = ConnectRequest::new(HostWithPort::localhost_domain_with_port(port))
        .with_application_protocol(Protocol::HTTPS);
    source
        .extensions()
        .insert(ConnectorTarget(HostWithPort::local_ipv4(port)));
    source.extensions().insert(profile.clone());
    request(connector.serve(source).await.unwrap().conn).await;
    let mut capture = receive.await.unwrap();
    // Select an unpadded TLS template. Explicit padding is not supported by the
    // wire compiler; this test does not claim byte-for-byte replay of that option.
    capture.extensions = capture
        .extensions
        .into_vec()
        .into_iter()
        .filter(|extension| extension.id != u16::from(ExtensionId::PADDING))
        .collect();
    Fixture {
        connector,
        server,
        client_endpoint,
        task: Some(task),
        capture,
        port,
        profile,
    }
}
