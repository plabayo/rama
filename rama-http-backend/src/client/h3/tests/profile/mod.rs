// Fixture helpers fail immediately when native setup or an exchange fails.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use crate::client::{Http3Connector, Http3Transport, h3::PreparedTls};
use rama_core::{
    Service,
    extensions::Extensions,
    rt::{Executor, spawn},
};
use rama_http_core::h3::{client as h3_client, connection::Config, server as h3_server};
use rama_http_types::{Body, Request, Response};
use rama_net::{
    Protocol,
    address::{HostWithPort, SocketAddress},
    client::{
        ConnectionError, ConnectionErrorKind, ConnectorTarget, EstablishedClientConnection,
        pool::{ConnectionReuse, ReuseKey},
    },
};
use rama_quic::{
    Endpoint, ServerConfig,
    profile::replay::{CompiledConnection, ConnectionProfileCompiler},
    tls::{BoringTlsProvider, ClientConfigCache, TlsOptions},
};
use rama_quic_proto::{
    VarInt,
    capture::{CaptureLimits, QuicObservation, transport_parameters_from_hello},
    profile::{GreaseParameter, OpaqueParameter, QuicProfile, TransportParameterProfile},
    transport_parameters::TransportParameterId,
};
use rama_tls::client::TlsClientConfig;
use rama_tls::{
    ExtensionId,
    client::TlsPoolId,
    server::{LeafCertRequest, ServerAuthData, TlsServerConfig},
};
use rama_ua::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::CapturedSlotKind,
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
        tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
    },
    model::identity::ConnectionContext,
};
use rama_ua::{
    layer::emulate::ProfileEmulateHttpConnectModifier,
    profile::replay::connection::{
        compiler::{ConnectionProfileCompiler as _, InstalledConnectionProfile},
        preparation::ConnectionPreparation,
    },
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
    task: Option<JoinHandle<Vec<(TlsCapture, OrderedProtocolCapture, QuicFlightCapture)>>>,
    capture: TlsCapture,
    parameters: OrderedProtocolCapture,
    flight: QuicFlightCapture,
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
    fn compiler(&self) -> ConnectionProfileCompiler {
        ConnectionProfileCompiler::new(
            self.connector.tls.clone(),
            self.connector.tls_provider().clone(),
        )
    }

    fn prepare_connection(
        &self,
        input: &ConnectRequest,
    ) -> Result<(PreparedTls, Arc<Config>), ConnectionError> {
        validate_version(input)?;
        if let Some((mut preparation, compiled)) =
            prepare(input, &self.connector.tls, &self.connector.tls_configs)
                .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))?
        {
            preparation.apply_http(input).map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
            })?;
            // Publish the selection and report on the input for inspection.
            preparation
                .publish(input.extensions(), input.extensions(), None)
                .map_err(|error| {
                    ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                })?;
            <CompiledConnection as InstalledConnectionProfile<ConnectRequest>>::apply(
                compiled,
                input.extensions(),
            );
        }
        self.connector.prepare_connection(input)
    }

    async fn serve(
        &self,
        input: ConnectRequest,
    ) -> Result<EstablishedClientConnection<Http3Transport, ConnectRequest>, ConnectionError> {
        ProfileEmulateHttpConnectModifier::new(self.connector.clone())
            .with_connection_compiler(self.compiler())
            .serve(input)
            .await
    }

    fn target(&self) -> ConnectRequest {
        let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(self.port))
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(ConnectorTarget(HostWithPort::local_ipv4(self.port)));
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        input
    }

    fn input(&self) -> ConnectRequest {
        let input = self.target();
        input.extensions().insert(self.profile.clone());
        input
    }

    fn install(&self, input: &ConnectRequest) {
        let (context, _) = selection::selected("native-h3-selection", &self.capture, None, None);
        context.publish(input.extensions());
    }
}

async fn request(transport: Http3Transport) {
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

fn rejected(result: Result<(PreparedTls, Arc<Config>), ConnectionError>) {
    let Err(error) = result else {
        panic!("invalid captured connection was accepted");
    };
    assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
}

async fn fixture() -> Fixture {
    // Keep only connection-owned parameter values variable, not their lengths.
    let profile = QuicProfile::standard().with_transport_parameters(
        TransportParameterProfile::standard()
            .try_with_grease(GreaseParameter::None)
            .unwrap(),
    );
    fixture_with_profile(profile).await
}

async fn fixture_with_profile(profile: QuicProfile) -> Fixture {
    // An opaque test parameter makes ClientHello span multiple datagrams and
    // exceed automatic TLS padding, without provider-specific configuration.
    let mut extra = profile.transport_parameters().extra().to_vec();
    extra.push(OpaqueParameter {
        id: TransportParameterId::from(0xface),
        value: vec![0; 1024],
    });
    let parameters = profile
        .transport_parameters()
        .clone()
        .try_with_extra(extra)
        .unwrap();
    let profile = profile.with_transport_parameters(parameters);
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
            let raw = transport_parameters_from_hello(&hello, &CaptureLimits::default()).unwrap();
            let parameters = OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::QuicParameter,
                raw.iter()
                    .map(|parameter| (u64::from(parameter.id), parameter.value.as_slice())),
                OrderCaptureLimits::default(),
            )
            .unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            let observation = connection
                .extensions()
                .get_ref::<QuicObservation>()
                .unwrap();
            let flight =
                QuicFlightCapture::capture(observation, QuicFlightCaptureLimits::default())
                    .unwrap();
            if let Some(send) = send.take() {
                send.send((capture.clone(), parameters.clone(), flight.clone()))
                    .unwrap();
            }
            captures.push((capture, parameters, flight));
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
    let (capture, parameters, flight) = receive.await.unwrap();
    assert!(
        !capture
            .extensions
            .iter()
            .any(|extension| extension.id == u16::from(ExtensionId::PADDING))
    );
    Fixture {
        connector,
        server,
        client_endpoint,
        task: Some(task),
        capture,
        parameters,
        flight,
        port,
        profile,
    }
}

fn prepare(
    input: &ConnectRequest,
    tls: &TlsClientConfig,
    cache: &ClientConfigCache,
) -> Result<Option<(ConnectionPreparation, CompiledConnection)>, BoxError> {
    let compiler = ConnectionProfileCompiler::new(tls.clone(), cache.provider().clone());
    ConnectionPreparation::prepare(input, |selection, components| {
        compiler.compile(input, selection, components)
    })
}
