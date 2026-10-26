//! HTTP/3 establishment over a QUIC connector, with Rama DNS candidates and the existing
//! multiplex pool.

pub(crate) mod coalescing;
#[doc(inline)]
pub use coalescing::Http3Coalescing;

#[cfg(test)]
mod tests;

use super::Http3Transport;
use coalescing::PendingAliases;
use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    rt::Executor,
    telemetry::tracing,
};
use rama_http_core::h3::connection::Config;
use rama_http_types::{
    Version,
    conn::TargetHttpVersion,
    proto::h3::{
        ClientSettingsProfile, control::ClientControlPreferences,
        critical_streams::Preferences as CriticalStreamPreferences, qpack::EncoderPreferences,
    },
};
use rama_net::{
    ProtocolInputExt,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectionErrorKind::InvalidInput,
        ConnectorService, EstablishedClientConnection,
    },
    tls::{AlpnPolicy, ApplicationProtocol, TlsAlpn},
};
use rama_quic::{
    Endpoint, NegotiatedTlsParameters, TransportConfig,
    client::{ClientEndpoint, QuicConnector, SharedQuicEndpoint},
    tls::{QuicClientConfigProvider, default_tls_provider},
};
use rama_quic_proto::profile::{QuicProfile, TransportLimits};
use rama_tls::client::{TlsClientConfig, TlsServerAuthentication};
use std::sync::Arc;

/// Establish HTTP/3 transports over the authenticated QUIC connections of a
/// [`QuicConnector`], for the common HTTP handshake.
///
/// Wrap this connector with Rama's DNS connector and HTTP connection pool, which checks the
/// reuse policy published by the QUIC connector. Requests may supply an explicit ALPN offer
/// containing `h3`; otherwise `h3` is offered alone and required after the handshake.
/// HTTP/3 limits set the QUIC receive budgets.
///
/// Where the QUIC connections come from is the QUIC connector's endpoint connector `E`: by
/// default one [`SharedQuicEndpoint`] for every connection; a
/// [`QuicEndpointConnector`](rama_quic::client::QuicEndpointConnector) over a datagram
/// connector gives each connection its own socket, such as a UDP tunnel through a proxy.
/// Proxy routes are served only by an endpoint connector that establishes them.
pub struct Http3Connector<E = SharedQuicEndpoint> {
    quic: QuicConnector<E>,
    // The same connector, also storing the server's certificate chain: a coalescing group
    // checks its other origins against the leaf.
    coalescing: QuicConnector<E>,
    config: Arc<Config>,
}

impl<E: Clone> Clone for Http3Connector<E> {
    fn clone(&self) -> Self {
        Self {
            quic: self.quic.clone(),
            coalescing: self.coalescing.clone(),
            config: self.config.clone(),
        }
    }
}

impl<E: std::fmt::Debug> std::fmt::Debug for Http3Connector<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3Connector")
            .field("quic", &self.quic)
            .field("config", &self.config)
            .finish()
    }
}

/// Configure an HTTP/3 connector and the QUIC connector below it.
///
/// The supplied executor owns endpoint and connection tasks. Pass an executor tied to the
/// application's graceful shutdown when those tasks should drain with the application.
#[derive(Debug)]
pub struct Http3ConnectorBuilder<E = SharedQuicEndpoint> {
    endpoints: E,
    tls: TlsClientConfig,
    provider: Option<Arc<dyn QuicClientConfigProvider>>,
    config: Config,
    transport: Option<TransportConfig>,
    executor: Executor,
}

impl Http3Connector {
    /// Configure a connector with default TLS verification and HTTP/3 limits, sharing one
    /// managed QUIC endpoint.
    #[must_use]
    pub fn builder(executor: Executor) -> Http3ConnectorBuilder {
        Http3ConnectorBuilder {
            endpoints: SharedQuicEndpoint::managed(executor.clone()),
            tls: TlsClientConfig::default_http(),
            provider: None,
            config: Config::default(),
            transport: None,
            executor,
        }
    }
}

impl<E> Http3Connector<E> {
    /// HTTP/3 over the connections of `quic`, whose transport gets HTTP/3's limits and whose
    /// TLS defaults offer `h3`.
    pub fn try_new(mut quic: QuicConnector<E>, config: Config) -> Result<Self, BoxError>
    where
        E: Clone,
    {
        let mut transport = (**quic.transport()).clone();
        config.configure_transport(&mut transport)?;
        quic.set_transport(Arc::new(transport));
        let tls = offering_h3(quic.tls_config().clone());
        let coalescing = quic
            .clone()
            .with_tls_config(tls.clone().with_store_server_cert_chain(true));
        quic.set_tls_config(tls);
        Ok(Self {
            quic,
            coalescing,
            config: Arc::new(config),
        })
    }

    /// The QUIC connector below.
    #[must_use]
    pub fn quic(&self) -> &QuicConnector<E> {
        &self.quic
    }

    /// Fixed TLS defaults for this connector. Rebuild its pool when these defaults
    /// or behavior captured by native TLS hooks change.
    #[must_use]
    pub fn tls_config(&self) -> &TlsClientConfig {
        self.quic.tls_config()
    }

    /// Provider selection used for establishment and TLS pool identity.
    #[must_use]
    pub fn tls_provider(&self) -> &Arc<dyn QuicClientConfigProvider> {
        self.quic.tls_provider()
    }
}

impl Http3ConnectorBuilder {
    rama_utils::macros::generate_set_and_with! {
        /// Share an application-managed endpoint instead of binding a new socket.
        pub fn endpoint(mut self, endpoint: Endpoint) -> Self {
            self.endpoints = SharedQuicEndpoint::supplied(endpoint, self.executor.clone());
            self
        }
    }

    /// Validate the limits and bind the shared endpoint now.
    pub async fn build(self) -> Result<Http3Connector, BoxError> {
        let connector = self.build_lazy()?;
        connector.quic.endpoints().prepare().await?;
        Ok(connector)
    }
}

impl<E> Http3ConnectorBuilder<E> {
    /// The executor of endpoint and connection tasks.
    #[must_use]
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Take the QUIC endpoints from `endpoints`, such as a
    /// [`QuicEndpointConnector`](rama_quic::client::QuicEndpointConnector) giving each
    /// connection its own socket.
    pub fn with_endpoints<E2>(self, endpoints: E2) -> Http3ConnectorBuilder<E2> {
        Http3ConnectorBuilder {
            endpoints,
            tls: self.tls,
            provider: self.provider,
            config: self.config,
            transport: self.transport,
            executor: self.executor,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set TLS defaults; request TLS extensions can override these settings.
        /// HTTP/3 requires ALPN by default. With [`AlpnPolicy::OutOfBandAgreement`],
        /// an explicitly empty ALPN offer is preserved for known HTTP/3 peers.
        /// The selected QUIC TLS backend must support this mode.
        ///
        /// [`AlpnPolicy::OutOfBandAgreement`]: rama_net::tls::AlpnPolicy::OutOfBandAgreement
        pub fn tls_config(mut self, tls: TlsClientConfig) -> Self {
            self.tls = tls;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Inject the fixed TLS configuration provider, including custom implementations.
        pub fn tls_provider(mut self, provider: Arc<dyn QuicClientConfigProvider>) -> Self {
            self.provider = Some(provider);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure HTTP/3 limits and their corresponding QUIC receive budgets.
        pub fn config(mut self, config: Config) -> Self {
            self.config = config;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// The QUIC transport connections start from, such as a larger initial MTU for a
        /// connection to a MASQUE proxy; HTTP/3 limits are applied on top. A request's
        /// [`QuicProfile`] replaces it.
        pub fn transport(mut self, transport: Option<TransportConfig>) -> Self {
            self.transport = transport;
            self
        }
    }

    /// Validate configuration now; endpoints are bound on the first connection attempt.
    ///
    /// Construction requires no runtime or socket. Clones share the endpoints.
    pub fn build_lazy(self) -> Result<Http3Connector<E>, BoxError>
    where
        E: Clone,
    {
        let provider = match self.provider {
            Some(provider) => provider,
            None => default_tls_provider()?,
        };
        let quic = QuicConnector::new(self.endpoints, self.tls, provider)
            .with_transport(Arc::new(self.transport.unwrap_or_default()));
        Http3Connector::try_new(quic, self.config)
    }
}

impl<E> Http3Connector<E> {
    /// The HTTP/3 limits for a connection: captured client settings and preferences on the
    /// request applied to the configured ones.
    fn h3_config(
        &self,
        input: &ConnectRequest,
        profile: Option<&QuicProfile>,
    ) -> Result<Arc<Config>, ConnectionError> {
        let mut h3_config = match input.extensions().get_ref::<ClientSettingsProfile>() {
            Some(settings) => {
                let datagrams = match profile {
                    Some(profile) => TransportConfig::from_quic_profile(profile)
                        .map_err(|error| ConnectionError::local(error, InvalidInput))?
                        .datagram_receive_enabled(),
                    None => self.quic.transport().datagram_receive_enabled(),
                };
                // A captured datagram grant without QUIC reception is dropped while fitting.
                let config = if datagrams || self.config.datagrams.is_none() {
                    self.config.try_with_client_settings(settings.0.clone())
                } else {
                    Config {
                        datagrams: None,
                        ..(*self.config).clone()
                    }
                    .try_with_client_settings(settings.0.clone())
                };
                Arc::new(config.map_err(|error| ConnectionError::local(error, InvalidInput))?)
            }
            None => self.config.clone(),
        };
        if let Some(preferences) = input.extensions().get_ref::<CriticalStreamPreferences>() {
            Arc::make_mut(&mut h3_config).critical_streams = *preferences;
        }
        if let Some(preferences) = input.extensions().get_ref::<EncoderPreferences>() {
            Arc::make_mut(&mut h3_config)
                .encoder
                .apply_preferences(*preferences);
        }
        if let Some(preferences) = input.extensions().get_arc::<ClientControlPreferences>() {
            Arc::make_mut(&mut h3_config)
                .try_set_client_controls(Some(preferences))
                .map_err(|error| ConnectionError::local(error, InvalidInput))?;
        }
        Ok(h3_config)
    }
}

/// `profile` granting at least the peer's three critical unidirectional streams.
fn with_critical_stream_credit(profile: Arc<QuicProfile>) -> Arc<QuicProfile> {
    let captured = profile.limits().initial_max_streams_uni;
    if captured >= 3 {
        return profile;
    }
    let limits = TransportLimits {
        initial_max_streams_uni: 3,
        ..profile.limits().clone()
    };
    match (*profile).clone().try_with_limits(limits) {
        Ok(raised) => {
            tracing::debug!(
                captured,
                "HTTP/3 QUIC profile raises unidirectional stream credit to three critical streams"
            );
            Arc::new(raised)
        }
        Err(error) => {
            tracing::debug!(%error, "HTTP/3 QUIC profile keeps its unidirectional stream credit");
            profile
        }
    }
}

impl<E> Service<ConnectRequest> for Http3Connector<E>
where
    E: ConnectorService<ConnectRequest, Connection = ClientEndpoint>,
{
    type Output = EstablishedClientConnection<Http3Transport, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        if input.target_protocol().is_none_or(|p| !p.is_secure()) {
            return Err(ConnectionError::local(
                BoxError::from_static_str("HTTP/3 requires a secure origin"),
                InvalidInput,
            ));
        }
        validate_version(&input)?;
        let profile = input
            .extensions()
            .get_arc::<QuicProfile>()
            .map(with_critical_stream_credit);
        if let Some(profile) = &profile {
            input.extensions().insert_arc(profile.clone());
        }
        let h3_config = self.h3_config(&input, profile.as_deref())?;
        let quic = if coalescing::pool_group(&input).is_some() {
            &self.coalescing
        } else {
            &self.quic
        };

        let EstablishedClientConnection {
            input,
            conn: connection,
        } = quic.serve(input).await?;
        let policy = connection
            .extensions()
            .get_ref::<AlpnPolicy>()
            .copied()
            .unwrap_or_default();
        let negotiated = connection
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .and_then(|tls| tls.application_layer_protocol.as_ref());
        if !policy.accepts(&ApplicationProtocol::HTTP_3, negotiated) {
            connection.close(0u32, b"h3 ALPN required");
            return Err(ConnectionError::application(
                BoxError::from_static_str(
                    "HTTP/3 requires h3 ALPN or explicit out-of-band agreement",
                ),
                ConnectionErrorKind::Protocol,
            ));
        }
        let authenticated = connection
            .extensions()
            .get_ref::<TlsServerAuthentication>()
            .and_then(|authentication| authentication.0.clone());
        if let Some(aliases) =
            PendingAliases::new(&input, quic.tls_config_for(&input), authenticated.as_ref())
        {
            aliases.verify(&connection, self.tls_provider().as_ref());
        }
        connection
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        Ok(EstablishedClientConnection {
            input,
            conn: Http3Transport {
                connection,
                config: h3_config,
            },
        })
    }
}

/// `tls` offering `h3` alone, unless its offer is explicitly empty: the protocol is then
/// agreed out of band.
fn offering_h3(mut tls: TlsClientConfig) -> TlsClientConfig {
    let empty = tls
        .as_extensions()
        .get_ref::<TlsAlpn>()
        .is_some_and(|offer| offer.0.is_empty());
    if !empty {
        tls.set_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    }
    tls
}

fn validate_version(input: &ConnectRequest) -> Result<(), ConnectionError> {
    if input
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .is_some_and(|version| version.0 != Version::HTTP_3)
    {
        return Err(ConnectionError::local(
            BoxError::from_static_str("explicit HTTP version conflicts with HTTP/3 connector"),
            ConnectionErrorKind::InvalidInput,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod concrete_transport_tests {
    use super::{tests::prepare, *};
    #[cfg(feature = "boring")]
    use rama_core::error::error_chain;
    use rama_core::{
        extensions::{Extensions, Ingress},
        rt::spawn,
    };
    use rama_crypto::pki_types::CertificateDer;
    use rama_http_core::h3::{
        client as h3_client,
        observation::{H3Observer, SettingsObservation},
        server as h3_server,
    };
    use rama_http_types::{
        Body, Request, Response,
        proto::h3::{SettingId, Settings},
    };
    use rama_net::{
        Protocol,
        address::{Host, HostWithPort, SocketAddress},
        client::{
            ConnectionErrorDomain, ConnectorTarget, ProxyRoute, ProxyRouteFailureCache,
            ProxyRouteFailureCacheConnector, ProxyRoutes, ProxyRoutesConnector, pool::ReuseKey,
        },
        tls::{AlpnPolicy, TlsAlpn},
    };
    use rama_quic::{
        ClientConfig, EndpointConfig, ServerConfig,
        tls::{TlsConfigError, TlsOptions},
    };
    use rama_quic_proto::{
        VarInt,
        capture::{CaptureLimits, QuicObservation},
        coding::Codec,
        profile::{ConnectionIdProfile, TransportParameterProfile},
        transport_parameters::TransportParameterId,
        version::{ClientVersionPolicy, Version as QuicVersion},
    };
    use rama_tls::{
        client::{ServerVerifyMode, TlsClientConfigProvider, TlsPoolId, TlsServerVerify},
        server::{LeafCertRequest, ServerAuthData, TlsServerConfig},
    };
    use std::{
        future::pending,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::time::Instant;

    #[derive(Debug, Default)]
    struct CustomProvider {
        calls: AtomicUsize,
        authenticated_checks: AtomicUsize,
    }

    impl TlsClientConfigProvider for CustomProvider {
        fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
            TlsPoolId::builder()
                .maybe_with_verify(extensions.get_ref::<TlsServerVerify>())
                .build()
        }

        fn pool_classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn authenticates_server(&self, extensions: &Extensions) -> bool {
            self.authenticated_checks.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                extensions.get_ref::<TlsAlpn>().unwrap().0.as_slice(),
                &[ApplicationProtocol::HTTP_3]
            );
            extensions
                .get_ref::<TlsServerVerify>()
                .is_none_or(|verify| verify.0 != ServerVerifyMode::Disable)
        }
    }

    impl QuicClientConfigProvider for CustomProvider {
        fn peer_matches_name(&self, _: &Extensions, _: &CertificateDer<'_>, _: &Host) -> bool {
            false
        }

        fn client_config(
            &self,
            config: &TlsClientConfig,
            _: TlsOptions,
        ) -> Result<ClientConfig, TlsConfigError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                config
                    .as_extensions()
                    .get_ref::<TlsAlpn>()
                    .unwrap()
                    .0
                    .as_slice(),
                &[ApplicationProtocol::HTTP_3]
            );
            assert_eq!(
                config
                    .as_extensions()
                    .get_ref::<TlsServerVerify>()
                    .unwrap()
                    .0,
                ServerVerifyMode::Disable
            );
            Err(TlsConfigError::InvalidConfiguration(
                BoxError::from_static_str("custom factory invoked"),
            ))
        }
    }

    #[tokio::test]
    async fn an_offer_with_h3_still_requires_h3_to_be_negotiated() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let other = ApplicationProtocol::from(b"rama-other");
            let identity =
                ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
            let server_tls = TlsServerConfig::new()
                .with_server_auth(identity)
                .with_alpn([other.clone()].into_iter().collect());
            let server = Endpoint::bind_server(
                Executor::new(),
                ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap(),
                SocketAddress::local_ipv4(0),
            )
            .await
            .unwrap();
            let address = server.local_addr().unwrap();
            let accept = server.clone();
            spawn(async move {
                let connecting = accept.accept().await.unwrap().accept().unwrap();
                // Held open: the client, not the server, must refuse the protocol.
                let _connection = connecting.await;
                pending::<()>().await;
            });
            let connector = Http3Connector::builder(Executor::new())
                .with_tls_config(
                    TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
                )
                .build_lazy()
                .unwrap();
            let input = ConnectRequest::new(HostWithPort::local_ipv4(address.port()))
                .with_application_protocol(Protocol::HTTPS);
            // An explicit offer that includes h3 is kept, so the server may pick the other.
            input.extensions().insert(TlsAlpn(
                [ApplicationProtocol::HTTP_3, other].into_iter().collect(),
            ));
            let error = connector.serve(input).await.unwrap_err();
            assert_eq!(error.kind(), ConnectionErrorKind::Protocol, "{error:?}");
            server.close(0u32, b"test complete");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn http3_without_alpn_requires_explicit_agreement() {
        tokio::time::timeout(Duration::from_secs(20), async {
            for (base_policy, request_policy) in [
                (None, None),
                (Some(AlpnPolicy::Require), None),
                (Some(AlpnPolicy::OutOfBandAgreement), None),
                (None, Some(AlpnPolicy::OutOfBandAgreement)),
                (
                    Some(AlpnPolicy::Require),
                    Some(AlpnPolicy::OutOfBandAgreement),
                ),
                (
                    Some(AlpnPolicy::OutOfBandAgreement),
                    Some(AlpnPolicy::Require),
                ),
            ] {
                let policy = request_policy.or(base_policy);
                let identity =
                    ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
                let server_tls = TlsServerConfig::new()
                    .with_server_auth(identity)
                    .with_alpn(Default::default());
                let server = Endpoint::bind_server(
                    Executor::new(),
                    ServerConfig::try_from_rama_tls(
                        &server_tls,
                        TlsOptions::default().with_alpn(AlpnPolicy::OutOfBandAgreement),
                    )
                    .unwrap(),
                    SocketAddress::local_ipv4(0),
                )
                .await
                .unwrap();
                let address = server.local_addr().unwrap();
                let accept = server.clone();
                let serve = spawn(async move {
                    let connecting = accept.accept().await.unwrap().accept().unwrap();
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    assert!(
                        connection
                            .extensions()
                            .get_ref::<NegotiatedTlsParameters>()
                            .unwrap()
                            .application_layer_protocol
                            .is_none()
                    );
                    let forwarded = Extensions::new();
                    forwarded.insert(Ingress(connection.extensions().clone()));
                    let outbound = TlsClientConfig::new()
                        .with_alpn_policy(AlpnPolicy::Require)
                        .with_overrides(&forwarded);
                    assert_eq!(
                        outbound.as_extensions().get_ref::<AlpnPolicy>(),
                        Some(&AlpnPolicy::Require)
                    );
                    assert!(!forwarded.contains::<AlpnPolicy>());
                    let (mut http, driver) = h3_server::handshake(
                        connection,
                        Config {
                            server_alpn_policy: AlpnPolicy::OutOfBandAgreement,
                            ..Config::default()
                        },
                    )
                    .unwrap();
                    spawn(driver.run());
                    let (_, response) = http.accept().await.unwrap().resolve().await.unwrap();
                    response
                        .send_response(Response::new(Body::empty()))
                        .await
                        .unwrap();
                    // Keep the HTTP service alive until the test closes the endpoint.
                    drop(http.accept().await);
                });
                let mut tls = TlsClientConfig::new()
                    .with_server_verify(ServerVerifyMode::Disable)
                    .with_alpn(Default::default());
                if let Some(policy) = base_policy {
                    tls.set_alpn_policy(policy);
                }
                let connector = Http3Connector::builder(Executor::new())
                    .with_tls_config(tls)
                    .build_lazy()
                    .unwrap();
                let input = ConnectRequest::new(HostWithPort::local_ipv4(address.port()))
                    .with_application_protocol(Protocol::HTTPS);
                if let Some(policy) = request_policy {
                    input.extensions().insert(policy);
                }
                let result = connector.serve(input).await;
                assert_eq!(
                    result.is_ok(),
                    policy == Some(AlpnPolicy::OutOfBandAgreement),
                    "{policy:?}"
                );
                if let Ok(established) = result {
                    let connection = established.conn.connection.clone();
                    let second_transport = Http3Transport {
                        connection: connection.clone(),
                        config: established.conn.config.clone(),
                    };
                    let established = crate::client::http_connect::<_, _, Body>(
                        established.conn,
                        established.input,
                        Executor::new(),
                    )
                    .await
                    .unwrap();
                    let strict = ConnectRequest::new(HostWithPort::local_ipv4(address.port()))
                        .with_application_protocol(Protocol::HTTPS);
                    strict.extensions().insert(AlpnPolicy::Require);
                    assert!(
                        crate::client::http_connect::<_, _, Body>(
                            second_transport,
                            strict,
                            Executor::new(),
                        )
                        .await
                        .is_err()
                    );
                    assert_eq!(
                        connection.extensions().get_ref::<AlpnPolicy>(),
                        Some(&AlpnPolicy::OutOfBandAgreement)
                    );
                    // The original service must still send requests after the rejected override.
                    let request = Request::builder()
                        .version(Version::HTTP_3)
                        .uri(format!("https://{address}/"))
                        .body(Body::empty())
                        .unwrap();
                    let response = established.conn.serve(request).await.unwrap();
                    assert_eq!(response.version(), Version::HTTP_3);
                    assert!(
                        connection
                            .extensions()
                            .get_ref::<NegotiatedTlsParameters>()
                            .unwrap()
                            .application_layer_protocol
                            .is_none()
                    );
                    connection.close(0u32, b"done");
                }
                serve.abort();
                server.close(0u32, b"done");
            }
        })
        .await
        .expect("HTTP/3 no-ALPN matrix deadline");
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn boring_rejects_unsupported_alpnless_http3_configuration() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(rama_quic::tls::BoringTlsProvider))
            .with_tls_config(
                TlsClientConfig::new()
                    .with_alpn_policy(AlpnPolicy::OutOfBandAgreement)
                    .with_alpn(Default::default()),
            )
            .build_lazy()
            .unwrap();
        let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
            .with_application_protocol(Protocol::HTTPS);
        let error = prepare(&connector, &input).await.unwrap_err();
        assert!(error_chain(&error).any(|cause| {
            matches!(
                cause.downcast_ref::<TlsConfigError>(),
                Some(TlsConfigError::UnsupportedOutOfBandAgreement)
            )
        }));
    }

    #[tokio::test]
    async fn explicit_alpn_conflicts_are_lowered_to_http3() {
        for offer in [TlsAlpn::empty(), TlsAlpn::http_auto()] {
            let provider = Arc::new(CustomProvider::default());
            let connector = Http3Connector::builder(Executor::new())
                .with_tls_provider(provider.clone())
                .build_lazy()
                .unwrap();
            let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
                .with_application_protocol(Protocol::HTTPS);
            input.extensions().insert(offer);
            input
                .extensions()
                .insert(TlsServerVerify(ServerVerifyMode::Disable));
            // The provider asserts it is handed exactly the HTTP/3 offer.
            drop(connector.serve(input).await.err().unwrap());
            assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn captured_h3_datagrams_without_quic_reception_are_dropped() {
        for (window, advertised) in [(None, None), (Some(0), None), (Some(4096), Some(0))] {
            for request_settings in [false, true] {
                let mut settings = Settings::default();
                settings.set(SettingId::H3_DATAGRAM, 1).unwrap();
                let settings = Arc::new(settings);
                let config = if request_settings {
                    Config::default()
                } else {
                    Config::default()
                        .try_with_client_settings(settings.clone())
                        .unwrap()
                };
                let connector = Http3Connector::builder(Executor::new())
                    .with_config(config)
                    .build_lazy()
                    .unwrap();
                let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
                    .with_application_protocol(Protocol::HTTPS);
                input
                    .extensions
                    .insert(TlsServerVerify(ServerVerifyMode::Disable));
                // Without a version switch every TLS provider accepts the profile.
                let profile = QuicProfile::standard()
                    .with_versions(ClientVersionPolicy::new(QuicVersion::V1).unwrap())
                    .with_transport_parameters(
                        TransportParameterProfile::standard()
                            .try_with_max_datagram_frame_size(advertised)
                            .unwrap(),
                    )
                    .try_with_limits(TransportLimits {
                        datagram_receive_buffer_size: window,
                        ..TransportLimits::standard()
                    })
                    .unwrap();
                input.extensions.insert(profile);
                if request_settings {
                    input.extensions.insert(ClientSettingsProfile(settings));
                }
                let h3_config = prepare(&connector, &input).await.unwrap();
                if request_settings {
                    assert!(!h3_config.settings_profile.as_ref().unwrap().h3_datagram());
                    assert!(h3_config.datagrams.is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn captured_h3_without_datagrams_allows_quic_reception_disabled() {
        let provider = Arc::new(CustomProvider::default());
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(provider.clone())
            .build_lazy()
            .unwrap();
        let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        input
            .extensions
            .insert(ClientSettingsProfile(Arc::new(Settings::default())));
        input.extensions.insert(
            QuicProfile::standard()
                .try_with_limits(TransportLimits {
                    datagram_receive_buffer_size: None,
                    ..TransportLimits::standard()
                })
                .unwrap(),
        );
        // This fixture provider deliberately fails once reached. Its call count
        // proves the compatible profile passes the cross-protocol preflight.
        let error = connector.serve(input).await.err().unwrap();
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn lazy_connector_construction_needs_no_runtime() {
        // No runtime exists here: construction must neither bind nor spawn.
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build_lazy()
            .unwrap();
        drop(connector);
    }

    #[tokio::test]
    async fn built_connector_clones_share_the_prepared_endpoint() {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(Arc::new(CustomProvider::default()))
            .build()
            .await
            .unwrap();
        let clone = connector.clone();
        let endpoint = |connector: Http3Connector| async move {
            connector
                .quic()
                .endpoints()
                .serve(ConnectRequest::new(HostWithPort::local_ipv4(443)))
                .await
                .unwrap()
                .conn
                .endpoint()
                .clone()
        };
        let (first, second) = tokio::join!(endpoint(connector), endpoint(clone));
        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
        first.close(0u32, b"test complete");
        assert!(second.is_closed());
        first.shutdown().await;
    }

    #[tokio::test]
    async fn custom_factory_uses_public_builder_without_builtin_provider() {
        let provider = Arc::new(CustomProvider::default());
        let connector = Http3Connector::builder(Executor::default())
            .with_tls_provider(provider.clone())
            .with_tls_config(TlsClientConfig::new().with_server_verify(ServerVerifyMode::Auto))
            .build()
            .await
            .unwrap();
        let input = ConnectRequest::new(HostWithPort::local_ipv4(443))
            .with_application_protocol(Protocol::HTTPS);
        input
            .extensions
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        let classifier: Arc<dyn TlsClientConfigProvider> = connector.tls_provider().clone();
        assert_eq!(
            classifier.pool_id(input.extensions()),
            provider.pool_id(input.extensions())
        );

        let error = connector.serve(input).await.err().unwrap();
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.authenticated_checks.load(Ordering::Relaxed), 1);
        connector
            .quic()
            .endpoints()
            .serve(ConnectRequest::new(HostWithPort::local_ipv4(443)))
            .await
            .unwrap()
            .conn
            .endpoint()
            .close(0u32, b"test complete");
    }

    #[tokio::test]
    async fn proxy_only_route_never_implicitly_dials_direct_quic() {
        let executor = Executor::default();
        let endpoint = Endpoint::bind_client(executor.clone(), SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let http3 = Http3Connector::builder(executor)
            .with_endpoint(endpoint.clone())
            .build_lazy()
            .unwrap();
        let cache = ProxyRouteFailureCache::default();
        let connector =
            ProxyRoutesConnector::new(ProxyRouteFailureCacheConnector::new(http3, cache.clone()));
        let proxy = ProxyRoute::Proxy("http://proxy.example:8080".parse().unwrap());
        for routes in [vec![proxy.clone()], vec![proxy, ProxyRoute::Direct]] {
            for _ in 0..2 {
                let input = ConnectRequest::new("origin.example:443".parse().unwrap())
                    .with_application_protocol(Protocol::HTTPS);
                // A directly dialable target: only the route keeps the request off it.
                input
                    .extensions()
                    .insert(ConnectorTarget(HostWithPort::local_ipv4(9)));
                input
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_3));
                input.extensions().insert(ProxyRoutes::new(routes.clone()));
                let error = connector.serve(input).await.err().unwrap();
                assert_eq!(error.domain(), ConnectionErrorDomain::Local);
                assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
                assert_eq!(cache.entry_count(), 0);
            }
        }
        assert_eq!(endpoint.stats().outgoing_handshakes, 0);
        endpoint.close(0u32, b"test complete");
    }

    #[tokio::test]
    async fn profile_endpoints_reach_the_peer_and_survive_connector_drop() {
        profile_peer_exchange(false).await;
    }

    #[tokio::test]
    async fn profile_supplied_zero_cid_endpoint_survives_connector_drop() {
        profile_peer_exchange(true).await;
    }

    async fn profile_peer_exchange(supplied: bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let identity =
                ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
            let server_tls = TlsServerConfig::new()
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
                .with_server_auth(identity.clone());
            let mut server_config =
                ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
            server_config.set_capture(CaptureLimits::default());
            let server =
                Endpoint::bind_server(Executor::new(), server_config, SocketAddress::local_ipv4(0))
                    .await
                    .unwrap();
            let address = server.local_addr().unwrap();
            let count = if supplied { 1 } else { 2 };
            let accept = server.clone();
            let serve = spawn(async move {
                let mut handlers = Vec::new();
                for _ in 0..count {
                    let connection = accept
                        .accept()
                        .await
                        .unwrap()
                        .accept()
                        .unwrap()
                        .await
                        .unwrap();
                    let remote = connection.remote_address();
                    let observed = connection
                        .extensions()
                        .get_ref::<QuicObservation>()
                        .unwrap()
                        .clone();
                    let forwarded = Extensions::new();
                    forwarded.insert(Ingress(connection.extensions().clone()));
                    let outbound = TlsClientConfig::new()
                        .with_alpn_policy(AlpnPolicy::Require)
                        .with_overrides(&forwarded);
                    assert_eq!(
                        outbound.as_extensions().get_ref::<AlpnPolicy>(),
                        Some(&AlpnPolicy::Require)
                    );
                    assert!(!forwarded.contains::<AlpnPolicy>());
                    let (mut http, driver) = h3_server::handshake(
                        connection.clone(),
                        Config {
                            observation: Some(Default::default()),
                            ..Config::default()
                        },
                    )
                    .unwrap();
                    spawn(driver.run());
                    handlers.push(spawn(async move {
                        let (request, response) =
                            http.accept().await.unwrap().resolve().await.unwrap();
                        let observer = request
                            .extensions()
                            .get_ref::<H3Observer>()
                            .unwrap()
                            .clone();
                        let SettingsObservation::Received(settings) = observer
                            .settings(Instant::now() + Duration::from_secs(1))
                            .await
                        else {
                            panic!("client settings were not observed");
                        };
                        let actual: Vec<_> = settings
                            .settings
                            .as_ref()
                            .unwrap()
                            .iter()
                            .map(|setting| (setting.id, setting.value))
                            .collect();
                        assert_eq!(
                            actual,
                            [(SettingId::FIRST_RESERVED.value(), 17), (0xface, 29)]
                        );
                        response
                            .send_response(Response::new(Body::empty()))
                            .await
                            .unwrap();
                        (remote, observed, connection)
                    }));
                }
                let mut results = Vec::new();
                for handler in handlers {
                    results.push(handler.await.unwrap());
                }
                results
            });
            let tls = TlsClientConfig::new()
                .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
                .unwrap();
            let profile = QuicProfile::standard()
                .with_versions(ClientVersionPolicy::new(QuicVersion::V1).unwrap())
                .with_connection_ids(
                    ConnectionIdProfile::standard()
                        .try_with_local_len(0)
                        .unwrap(),
                )
                .with_grease_quic_bit(false)
                .try_with_limits(TransportLimits {
                    max_udp_payload_size: 1400,
                    initial_max_data: 1_234_567,
                    ..TransportLimits::standard()
                })
                .unwrap();
            let mut builder = Http3Connector::builder(Executor::new()).with_tls_config(tls);
            if supplied {
                let mut endpoint = EndpointConfig::try_with_rand_key().unwrap();
                endpoint.apply_quic_profile(&profile).unwrap();
                builder = builder.with_endpoint(
                    Endpoint::build(Executor::new())
                        .with_config(endpoint)
                        .bind_client_address(SocketAddress::local_ipv4(0))
                        .await
                        .unwrap(),
                );
            }
            let connector = builder.build_lazy().unwrap();
            let mut transports = Vec::new();
            for _ in 0..count {
                let input =
                    ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()))
                        .with_application_protocol(Protocol::HTTPS);
                input
                    .extensions()
                    .insert(ConnectorTarget(HostWithPort::local_ipv4(address.port())));
                input.extensions().insert(profile.clone());
                let mut settings = Settings::new();
                settings.set(SettingId::FIRST_RESERVED, 17).unwrap();
                settings.set(SettingId::new(0xface), 29).unwrap();
                input
                    .extensions()
                    .insert(ClientSettingsProfile(Arc::new(settings)));
                transports.push(connector.serve(input).await.unwrap().conn);
            }
            // Each established connection retains its socket through the driver;
            // neither the connector nor an endpoint-cache entry is needed now.
            drop(connector);
            let connections: Vec<_> = transports
                .iter()
                .map(|transport| transport.connection.clone())
                .collect();
            let mut senders = Vec::new();
            for transport in transports {
                let (mut sender, driver) = h3_client::handshake::<Body>(
                    transport.connection,
                    Arc::unwrap_or_clone(transport.config),
                    Executor::new(),
                )
                .unwrap();
                spawn(driver.run());
                sender
                    .send_request(
                        Request::builder()
                            .uri("https://localhost/")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                senders.push(sender);
            }
            let results = serve.await.unwrap();
            if !supplied {
                assert_ne!(results[0].0.port(), results[1].0.port());
            }
            for (_, observed, connection) in results {
                assert_eq!(observed.first_flight.as_ref().unwrap().scid_len, 0);
                assert!(
                    !observed
                        .transport_parameters
                        .iter()
                        .any(|parameter| parameter.id == TransportParameterId::GreaseQuicBit)
                );
                let max_udp = observed
                    .transport_parameters
                    .iter()
                    .find(|parameter| parameter.id == TransportParameterId::MaxUdpPayloadSize)
                    .unwrap();
                assert_eq!(
                    VarInt::decode(&mut max_udp.value.as_slice())
                        .unwrap()
                        .into_inner(),
                    1400
                );
                let max_data = observed
                    .transport_parameters
                    .iter()
                    .find(|parameter| parameter.id == TransportParameterId::InitialMaxData)
                    .unwrap();
                assert_eq!(
                    VarInt::decode(&mut max_data.value.as_slice())
                        .unwrap()
                        .into_inner(),
                    1_234_567
                );
                connection.close(0u32, b"test complete");
            }
            for connection in connections {
                connection.close(0u32, b"test complete");
            }
            drop(senders);
            server.shutdown().await;
        })
        .await
        .unwrap();
    }
}
