use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    extensions::{self, Extensions, ExtensionsRef},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::{
    address::{Domain, Host},
    client::ConnectorTarget,
};
use rama_tls::{
    KeyLogIntent,
    client::{ClientHello, ServerVerifyMode, TlsClientConfig},
    server::InputWithClientHello,
};

use crate::{
    TlsStream,
    client::{BoringClientConfigExt, BoringTlsConnectorConfig, TlsConnectorData},
    proxy::{TlsMitmRelay, TlsMitmRelayError},
};

/// Build the egress [`TlsClientConfig`] for the MITM relay from the peeked
/// ingress [`ClientHello`] (or boring defaults when none is available).
///
/// `new_from_client_hello` deliberately strips the server identity: regular
/// connectors re-derive it per-request from the transport authority. The relay
/// reaches the upstream through [`tls_connect`], which has no such fallback,
/// so the ingress SNI (or connector-target host) is re-attached here. The
/// configured policy is written last so all its explicit pieces win.
///
/// [`tls_connect`]: crate::client::tls_connect
fn egress_tls_client_config(
    client_hello: Option<&ClientHello>,
    server_name: Option<Host>,
    keylog: KeyLogIntent,
    policy: Option<&TlsClientConfig>,
) -> TlsClientConfig {
    let mut config = match client_hello {
        Some(hello) => TlsClientConfig::new_from_client_hello(hello),
        None => TlsClientConfig::new(),
    }
    .with_keylog(keylog);

    if let Some(server_name) = server_name {
        config.set_server_name(server_name);
    }

    match policy {
        Some(policy) => policy.write_to(config.as_extensions()),
        None => {
            config.set_server_verify(ServerVerifyMode::Disable);
        }
    }

    config
}

/// Apply the flow's extensions over the derived relay config, then resolve
/// forced HTTP ALPN last just like the normal BoringSSL connector path.
fn egress_tls_extensions(
    flow_extensions: &Extensions,
    config: &TlsClientConfig,
) -> Result<Extensions, BoxError> {
    let extensions = flow_extensions.with_base(config.as_extensions());
    #[cfg(feature = "http")]
    crate::client::resolve_http_alpn(&extensions)?;
    Ok(extensions)
}

fn connector_target(input: &impl ExtensionsRef) -> Option<rama_net::address::HostWithPort> {
    input
        .extensions()
        .get_ref()
        .map(|ConnectorTarget(target)| target.clone())
}

fn relay_server_name(
    sni: Option<&Domain>,
    connector_target: Option<&rama_net::address::HostWithPort>,
) -> Option<Host> {
    sni.cloned()
        .map(Into::into)
        .or_else(|| connector_target.map(|target| target.host.clone()))
}

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay (and MITM a TLS connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct TlsMitmRelayService<Issuer, Inner> {
    relay: TlsMitmRelay<Issuer>,
    inner: Inner,
}

impl<Issuer, Inner> TlsMitmRelayService<Issuer, Inner> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`TlsMitmRelayService`] which is ready to serve,
    /// bridged Io streams. It's a [`Service`] (layer) implementation
    /// on top of [`TlsMitmRelay`].
    pub fn new(relay: TlsMitmRelay<Issuer>, inner: Inner) -> Self {
        Self { relay, inner }
    }
}

impl<Issuer, Inner, Ingress, Egress> Service<BridgeIo<Ingress, Egress>>
    for TlsMitmRelayService<Issuer, Inner>
where
    Issuer: super::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
    Inner: Service<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    type Output = ();
    type Error = TlsMitmRelayError;

    async fn serve(&self, input: BridgeIo<Ingress, Egress>) -> Result<Self::Output, Self::Error> {
        // No-CH path: egress cannot mirror a fingerprint, but it can still use
        // the connector target for identity and apply relay/flow policy.
        tracing::warn!(
            "tls mitm relay: BridgeIo (no ClientHello) impl invoked; \
             egress will ship boring defaults without a mirrored fingerprint"
        );

        let connector_target = connector_target(&input);
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, connector_target.as_ref()),
            self.relay.keylog_intent_ref().clone(),
            self.relay.egress_tls_config_ref(),
        );
        let extensions = egress_tls_extensions(input.extensions(), &config).map_err(|error| {
            TlsMitmRelayError::config(
                error.context("tls mitm relay: resolve default egress TLS policy"),
            )
            .maybe_with_connector_target(connector_target.clone())
        })?;
        let connector_data =
            TlsConnectorData::try_from(BoringTlsConnectorConfig::from_extensions(&extensions))
                .map_err(|error| {
                    TlsMitmRelayError::config(
                        error.context("tls mitm relay: build default egress connector data"),
                    )
                    .maybe_with_connector_target(connector_target.clone())
                })?;

        let tls_input = self
            .relay
            .handshake(input, Some(connector_data))
            .await
            .map_err(|err| err.maybe_with_connector_target(connector_target))?;

        self.inner
            .serve(tls_input)
            .await
            .map(drop)
            .map_err(TlsMitmRelayError::tls_serve)
    }
}

impl<Issuer, Inner, Ingress, Egress> Service<InputWithClientHello<BridgeIo<Ingress, Egress>>>
    for TlsMitmRelayService<Issuer, Inner>
where
    Issuer: super::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
    Inner: Service<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, Error: Into<BoxError>>,
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    type Output = ();
    type Error = TlsMitmRelayError;

    async fn serve(
        &self,
        InputWithClientHello {
            input,
            client_hello,
        }: InputWithClientHello<BridgeIo<Ingress, Egress>>,
    ) -> Result<Self::Output, Self::Error> {
        // TODO: in future have flow that works for SNI
        // as well as ECH target data??? If not already...
        let maybe_sni = client_hello.ext_server_name().cloned();
        let keylog = self.relay.keylog_intent_ref().clone();
        let connector_target = connector_target(&input);
        let server_name = relay_server_name(maybe_sni.as_ref(), connector_target.as_ref());
        // Split the mirror+default fallback so we can surface which
        // ClientHellos cannot be represented by BoringSSL. The fallback still
        // retains identity, relay policy, and per-flow extensions; it only
        // drops the mirrored fingerprint pieces.
        let config = egress_tls_client_config(
            Some(&client_hello),
            server_name.clone(),
            keylog.clone(),
            self.relay.egress_tls_config_ref(),
        );
        let extensions = egress_tls_extensions(input.extensions(), &config).map_err(|error| {
            TlsMitmRelayError::config(error.context("tls mitm relay: resolve egress TLS policy"))
                .maybe_with_connector_target(connector_target.clone())
                .maybe_with_sni(maybe_sni.clone())
        })?;
        let connector_data =
            TlsConnectorData::try_from(BoringTlsConnectorConfig::from_extensions(&extensions))
            .or_else(|err| {
                tracing::warn!(
                    ?maybe_sni,
                    %err,
                    "tls mitm relay: build TlsConnectorData from ClientHello failed; falling back without mirrored fingerprint"
                );
                let config = egress_tls_client_config(
                    None,
                    server_name,
                    keylog,
                    self.relay.egress_tls_config_ref(),
                );
                let extensions = egress_tls_extensions(input.extensions(), &config)?;
                TlsConnectorData::try_from(BoringTlsConnectorConfig::from_extensions(&extensions))
            })
            .map_err(|error| {
                TlsMitmRelayError::config(
                    error.context("tls mitm relay: build egress connector data"),
                )
                .maybe_with_connector_target(connector_target.clone())
                .maybe_with_sni(maybe_sni.clone())
            })?;

        let tls_input = self
            .relay
            .handshake(input, Some(connector_data))
            .await
            .map_err(|err| {
                err.maybe_with_connector_target(connector_target)
                    .maybe_with_sni(maybe_sni.clone())
            })?;

        tracing::debug!(
            "tls MITM relay handshake for SNI={maybe_sni:?} is complete... continue to serve tls tunnel bridge from within..."
        );

        self.inner
            .serve(tls_input)
            .await
            .map(drop)
            .map_err(TlsMitmRelayError::tls_serve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{Layer, ServiceInput, extensions::Extensions, service::service_fn};
    use rama_crypto::{cert::generate_server_auth, pki_types::CertificateDer};
    #[cfg(feature = "http")]
    use rama_net::http::{TargetHttpVersion, Version};
    use rama_net::{address::HostWithPort, stream::service::EchoService};
    use rama_tls::{
        ApplicationProtocol, CipherSuite, ProtocolVersion, TlsAlpn,
        client::{ClientHelloExtension, ServerTrustRoots, TlsServerTrust, TlsServerVerify},
        server::{GeneratedServerAuthConfig, SelfSignedCaConfig, ServerAuthData, TlsServerConfig},
    };

    use crate::{
        client::{BoringCipherSuites, tls_connect},
        proxy::mitm::{
            HandshakeRelayClassification, TlsMitmRelayErrorDirection, TlsMitmRelayErrorKind,
        },
        server::TlsAcceptorLayer,
    };

    fn hello_with_sni(sni: &Domain) -> ClientHello {
        ClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ServerName(Some(sni.clone()))],
        )
    }

    // Regression (boring extensions refactor): `new_from_client_hello`
    // strips the SNI and the relay's `tls_connect` path can't re-derive it
    // from a transport authority, so the egress config MUST carry the peeked
    // SNI or the upstream gets an SNI-less hello (wrong cert / handshake
    // failure). Pin that the egress connector data keeps the ingress SNI.
    #[test]
    fn egress_config_carries_ingress_sni() {
        let sni = Domain::from_static("example.com");
        let hello = hello_with_sni(&sni);

        let config = egress_tls_client_config(
            Some(&hello),
            Some(sni.clone().into()),
            KeyLogIntent::Disabled,
            None,
        );
        let data = TlsConnectorData::try_from(&config).expect("build egress connector data");
        assert_eq!(data.server_name, Some(sni.into()));
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Disable);

        // Guard the contract the re-attach compensates for: the config taken
        // straight from the hello carries no SNI on its own.
        let stripped = TlsClientConfig::new_from_client_hello(&hello);
        let stripped_data =
            TlsConnectorData::try_from(&stripped).expect("build stripped connector data");
        assert_eq!(stripped_data.server_name, None);
    }

    #[test]
    fn configured_policy_enables_normal_verification() {
        let policy = TlsClientConfig::new().with_webpki_roots();
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build verified connector data");
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Auto);
        let trust = config
            .as_extensions()
            .get_ref::<TlsServerTrust>()
            .expect("WebPKI trust policy");
        assert_eq!(trust.roots(), &ServerTrustRoots::WebPki);
    }

    #[test]
    fn configured_policy_supports_custom_and_additive_roots() {
        let custom = CertificateDer::from(vec![1, 2, 3]);
        let additional = CertificateDer::from(vec![4, 5, 6]);
        let policy = TlsClientConfig::new()
            .try_with_server_trust_anchors([custom.clone()])
            .unwrap()
            .try_with_extra_server_trust_anchors([additional.clone()])
            .unwrap();
        let config = egress_tls_client_config(None, None, KeyLogIntent::Disabled, Some(&policy));

        let trust = config
            .as_extensions()
            .get_ref::<TlsServerTrust>()
            .expect("custom trust policy");
        let ServerTrustRoots::Custom(anchors) = trust.roots() else {
            panic!("expected custom roots");
        };
        assert_eq!(anchors.certificates(), &[custom]);
        assert_eq!(
            trust
                .additional_anchors()
                .expect("additional roots")
                .certificates(),
            &[additional]
        );
    }

    #[test]
    fn configured_policy_can_explicitly_disable_verification() {
        let policy = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build insecure connector data");
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Disable);
    }

    async fn connect_to_private_ca_with_policy<F>(make_policy: F) -> bool
    where
        F: FnOnce(CertificateDer<'static>) -> Option<TlsClientConfig>,
    {
        let (cert_chain, private_key) = generate_server_auth(GeneratedServerAuthConfig::default())
            .expect("generate private upstream identity");
        let trust_anchor = cert_chain.last().expect("certificate chain").clone();
        let server =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());

        let policy = make_policy(trust_anchor);
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("localhost")),
            KeyLogIntent::Disabled,
            policy.as_ref(),
        );
        let connector_data =
            TlsConnectorData::try_from(&config).expect("build egress connector data");
        let (client_io, server_io) = tokio::io::duplex(usize::MAX);
        let server_handle =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        let connected = match tls_connect(ServiceInput::new(client_io), Some(connector_data)).await
        {
            Ok(stream) => {
                drop(stream);
                true
            }
            Err(_) => false,
        };
        drop(server_handle.await);
        connected
    }

    #[tokio::test]
    async fn egress_policy_controls_live_certificate_verification() {
        assert!(
            connect_to_private_ca_with_policy(|_| None).await,
            "legacy no-policy mode accepts an untrusted upstream"
        );
        assert!(
            !connect_to_private_ca_with_policy(|_| {
                Some(TlsClientConfig::new().with_webpki_roots())
            })
            .await,
            "WebPKI policy rejects an untrusted upstream"
        );
        assert!(
            connect_to_private_ca_with_policy(|anchor| {
                Some(
                    TlsClientConfig::new()
                        .try_with_server_trust_anchors([anchor])
                        .unwrap(),
                )
            })
            .await,
            "custom trust anchors accept their upstream"
        );
        assert!(
            connect_to_private_ca_with_policy(|anchor| {
                Some(
                    TlsClientConfig::new()
                        .with_webpki_roots()
                        .try_with_extra_server_trust_anchors([anchor])
                        .unwrap(),
                )
            })
            .await,
            "additive trust anchors accept their upstream"
        );
        assert!(
            connect_to_private_ca_with_policy(|_| {
                Some(TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable))
            })
            .await,
            "explicitly disabled verification accepts an untrusted upstream"
        );
    }

    #[tokio::test]
    async fn verification_failure_keeps_relay_classification_and_context() {
        let (cert_chain, private_key) = generate_server_auth(GeneratedServerAuthConfig::default())
            .expect("generate private upstream identity");
        let upstream =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());

        let relay = TlsMitmRelay::try_new_with_self_signed_issuer(&SelfSignedCaConfig::default())
            .expect("build MITM relay")
            .with_egress_tls_config(TlsClientConfig::new().with_webpki_roots());
        let inner = service_fn(
            |_: BridgeIo<
                TlsStream<ServiceInput<tokio::io::DuplexStream>>,
                TlsStream<ServiceInput<tokio::io::DuplexStream>>,
            >| async { Ok::<(), BoxError>(()) },
        );
        let service = TlsMitmRelayService::new(relay, inner);

        let (_client_io, relay_ingress) = tokio::io::duplex(usize::MAX);
        let (relay_egress, upstream_io) = tokio::io::duplex(usize::MAX);
        let upstream_handle =
            tokio::spawn(async move { upstream.serve(ServiceInput::new(upstream_io)).await });

        let sni = Domain::from_static("localhost");
        let target = HostWithPort::new(Host::from_static("target.example"), 443);
        let ingress = ServiceInput::new(relay_ingress);
        ingress.extensions().insert(ConnectorTarget(target.clone()));
        let error = service
            .serve(InputWithClientHello {
                input: BridgeIo(ingress, ServiceInput::new(relay_egress)),
                client_hello: hello_with_sni(&sni),
            })
            .await
            .expect_err("private upstream must fail WebPKI verification");

        assert_eq!(
            error.kind(),
            TlsMitmRelayErrorKind::Handshake {
                direction: TlsMitmRelayErrorDirection::Egress,
                classification: HandshakeRelayClassification::CertTrust,
            }
        );
        assert_eq!(error.connector_target(), Some(&target));
        assert_eq!(error.sni(), Some(&sni));
        drop(upstream_handle.await);
    }

    #[test]
    fn connector_target_ip_is_the_no_sni_identity_fallback() {
        let target = HostWithPort::new(Host::from(std::net::Ipv4Addr::LOCALHOST), 443);
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, Some(&target)),
            KeyLogIntent::Disabled,
            None,
        );

        let data = TlsConnectorData::try_from(&config).expect("build fallback connector data");
        assert_eq!(data.server_name, Some(target.host));
    }

    #[test]
    fn configured_identity_overrides_ingress_sni() {
        let ingress_sni = Domain::from_static("ingress.example");
        let policy = TlsClientConfig::new().with_server_name(Host::from_static("policy.example"));
        let config = egress_tls_client_config(
            Some(&hello_with_sni(&ingress_sni)),
            Some(ingress_sni.into()),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build connector data");
        assert_eq!(data.server_name, Some(Host::from_static("policy.example")));
    }

    #[test]
    fn mirrored_fingerprint_is_preserved_unless_policy_overrides_it() {
        let mirrored_cipher = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let policy_cipher = CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![mirrored_cipher],
            Vec::new(),
            vec![ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            )],
        );

        let mirrored = egress_tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, None);
        assert_eq!(
            mirrored
                .as_extensions()
                .get_ref::<BoringCipherSuites>()
                .map(|suites| suites.0.as_slice()),
            Some([mirrored_cipher].as_slice())
        );
        assert_eq!(
            mirrored
                .as_extensions()
                .get_ref::<TlsAlpn>()
                .map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11].as_slice())
        );

        let policy = TlsClientConfig::new()
            .with_cipher_suites(vec![policy_cipher])
            .with_alpn_http_1();
        let overridden =
            egress_tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, Some(&policy));
        assert_eq!(
            overridden
                .as_extensions()
                .get_ref::<BoringCipherSuites>()
                .map(|suites| suites.0.as_slice()),
            Some([policy_cipher].as_slice())
        );
        assert_eq!(
            overridden
                .as_extensions()
                .get_ref::<TlsAlpn>()
                .map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_11].as_slice())
        );
    }

    #[test]
    fn per_flow_extensions_override_the_static_policy() {
        let policy = TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .with_alpn_http_2();
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );
        let flow = Extensions::new();
        flow.insert(TlsServerVerify(ServerVerifyMode::Disable));
        flow.insert(TlsAlpn::http_1());
        let extensions = egress_tls_extensions(&flow, &config).expect("compose egress policy");

        assert_eq!(
            extensions
                .get_ref::<TlsServerVerify>()
                .map(|verify| verify.0),
            Some(ServerVerifyMode::Disable)
        );
        assert_eq!(
            extensions
                .get_ref::<TlsAlpn>()
                .map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_11].as_slice())
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn target_http_version_forces_the_final_alpn_offer() {
        for (version, expected) in [
            (Version::HTTP_11, ApplicationProtocol::HTTP_11),
            (Version::HTTP_2, ApplicationProtocol::HTTP_2),
        ] {
            let policy = TlsClientConfig::new().with_alpn_http_auto();
            let config = egress_tls_client_config(
                None,
                Some(Host::from_static("example.com")),
                KeyLogIntent::Disabled,
                Some(&policy),
            );
            let flow = Extensions::new();
            flow.insert(TargetHttpVersion(version));
            let extensions =
                egress_tls_extensions(&flow, &config).expect("resolve forced HTTP ALPN");

            assert_eq!(
                extensions
                    .get_ref::<TlsAlpn>()
                    .map(|alpn| alpn.0.as_slice()),
                Some([expected].as_slice())
            );
        }
    }
}
