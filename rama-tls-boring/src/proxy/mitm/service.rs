#[cfg(feature = "http")]
use rama_core::error::BoxErrorExt;
#[cfg(feature = "http")]
use rama_core::extensions::Extensions;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    extensions::{self, ExtensionsRef},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
#[cfg(feature = "http")]
use rama_net::http::{TargetHttpVersion, Version};
use rama_net::{
    address::{Domain, Host},
    client::ConnectorTarget,
};
#[cfg(feature = "http")]
use rama_tls::ApplicationProtocol;
use rama_tls::{
    KeyLogIntent,
    client::{ClientHello, ServerVerifyMode, TlsClientConfig, TlsServerIdentity, TlsServerName},
    server::InputWithClientHello,
};
#[cfg(feature = "http")]
use rama_utils::collections::smallvec::smallvec;

#[cfg(feature = "http")]
use crate::client::BoringAlps;
use crate::{
    TlsStream,
    client::{BoringClientConfigExt, TlsConnectorData},
    proxy::{TlsMitmEgressServerAuth, TlsMitmRelay, TlsMitmRelayError},
};

#[cfg(feature = "http")]
use super::EgressAlpnRequirement;

/// Build the egress [`TlsClientConfig`] for the MITM relay from the peeked
/// ingress [`ClientHello`] (or boring defaults when none is available).
///
/// `new_from_client_hello` deliberately strips the server identity: regular
/// connectors re-derive it per-request from the transport authority. The relay
/// reaches the upstream through [`tls_connect`], which has no such fallback,
/// so the ingress SNI is re-attached here. A configured server-authentication
/// policy may additionally use the connector-target host when there is no SNI.
/// The configured policy is written last so all its explicit pieces win.
///
/// [`tls_connect`]: crate::client::tls_connect
fn egress_tls_client_config(
    client_hello: Option<&ClientHello>,
    server_name: Option<Host>,
    keylog: KeyLogIntent,
    server_auth: Option<&TlsMitmEgressServerAuth>,
) -> TlsClientConfig {
    let mut config = match client_hello {
        Some(hello) => TlsClientConfig::new_from_client_hello(hello),
        None => TlsClientConfig::new(),
    }
    .with_keylog(keylog);

    if let Some(server_name) = server_name {
        config.set_server_name(server_name);
    }

    match server_auth {
        Some(server_auth) => server_auth.write_to(&config),
        None => {
            config.set_server_verify(ServerVerifyMode::Disable);
        }
    }

    config
}

/// Apply a concrete target HTTP version only when the ingress side can use the
/// same protocol. The TLS relay is not an HTTP version adapter, so forcing an
/// incompatible ALPN would desynchronize the two sides of `HttpMitmRelay`.
///
/// A peeked ingress ClientHello without ALPN naturally falls back to HTTP/1.1,
/// so that one target remains compatible. Without a peeked ClientHello there
/// is no safe way to prove ingress compatibility, so a target is rejected.
///
#[cfg(feature = "http")]
fn apply_target_http_version(
    client_hello: Option<&ClientHello>,
    flow_extensions: &Extensions,
    config: &mut TlsClientConfig,
) -> Result<Option<EgressAlpnRequirement>, BoxError> {
    let Some(target_version) = flow_extensions.get_ref::<TargetHttpVersion>() else {
        return Ok(None);
    };

    let Some(client_hello) = client_hello else {
        return Err(BoxError::from_static_str(
            "target HTTP version requires a peeked ingress ClientHello",
        )
        .context_debug_field("target_http_version", *target_version));
    };

    let target_alpn = ApplicationProtocol::try_from(target_version.0)?;
    let ingress_alpn = client_hello.ext_alpn();
    let compatible = match ingress_alpn {
        Some(protocols) => protocols.contains(&target_alpn),
        None => target_version.0 == Version::HTTP_11,
    };
    if !compatible {
        return Err(BoxError::from_static_str(
            "target HTTP version is not compatible with ingress ClientHello ALPN",
        )
        .context_debug_field("target_http_version", *target_version)
        .context_debug_field("ingress_alpn", ingress_alpn.map(<[_]>::to_vec)));
    }

    config.set_alpn(smallvec![target_alpn.clone()]);

    if let Some((has_target, new_codepoint)) = config
        .as_extensions()
        .get_ref::<BoringAlps>()
        .map(|alps| (alps.protocols.contains(&target_alpn), alps.new_codepoint))
    {
        config.set_alps(
            if has_target {
                vec![target_alpn.clone()]
            } else {
                Vec::new()
            },
            new_codepoint,
        );
    }

    Ok(Some(EgressAlpnRequirement::new(
        target_alpn,
        target_version.0 == Version::HTTP_11,
    )))
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
    use_connector_target_fallback: bool,
) -> Option<Host> {
    sni.cloned().map(Into::into).or_else(|| {
        if use_connector_target_fallback {
            connector_target.map(|target| target.host.clone())
        } else {
            None
        }
    })
}

fn config_sni(config: &TlsClientConfig) -> Option<Domain> {
    let server_name = config.as_extensions().get_ref::<TlsServerName>()?;
    match TlsServerIdentity::try_from(&server_name.0).ok()? {
        TlsServerIdentity::Dns(domain) => Some(domain.into_owned()),
        TlsServerIdentity::Ip(_) => None,
    }
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
        // No-CH path: egress cannot mirror a fingerprint. A configured
        // authentication policy can still use the connector target for its
        // identity; legacy verification-disabled mode preserves no SNI.
        tracing::warn!(
            "tls mitm relay: BridgeIo (no ClientHello) impl invoked; \
             egress will ship boring defaults without a mirrored fingerprint"
        );

        let connector_target = connector_target(&input);
        let server_auth = self.relay.egress_server_auth_ref();
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, connector_target.as_ref(), server_auth.is_some()),
            self.relay.keylog_intent_ref().clone(),
            server_auth,
        );
        #[cfg(feature = "http")]
        let mut config = config;
        let effective_sni = config_sni(&config);
        #[cfg(feature = "http")]
        let egress_alpn_requirement =
            apply_target_http_version(None, input.extensions(), &mut config).map_err(|error| {
                TlsMitmRelayError::config(
                    error.context("tls mitm relay: apply target HTTP version without ClientHello"),
                )
                .maybe_with_connector_target(connector_target.clone())
                .maybe_with_sni(effective_sni.clone())
            })?;
        #[cfg(not(feature = "http"))]
        let egress_alpn_requirement = None;
        let connector_data = TlsConnectorData::try_from(&config).map_err(|error| {
            TlsMitmRelayError::config(
                error.context("tls mitm relay: build default egress connector data"),
            )
            .maybe_with_connector_target(connector_target.clone())
            .maybe_with_sni(effective_sni.clone())
        })?;

        let tls_input = self
            .relay
            .handshake_with_egress_alpn_requirement(
                input,
                Some(connector_data),
                egress_alpn_requirement,
            )
            .await
            .map_err(|err| {
                err.maybe_with_connector_target(connector_target)
                    .maybe_with_sni(effective_sni)
            })?;

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
        let server_auth = self.relay.egress_server_auth_ref();
        let server_name = relay_server_name(
            maybe_sni.as_ref(),
            connector_target.as_ref(),
            server_auth.is_some(),
        );
        // Split the mirror+default fallback so we can surface which
        // ClientHellos cannot be represented by BoringSSL. The fallback still
        // retains identity, relay policy, and per-flow extensions; it only
        // drops the mirrored fingerprint pieces.
        let config = egress_tls_client_config(
            Some(&client_hello),
            server_name.clone(),
            keylog.clone(),
            server_auth,
        );
        #[cfg(feature = "http")]
        let mut config = config;
        let effective_sni = config_sni(&config);
        #[cfg(feature = "http")]
        let egress_alpn_requirement =
            apply_target_http_version(Some(&client_hello), input.extensions(), &mut config)
                .map_err(|error| {
                    TlsMitmRelayError::config(
                        error.context("tls mitm relay: apply target HTTP version"),
                    )
                    .maybe_with_connector_target(connector_target.clone())
                    .maybe_with_sni(effective_sni.clone())
                })?;
        #[cfg(not(feature = "http"))]
        let egress_alpn_requirement = None;
        let connector_data = TlsConnectorData::try_from(&config)
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
                    server_auth,
                );
                #[cfg(feature = "http")]
                let mut config = config;
                #[cfg(feature = "http")]
                let _ = apply_target_http_version(
                    Some(&client_hello),
                    input.extensions(),
                    &mut config,
                )?;
                TlsConnectorData::try_from(&config)
            })
            .map_err(|error| {
                TlsMitmRelayError::config(
                    error.context("tls mitm relay: build egress connector data"),
                )
                .maybe_with_connector_target(connector_target.clone())
                .maybe_with_sni(effective_sni.clone())
            })?;

        let tls_input = self
            .relay
            .handshake_with_egress_alpn_requirement(
                input,
                Some(connector_data),
                egress_alpn_requirement,
            )
            .await
            .map_err(|err| {
                err.maybe_with_connector_target(connector_target)
                    .maybe_with_sni(effective_sni)
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
    use rama_boring::x509::store::X509StoreBuilder;
    #[cfg(feature = "http")]
    use rama_core::extensions::Extensions;
    use rama_core::{Layer, ServiceInput, service::service_fn};
    use rama_crypto::{cert::generate_server_auth, pki_types::CertificateDer};
    #[cfg(feature = "http")]
    use rama_net::http::{TargetHttpVersion, Version};
    use rama_net::{address::HostWithPort, stream::service::EchoService};
    use rama_tls::{
        ApplicationProtocol, CipherSuite, ProtocolVersion, TlsAlpn, TlsKeyLog,
        client::{
            ClientHelloExtension, ServerTrustRoots, TlsServerCertPins, TlsServerTrust,
            TlsServerVerify,
        },
        server::{GeneratedServerAuthConfig, SelfSignedCaConfig, ServerAuthData, TlsServerConfig},
    };
    use std::sync::Arc;

    #[cfg(feature = "http")]
    use crate::client::BoringAlps;
    use crate::{
        client::{BoringCipherSuites, BoringServerVerifyCertStore, tls_connect},
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
    fn configured_server_auth_enables_normal_verification() {
        let policy = TlsMitmEgressServerAuth::new().with_webpki_roots();
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build verified connector data");
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Auto);
        assert!(matches!(
            config.as_extensions().get_ref::<TlsServerVerify>(),
            Some(TlsServerVerify(ServerVerifyMode::Auto))
        ));
        let trust = config
            .as_extensions()
            .get_ref::<TlsServerTrust>()
            .expect("WebPKI trust policy");
        assert_eq!(trust.roots(), &ServerTrustRoots::WebPki);
    }

    #[test]
    fn configured_server_auth_supports_custom_and_additive_roots() {
        let custom = CertificateDer::from(vec![1, 2, 3]);
        let additional = CertificateDer::from(vec![4, 5, 6]);
        let policy = TlsMitmEgressServerAuth::new()
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
    fn configured_server_auth_can_explicitly_disable_verification() {
        let policy = TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Disable);
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build insecure connector data");
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Disable);
    }

    async fn connect_to_private_ca_with_server_name<F>(server_name: Host, make_policy: F) -> bool
    where
        F: FnOnce(CertificateDer<'static>) -> Option<TlsMitmEgressServerAuth>,
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
            Some(server_name),
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

    async fn connect_to_private_ca_with_policy<F>(make_policy: F) -> bool
    where
        F: FnOnce(CertificateDer<'static>) -> Option<TlsMitmEgressServerAuth>,
    {
        connect_to_private_ca_with_server_name(Host::from_static("localhost"), make_policy).await
    }

    #[tokio::test]
    async fn egress_policy_controls_live_certificate_verification() {
        assert!(
            connect_to_private_ca_with_policy(|_| None).await,
            "legacy no-policy mode accepts an untrusted upstream"
        );
        assert!(
            !connect_to_private_ca_with_policy(|_| {
                Some(TlsMitmEgressServerAuth::new().with_webpki_roots())
            })
            .await,
            "WebPKI policy rejects an untrusted upstream"
        );
        assert!(
            connect_to_private_ca_with_policy(|anchor| {
                Some(
                    TlsMitmEgressServerAuth::new()
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
                    TlsMitmEgressServerAuth::new()
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
                Some(TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Disable))
            })
            .await,
            "explicitly disabled verification accepts an untrusted upstream"
        );
    }

    #[tokio::test]
    async fn trusted_upstream_still_checks_the_effective_dns_identity() {
        assert!(
            connect_to_private_ca_with_server_name(Host::from_static("localhost"), |anchor| {
                Some(
                    TlsMitmEgressServerAuth::new()
                        .try_with_server_trust_anchors([anchor])
                        .unwrap(),
                )
            })
            .await,
            "trusted upstream accepts its certificate identity"
        );
        let mismatch_accepted =
            connect_to_private_ca_with_server_name(Host::from_static("wrong.example"), |anchor| {
                Some(
                    TlsMitmEgressServerAuth::new()
                        .try_with_server_trust_anchors([anchor])
                        .unwrap(),
                )
            })
            .await;
        assert!(
            !mismatch_accepted,
            "trusted upstream still rejects a hostname mismatch"
        );
    }

    #[tokio::test]
    async fn ingress_extensions_cannot_disable_verification_or_hide_fallback_identity() {
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
            .with_egress_server_auth(TlsMitmEgressServerAuth::new().with_webpki_roots());
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

        let effective_sni = Domain::from_static("localhost");
        let target = HostWithPort::new(effective_sni.clone().into(), 443);
        let ingress = ServiceInput::new(relay_ingress);
        ingress.extensions().insert(ConnectorTarget(target.clone()));
        ingress
            .extensions()
            .insert(TlsServerVerify(ServerVerifyMode::Disable));
        ingress.extensions().insert(TlsAlpn::http_1());
        let error = service
            .serve(InputWithClientHello {
                input: BridgeIo(ingress, ServiceInput::new(relay_egress)),
                client_hello: ClientHello::new(
                    ProtocolVersion::TLSv1_3,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
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
        assert_eq!(error.sni(), Some(&effective_sni));
        drop(upstream_handle.await);
    }

    #[test]
    fn no_policy_preserves_no_sni_for_a_domain_connector_target() {
        let target = HostWithPort::new(Host::from_static("target.example"), 443);
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, Some(&target), false),
            KeyLogIntent::Disabled,
            None,
        );

        let data = TlsConnectorData::try_from(&config).expect("build no-policy connector data");
        assert_eq!(data.server_name, None);
    }

    #[test]
    fn configured_server_auth_uses_connector_target_ip_as_identity() {
        let target = HostWithPort::new(Host::from(std::net::Ipv4Addr::LOCALHOST), 443);
        let policy = TlsMitmEgressServerAuth::new();
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, Some(&target), true),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build fallback connector data");
        assert_eq!(data.server_name, Some(target.host));
    }

    #[test]
    fn configured_identity_overrides_ingress_sni() {
        let ingress_sni = Domain::from_static("ingress.example");
        let policy =
            TlsMitmEgressServerAuth::new().with_server_name(Host::from_static("policy.example"));
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
    fn server_auth_policy_preserves_mirrored_fingerprint_and_keylog() {
        let mirrored_cipher = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![mirrored_cipher],
            Vec::new(),
            vec![ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            )],
        );

        let policy = TlsMitmEgressServerAuth::new().with_webpki_roots();
        let mirrored =
            egress_tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, Some(&policy));
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
        assert!(matches!(
            mirrored.as_extensions().get_ref::<TlsKeyLog>(),
            Some(TlsKeyLog(KeyLogIntent::Disabled))
        ));
    }

    #[cfg(feature = "http")]
    #[test]
    fn target_resolution_ignores_unrelated_ingress_tls_extensions() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                vec![ApplicationProtocol::HTTP_2],
            )],
        );
        let policy = TlsMitmEgressServerAuth::new();
        let config = egress_tls_client_config(
            Some(&hello),
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );
        let mut config = config;
        let flow = Extensions::new();
        flow.insert(TlsServerVerify(ServerVerifyMode::Disable));
        flow.insert(TlsAlpn::http_1());
        flow.insert(TargetHttpVersion(Version::HTTP_2));
        let requirement = apply_target_http_version(Some(&hello), &flow, &mut config)
            .expect("unrelated ingress extensions are ignored");
        assert!(requirement.is_some());

        let data = TlsConnectorData::try_from(&config).expect("build connector data");
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Auto);
        assert_eq!(
            config
                .as_extensions()
                .get_ref::<TlsAlpn>()
                .map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_2].as_slice())
        );
    }

    #[test]
    fn server_auth_policy_carries_pins_and_boring_store() {
        let pins = TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]));
        let store = Arc::new(X509StoreBuilder::new().unwrap().build());
        let policy = TlsMitmEgressServerAuth::new()
            .with_server_cert_pins(pins)
            .with_server_verify_cert_store(store);
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        assert!(
            config
                .as_extensions()
                .get_ref::<TlsServerCertPins>()
                .is_some()
        );
        assert!(
            config
                .as_extensions()
                .get_ref::<BoringServerVerifyCertStore>()
                .is_some()
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn target_http_version_forces_the_final_alpn_offer() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11,
                ]),
                ClientHelloExtension::ApplicationSettings {
                    protocols: vec![ApplicationProtocol::HTTP_2],
                    new_codepoint: true,
                },
            ],
        );
        for (version, expected_alpn, expected_alps, allow_no_alpn) in [
            (
                Version::HTTP_11,
                ApplicationProtocol::HTTP_11,
                Vec::new(),
                true,
            ),
            (
                Version::HTTP_2,
                ApplicationProtocol::HTTP_2,
                vec![ApplicationProtocol::HTTP_2],
                false,
            ),
        ] {
            let mut config = egress_tls_client_config(
                Some(&hello),
                Some(Host::from_static("example.com")),
                KeyLogIntent::Disabled,
                None,
            );
            let flow = Extensions::new();
            flow.insert(TargetHttpVersion(version));
            let requirement = apply_target_http_version(Some(&hello), &flow, &mut config)
                .expect("resolve compatible forced HTTP ALPN")
                .expect("target creates an egress ALPN requirement");

            assert_eq!(
                config
                    .as_extensions()
                    .get_ref::<TlsAlpn>()
                    .map(|alpn| alpn.0.as_slice()),
                Some([expected_alpn.clone()].as_slice())
            );
            assert_eq!(
                config
                    .as_extensions()
                    .get_ref::<BoringAlps>()
                    .map(|alps| (alps.protocols.as_slice(), alps.new_codepoint)),
                Some((expected_alps.as_slice(), true))
            );
            assert!(requirement.is_satisfied_by(Some(&expected_alpn)));
            assert_eq!(requirement.is_satisfied_by(None), allow_no_alpn);
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn incompatible_target_http_version_is_rejected() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                vec![ApplicationProtocol::HTTP_11],
            )],
        );
        let flow = Extensions::new();
        flow.insert(TargetHttpVersion(Version::HTTP_2));
        let mut config = egress_tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, None);

        let error = apply_target_http_version(Some(&hello), &flow, &mut config)
            .expect_err("HTTP/2 was not offered by ingress");
        assert!(error.to_string().contains("not compatible"));
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn service_rejects_target_without_a_peeked_client_hello() {
        let relay = TlsMitmRelay::try_new_with_self_signed_issuer(&SelfSignedCaConfig::default())
            .expect("build MITM relay");
        let inner = service_fn(
            |_: BridgeIo<
                TlsStream<ServiceInput<tokio::io::DuplexStream>>,
                TlsStream<ServiceInput<tokio::io::DuplexStream>>,
            >| async { Ok::<(), BoxError>(()) },
        );
        let service = TlsMitmRelayService::new(relay, inner);
        let (_client_io, relay_ingress) = tokio::io::duplex(1024);
        let (relay_egress, _upstream_io) = tokio::io::duplex(1024);
        let ingress = ServiceInput::new(relay_ingress);
        ingress
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));

        let error = service
            .serve(BridgeIo(ingress, ServiceInput::new(relay_egress)))
            .await
            .expect_err("a target requires a peeked ClientHello");
        assert_eq!(error.kind(), TlsMitmRelayErrorKind::Config);
        assert!(error.to_string().contains("requires a peeked"));
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn service_rejects_incompatible_target_before_handshake() {
        let relay = TlsMitmRelay::try_new_with_self_signed_issuer(&SelfSignedCaConfig::default())
            .expect("build MITM relay");
        let inner = service_fn(
            |_: BridgeIo<
                TlsStream<ServiceInput<tokio::io::DuplexStream>>,
                TlsStream<ServiceInput<tokio::io::DuplexStream>>,
            >| async { Ok::<(), BoxError>(()) },
        );
        let service = TlsMitmRelayService::new(relay, inner);
        let (_client_io, relay_ingress) = tokio::io::duplex(1024);
        let (relay_egress, _upstream_io) = tokio::io::duplex(1024);
        let ingress = ServiceInput::new(relay_ingress);
        ingress
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        let client_hello = ClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                vec![ApplicationProtocol::HTTP_11],
            )],
        );

        let error = service
            .serve(InputWithClientHello {
                input: BridgeIo(ingress, ServiceInput::new(relay_egress)),
                client_hello,
            })
            .await
            .expect_err("incompatible target must fail before either TLS handshake");
        assert_eq!(error.kind(), TlsMitmRelayErrorKind::Config);
        assert!(error.to_string().contains("not compatible"));
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn service_rejects_upstream_that_declines_required_http2_alpn() {
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
            .expect("build MITM relay");
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
        let ingress = ServiceInput::new(relay_ingress);
        ingress
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        let client_hello = ClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                vec![ApplicationProtocol::HTTP_2],
            )],
        );

        let error = service
            .serve(InputWithClientHello {
                input: BridgeIo(ingress, ServiceInput::new(relay_egress)),
                client_hello,
            })
            .await
            .expect_err("upstream must negotiate forced HTTP/2 before ingress handshake");
        assert_eq!(
            error.kind(),
            TlsMitmRelayErrorKind::Handshake {
                direction: TlsMitmRelayErrorDirection::Egress,
                classification: HandshakeRelayClassification::TlsProtocol,
            }
        );
        assert!(error.to_string().contains("required ALPN"));
        drop(upstream_handle.await);
    }

    #[cfg(feature = "http")]
    #[test]
    fn no_alpn_client_hello_can_target_http1_only() {
        let hello = ClientHello::new(ProtocolVersion::TLSv1_2, Vec::new(), Vec::new(), Vec::new());
        for (version, should_succeed) in [(Version::HTTP_11, true), (Version::HTTP_2, false)] {
            let flow = Extensions::new();
            flow.insert(TargetHttpVersion(version));
            let mut config =
                egress_tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, None);
            assert_eq!(
                apply_target_http_version(Some(&hello), &flow, &mut config).is_ok(),
                should_succeed
            );
        }
    }
}
