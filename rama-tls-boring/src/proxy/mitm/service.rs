use crate::{
    TlsStream,
    client::TlsConnectorData,
    proxy::{TlsMitmRelay, TlsMitmRelayError},
};
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    extensions::{self, ExtensionsRef},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::{address::Domain, client::ConnectorTarget};
use rama_tls::{
    client::{ClientHello, TlsClientConfig, TlsServerName},
    server::InputWithClientHello,
};

#[cfg(feature = "http")]
use {
    crate::client::{AlpsCoupling, set_alpn_with_coupled_alps},
    rama_core::extensions::Extensions,
    rama_net::http::{TargetHttpVersion, Version},
    rama_tls::ApplicationProtocol,
};

use super::egress::{
    server_name as relay_server_name, tls_client_config as egress_tls_client_config,
};

/// Prefer a concrete target HTTP version only when the ingress side can use the
/// same protocol. The TLS relay is not an HTTP version adapter, so the
/// intercepted client's capabilities remain authoritative.
///
/// A peeked ingress ClientHello without ALPN naturally falls back to HTTP/1.1,
/// so that one preference remains compatible. A preference is ignored when no
/// ClientHello was peeked or the client did not offer the requested protocol.
///
/// When applicable, ALPN and ALPS are narrowed together by
/// [`set_alpn_with_coupled_alps`], which retains mirrored ALPS only for the
/// selected protocol.
#[cfg(feature = "http")]
fn apply_target_http_version(
    client_hello: Option<&ClientHello>,
    flow_extensions: &Extensions,
    config: &TlsClientConfig,
) {
    let Some(target_version) = flow_extensions.get_ref::<TargetHttpVersion>() else {
        return;
    };

    let Some(client_hello) = client_hello else {
        tracing::debug!(
            ?target_version,
            "ignoring preferred target HTTP version without a peeked ingress ClientHello"
        );
        return;
    };

    let target_alpn = match ApplicationProtocol::try_from(target_version.0) {
        Ok(protocol) => protocol,
        Err(error) => {
            tracing::debug!(
                ?target_version,
                %error,
                "ignoring target HTTP version without a corresponding TLS ALPN protocol"
            );
            return;
        }
    };
    let ingress_alpn = client_hello.ext_alpn();
    let compatible = match ingress_alpn {
        Some(protocols) => protocols.contains(&target_alpn),
        None => target_version.0 == Version::HTTP_11,
    };
    if !compatible {
        tracing::debug!(
            ?target_version,
            ?ingress_alpn,
            "ignoring target HTTP version incompatible with ingress ClientHello ALPN"
        );
        return;
    }

    // Compatibility above proves that narrowing the offer does not invent a
    // capability which was absent from the intercepted ClientHello.
    if set_alpn_with_coupled_alps(config.as_extensions(), target_alpn) == AlpsCoupling::Suppressed {
        tracing::debug!(
            ?target_version,
            "suppressing mirrored ALPS unsupported for preferred ALPN protocol"
        );
    }
}

fn connector_target(input: &impl ExtensionsRef) -> Option<rama_net::address::HostWithPort> {
    input
        .extensions()
        .get_ref()
        .map(|ConnectorTarget(target)| target.clone())
}

fn config_sni(config: &TlsClientConfig) -> Option<Domain> {
    let server_name = config.as_extensions().get_ref::<TlsServerName>()?;
    super::server_name_as_sni(&server_name.0)
}

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay (and MITM a TLS connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
///
/// Normal transparent-proxy stacks wrap this service in
/// [`rama_tls::server::PeekTlsClientHelloService`], which invokes the
/// [`InputWithClientHello`] implementation. The plain [`BridgeIo`] service
/// implementation remains available for direct callers that do not install a
/// ClientHello peeker; that fallback cannot mirror ClientHello-only details.
pub struct TlsMitmRelayService<Issuer, Inner> {
    relay: TlsMitmRelay<Issuer>,
    inner: Inner,
}

struct PreparedEgress {
    connector_data: TlsConnectorData,
    connector_target: Option<rama_net::address::HostWithPort>,
    effective_sni: Option<Domain>,
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

    fn prepare_egress<Ingress, Egress>(
        &self,
        input: &BridgeIo<Ingress, Egress>,
        client_hello: Option<&ClientHello>,
    ) -> Result<PreparedEgress, TlsMitmRelayError>
    where
        Ingress: extensions::ExtensionsRef,
    {
        let maybe_sni = client_hello.and_then(ClientHello::ext_server_name).cloned();
        let connector_target = connector_target(input);
        let server_auth = self.relay.egress_server_auth_ref();
        let server_name =
            relay_server_name(maybe_sni.as_ref(), connector_target.as_ref(), server_auth);
        let keylog = self.relay.keylog_intent_ref().clone();

        let config = egress_tls_client_config(
            client_hello,
            server_name.clone(),
            keylog.clone(),
            server_auth,
        );
        #[cfg(feature = "http")]
        apply_target_http_version(client_hello, input.extensions(), &config);
        let effective_sni = config_sni(&config);

        let connector_data = match TlsConnectorData::try_from(&config) {
            Ok(data) => Ok(data),
            Err(error) if client_hello.is_some() => {
                tracing::warn!(
                    ?maybe_sni,
                    %error,
                    "tls mitm relay: build TlsConnectorData from ClientHello failed; falling back without mirrored fingerprint"
                );
                // Keep identity, relay policy, and per-flow preferences; only
                // discard fingerprint pieces which BoringSSL could not model.
                let fallback =
                    egress_tls_client_config(None, server_name, keylog, server_auth);
                #[cfg(feature = "http")]
                apply_target_http_version(client_hello, input.extensions(), &fallback);
                TlsConnectorData::try_from(&fallback)
            }
            Err(error) => Err(error),
        }
        .map_err(|error| {
            TlsMitmRelayError::config(
                error.context("tls mitm relay: build egress connector data"),
            )
            .maybe_with_connector_target(connector_target.clone())
            .maybe_with_sni(effective_sni.clone())
        })?;

        Ok(PreparedEgress {
            connector_data,
            connector_target,
            effective_sni,
        })
    }

    async fn serve_bridge<Ingress, Egress>(
        &self,
        input: BridgeIo<Ingress, Egress>,
        client_hello: Option<&ClientHello>,
    ) -> Result<(), TlsMitmRelayError>
    where
        Issuer: super::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
        Inner: Service<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, Error: Into<BoxError>>,
        Ingress: Io + Unpin + extensions::ExtensionsRef,
        Egress: Io + Unpin + extensions::ExtensionsRef,
    {
        let PreparedEgress {
            connector_data,
            connector_target,
            effective_sni,
        } = self.prepare_egress(&input, client_hello)?;

        let tls_input = self
            .relay
            .handshake(input, Some(connector_data))
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

        self.serve_bridge(input, None).await
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
        self.serve_bridge(input, Some(&client_hello)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_boring::x509::store::X509StoreBuilder;
    use rama_core::{Layer, ServiceInput, service::service_fn};
    use rama_crypto::{cert::generate_server_auth, pki_types::CertificateDer};
    use rama_net::{
        address::{Host, HostWithPort},
        stream::service::EchoService,
    };
    use rama_tls::{
        ApplicationProtocol, CipherSuite, KeyLogIntent, ProtocolVersion, TlsAlpn, TlsKeyLog,
        client::{
            ClientHelloExtension, ServerTrustRoots, ServerVerifyMode, TlsServerCertPins,
            TlsServerTrust, TlsServerVerify,
        },
        server::{GeneratedServerAuthConfig, SelfSignedCaConfig, ServerAuthData, TlsServerConfig},
    };
    use std::sync::Arc;

    use crate::{
        client::{
            BoringCipherSuites, BoringClientConfigExt as _, BoringServerVerifyCertStore,
            tls_connect,
        },
        proxy::mitm::{
            HandshakeRelayClassification, TlsMitmEgressServerAuth, TlsMitmRelayErrorDirection,
            TlsMitmRelayErrorKind,
        },
        server::TlsAcceptorLayer,
    };
    #[cfg(feature = "http")]
    use {
        crate::client::BoringAlps,
        rama_core::extensions::Extensions,
        rama_net::http::{TargetHttpVersion, Version},
        rama_tls::server::peek_client_hello_from_input,
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
        let policy = TlsMitmEgressServerAuth::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .with_webpki_roots();
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
    fn configured_server_auth_defaults_to_disabled_verification() {
        let policy = TlsMitmEgressServerAuth::new();
        let config = egress_tls_client_config(
            None,
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build insecure connector data");
        assert_eq!(data.server_verify_mode, ServerVerifyMode::Disable);
        assert!(matches!(
            config.as_extensions().get_ref::<TlsServerVerify>(),
            Some(TlsServerVerify(ServerVerifyMode::Disable))
        ));
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
            connect_to_private_ca_with_policy(|_| Some(TlsMitmEgressServerAuth::new())).await,
            "default server-auth policy accepts an untrusted upstream"
        );
        assert!(
            !connect_to_private_ca_with_policy(|_| {
                Some(
                    TlsMitmEgressServerAuth::new()
                        .with_server_verify(ServerVerifyMode::Auto)
                        .with_webpki_roots(),
                )
            })
            .await,
            "WebPKI policy rejects an untrusted upstream"
        );
        assert!(
            connect_to_private_ca_with_policy(|anchor| {
                Some(
                    TlsMitmEgressServerAuth::new()
                        .with_server_verify(ServerVerifyMode::Auto)
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
                        .with_server_verify(ServerVerifyMode::Auto)
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
    async fn direct_handshake_derives_the_relay_server_auth_policy() {
        let (cert_chain, private_key) = generate_server_auth(GeneratedServerAuthConfig::default())
            .expect("generate private upstream identity");
        let trust_anchor = cert_chain.last().expect("certificate chain").clone();
        let upstream =
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }))
            .into_layer(EchoService::new());

        let relay = TlsMitmRelay::try_new_with_self_signed_issuer(&SelfSignedCaConfig::default())
            .expect("build MITM relay")
            .with_keylog_intent(KeyLogIntent::Disabled)
            .with_egress_server_auth(
                TlsMitmEgressServerAuth::new()
                    .with_server_verify(ServerVerifyMode::Auto)
                    .try_with_server_trust_anchors([trust_anchor])
                    .expect("configure private upstream trust"),
            );

        let (client_io, relay_ingress_io) = tokio::io::duplex(usize::MAX);
        let (relay_egress_io, upstream_io) = tokio::io::duplex(usize::MAX);
        let upstream_handle =
            tokio::spawn(async move { upstream.serve(ServiceInput::new(upstream_io)).await });

        let relay_ingress = ServiceInput::new(relay_ingress_io);
        relay_ingress
            .extensions()
            .insert(ConnectorTarget(HostWithPort::new(
                Host::from_static("localhost"),
                443,
            )));
        let ingress_connector_data = TlsConnectorData::try_from(
            &TlsClientConfig::new()
                .with_server_verify(ServerVerifyMode::Disable)
                .with_keylog(KeyLogIntent::Disabled),
        )
        .expect("build ingress TLS client config");

        let (relay_result, ingress_result) = tokio::join!(
            relay.handshake(
                BridgeIo(relay_ingress, ServiceInput::new(relay_egress_io),),
                None,
            ),
            tls_connect(ServiceInput::new(client_io), Some(ingress_connector_data)),
        );

        let bridged = relay_result
            .expect("direct relay handshake applies its trusted egress authentication policy");
        let ingress_tls = ingress_result.expect("ingress TLS handshake succeeds");
        drop(bridged);
        drop(ingress_tls);
        drop(upstream_handle.await);
    }

    #[tokio::test]
    async fn trusted_upstream_still_checks_the_effective_dns_identity() {
        assert!(
            connect_to_private_ca_with_server_name(Host::from_static("localhost"), |anchor| {
                Some(
                    TlsMitmEgressServerAuth::new()
                        .with_server_verify(ServerVerifyMode::Auto)
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
                        .with_server_verify(ServerVerifyMode::Auto)
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
            .with_egress_server_auth(
                TlsMitmEgressServerAuth::new()
                    .with_server_verify(ServerVerifyMode::Auto)
                    .with_webpki_roots(),
            );
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
            relay_server_name(None, Some(&target), None),
            KeyLogIntent::Disabled,
            None,
        );

        let data = TlsConnectorData::try_from(&config).expect("build no-policy connector data");
        assert_eq!(data.server_name, None);
    }

    #[test]
    fn default_disabled_policy_preserves_no_sni_for_a_domain_target() {
        let target = HostWithPort::new(Host::from_static("target.example"), 443);
        let policy = TlsMitmEgressServerAuth::new();
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, Some(&target), Some(&policy)),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build disabled connector data");
        assert_eq!(data.server_name, None);
    }

    #[test]
    fn verifying_server_auth_uses_connector_target_ip_as_identity() {
        let target = HostWithPort::new(Host::from(std::net::Ipv4Addr::LOCALHOST), 443);
        let policy = TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Auto);
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, Some(&target), Some(&policy)),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build fallback connector data");
        assert_eq!(data.server_name, Some(target.host));
    }

    #[test]
    fn pinning_policy_uses_connector_target_as_effective_identity() {
        let target = HostWithPort::new(Host::from_static("target.example"), 443);
        let policy = TlsMitmEgressServerAuth::new()
            .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3])));
        let config = egress_tls_client_config(
            None,
            relay_server_name(None, Some(&target), Some(&policy)),
            KeyLogIntent::Disabled,
            Some(&policy),
        );

        let data = TlsConnectorData::try_from(&config).expect("build pinned connector data");
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

        let policy = TlsMitmEgressServerAuth::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .with_webpki_roots();
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
        let policy = TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Auto);
        let config = egress_tls_client_config(
            Some(&hello),
            Some(Host::from_static("example.com")),
            KeyLogIntent::Disabled,
            Some(&policy),
        );
        let flow = Extensions::new();
        flow.insert(TlsServerVerify(ServerVerifyMode::Disable));
        flow.insert(TlsAlpn::http_1());
        flow.insert(TargetHttpVersion(Version::HTTP_2));
        apply_target_http_version(Some(&hello), &flow, &config);

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
    #[tokio::test]
    async fn target_http_version_keeps_alps_coupled_to_narrowed_alpn() {
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
        for (version, expected_alpn, expected_alps) in [
            (Version::HTTP_11, ApplicationProtocol::HTTP_11, Vec::new()),
            (
                Version::HTTP_2,
                ApplicationProtocol::HTTP_2,
                vec![ApplicationProtocol::HTTP_2],
            ),
        ] {
            let config = egress_tls_client_config(
                Some(&hello),
                Some(Host::from_static("example.com")),
                KeyLogIntent::Disabled,
                None,
            );
            let flow = Extensions::new();
            flow.insert(TargetHttpVersion(version));
            apply_target_http_version(Some(&hello), &flow, &config);

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

            // Validate the effective BoringSSL ClientHello, not just Rama's
            // intermediate config. An empty override must suppress the ALPS
            // extension on the wire while retaining the narrowed ALPN offer.
            let connector_data = TlsConnectorData::try_from(&config)
                .expect("build connector data for narrowed ALPN/ALPS");
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let connect_handle = tokio::spawn(tls_connect(
                ServiceInput::new(client_io),
                Some(connector_data),
            ));
            let (peeked_io, emitted_hello) = peek_client_hello_from_input(
                ServiceInput::new(server_io),
                Some(std::time::Duration::from_secs(5)),
            )
            .await
            .expect("peek generated egress ClientHello");
            drop(peeked_io);
            assert!(
                connect_handle
                    .await
                    .expect("join egress TLS client")
                    .is_err(),
                "TLS client must stop after the peer side is closed"
            );

            let emitted_hello = emitted_hello.expect("egress emitted a TLS ClientHello");
            assert_eq!(emitted_hello.ext_alpn(), Some([expected_alpn].as_slice()));
            assert_eq!(
                emitted_hello.ext_alps(),
                (!expected_alps.is_empty()).then_some(expected_alps.as_slice())
            );
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn incompatible_target_http_version_is_ignored() {
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
        let config = egress_tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, None);

        apply_target_http_version(Some(&hello), &flow, &config);
        assert_eq!(
            config
                .as_extensions()
                .get_ref::<TlsAlpn>()
                .map(|alpn| alpn.0.as_slice()),
            Some([ApplicationProtocol::HTTP_11].as_slice())
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn target_without_a_peeked_client_hello_is_ignored() {
        let flow = Extensions::new();
        flow.insert(TargetHttpVersion(Version::HTTP_11));
        let config = egress_tls_client_config(None, None, KeyLogIntent::Disabled, None);

        apply_target_http_version(None, &flow, &config);
        assert!(config.as_extensions().get_ref::<TlsAlpn>().is_none());
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn service_allows_upstream_to_decline_preferred_http2_alpn() {
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

        let (client_io, relay_ingress) = tokio::io::duplex(usize::MAX);
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

        let ingress_connector_data = TlsConnectorData::try_from(
            &TlsClientConfig::new()
                .with_server_verify(ServerVerifyMode::Disable)
                .with_alpn_http_2()
                .with_keylog(KeyLogIntent::Disabled),
        )
        .expect("build ingress TLS client config");
        let (service_result, ingress_result) = tokio::join!(
            service.serve(InputWithClientHello {
                input: BridgeIo(ingress, ServiceInput::new(relay_egress)),
                client_hello,
            }),
            tls_connect(ServiceInput::new(client_io), Some(ingress_connector_data),),
        );
        let ingress_tls =
            ingress_result.expect("ingress TLS succeeds when upstream declines preferred HTTP/2");
        assert!(ingress_tls.ssl_ref().selected_alpn_protocol().is_none());
        drop(ingress_tls);
        service_result.expect("relay accepts upstream ALPN decision");
        drop(upstream_handle.await);
    }

    #[cfg(feature = "http")]
    #[test]
    fn no_alpn_client_hello_applies_only_http1_preference() {
        let hello = ClientHello::new(ProtocolVersion::TLSv1_2, Vec::new(), Vec::new(), Vec::new());
        for (version, expected_alpn) in [
            (Version::HTTP_11, Some(ApplicationProtocol::HTTP_11)),
            (Version::HTTP_2, None),
        ] {
            let flow = Extensions::new();
            flow.insert(TargetHttpVersion(version));
            let config = egress_tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, None);
            assert_eq!(
                {
                    apply_target_http_version(Some(&hello), &flow, &config);
                    config
                        .as_extensions()
                        .get_ref::<TlsAlpn>()
                        .and_then(|alpn| alpn.0.first().cloned())
                },
                expected_alpn
            );
        }
    }
}
