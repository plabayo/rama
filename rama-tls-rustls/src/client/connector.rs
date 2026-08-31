use super::{AutoTlsStream, RustlsTlsStream, TlsConnectorData, TlsStream};
use crate::client::config::RustlsTlsConnectorConfig;
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use crate::types::TlsTunnel;
use rama_core::conversion::{RamaInto, RamaTryFrom};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::address::Host;
use rama_net::client::{
    ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
};
use rama_net::extensions::StreamTransformed;
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    tls::{ApplicationProtocol, TlsAlpn, default_tls_alpn},
};
use rama_tls::client::{NegotiatedTlsParameters, TlsClientConfig};
use rama_tls::{TlsTunnelMode, resolve_tls_tunnel};
#[cfg(feature = "http")]
use rama_utils::collections::smallvec::smallvec;

#[cfg(feature = "http")]
use ::{
    rama_core::error::ErrorExt,
    rama_net::http::{TargetHttpVersion, Version},
};

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<K = ConnectorKindAuto> {
    base_config: Option<TlsClientConfig>,
    kind: K,
}

impl<K> TlsConnectorLayer<K> {
    rama_utils::macros::generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnectorLayer`].
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    }
}

impl TlsConnectorLayer<ConnectorKindAuto> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
    #[must_use]
    pub fn auto() -> Self {
        Self {
            base_config: None,
            kind: ConnectorKindAuto,
        }
    }
}

impl TlsConnectorLayer<ConnectorKindSecure> {
    /// Creates a new [`TlsConnectorLayer`] which will always
    /// establish a secure connection regardless of the request it is for.
    #[must_use]
    pub fn secure() -> Self {
        Self {
            base_config: None,
            kind: ConnectorKindSecure,
        }
    }
}

impl TlsConnectorLayer<ConnectorKindTunnel> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection if the request is to be tunneled.
    #[must_use]
    pub fn tunnel(host: Option<Host>) -> Self {
        Self {
            base_config: None,
            kind: ConnectorKindTunnel { host },
        }
    }
}

impl<K: Clone, S> Layer<S> for TlsConnectorLayer<K> {
    type Service = TlsConnector<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config.clone(),
            kind: self.kind.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config,
            kind: self.kind,
        }
    }
}

impl Default for TlsConnectorLayer<ConnectorKindAuto> {
    fn default() -> Self {
        Self::auto()
    }
}

/// A connector which can be used to establish a connection to a server.
///
/// By default it will created in auto mode ([`TlsConnector::auto`]),
/// which will perform the Tls handshake on the underlying stream,
/// only if the request requires a secure connection. You can instead use
/// [`TlsConnector::secure`] to force the connector to always
/// establish a secure connection.
#[derive(Debug, Clone)]
pub struct TlsConnector<S, K = ConnectorKindAuto> {
    inner: S,
    base_config: Option<TlsClientConfig>,
    kind: K,
}

impl<S, K> TlsConnector<S, K> {
    /// Creates a new [`TlsConnector`].
    pub const fn new(inner: S, kind: K) -> Self {
        Self {
            inner,
            base_config: None,
            kind,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the base [`TlsClientConfig`] for this [`TlsConnector`].
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    }
}

impl<S> TlsConnector<S, ConnectorKindAuto> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection if the request demands it,
    /// otherwise it will forward the pre-established inner connection.
    pub fn auto(inner: S) -> Self {
        Self::new(inner, ConnectorKindAuto)
    }
}

impl<S> TlsConnector<S, ConnectorKindSecure> {
    /// Creates a new [`TlsConnector`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub fn secure(inner: S) -> Self {
        Self::new(inner, ConnectorKindSecure)
    }
}

impl<S> TlsConnector<S, ConnectorKindTunnel> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection if the request is to be tunneled.
    pub fn tunnel(inner: S, host: Option<Host>) -> Self {
        Self::new(inner, ConnectorKindTunnel { host })
    }
}

// this way we do not need a hacky macro... however is there a way to do this without needing to hacK?!?!

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindAuto>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(auto): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let app_protocol = input.protocol();

        if !app_protocol
            .as_ref()
            .map(|p| p.is_secure())
            .unwrap_or_default()
        {
            tracing::trace!(
                server.address = %authority.host,
                server.port = authority.port_u16(),
                "TlsConnector(auto): protocol not secure, return inner connection",
            );

            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        }

        let server_host = &authority.host;

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): attempt to secure inner connection w/ app protcol: {:?}",
            app_protocol,
        );

        let connector_data = self
            .connector_data(input.extensions(), app_protocol)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(auto): build connector configuration")
            })?;

        let (stream, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await
            .map_err(|error| {
                ConnectionError::application(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(auto): TLS handshake")
            })?;

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): protocol secure, established tls connection w/ app protcol: {:?}",
            app_protocol,
        );

        let conn = AutoTlsStream::secure(stream);
        #[cfg(feature = "http")]
        set_target_http_version(
            app_protocol,
            input.extensions(),
            conn.extensions(),
            &negotiated_params,
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(auto): validate negotiated HTTP version")
        })?;

        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsConnector",
        });
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindSecure>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: AuthorityInputExt + ProtocolInputExt + Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<TlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(secure): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protcol: {:?}",
            input.protocol(),
        );

        let server_host = &authority.host;

        let app_protocol = input.protocol();
        let connector_data = self
            .connector_data(input.extensions(), app_protocol)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(secure): build connector configuration")
            })?;

        let (conn, negotiated_params) = self
            .handshake(connector_data, Some(server_host), conn)
            .await
            .map_err(|error| {
                ConnectionError::application(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(secure): TLS handshake")
            })?;

        let conn = TlsStream::new(conn);
        #[cfg(feature = "http")]
        set_target_http_version(
            app_protocol,
            input.extensions(),
            conn.extensions(),
            &negotiated_params,
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(secure): validate negotiated HTTP version")
        })?;

        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsConnector",
        });
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, Input> Service<Input> for TlsConnector<S, ConnectorKindTunnel>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<AutoTlsStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let tunnel = input.extensions().get_ref::<TlsTunnel>().cloned();

        let TlsTunnelMode::Tls(maybe_server_host) =
            resolve_tls_tunnel(tunnel.as_ref(), self.kind.host.as_ref())
        else {
            tracing::trace!(
                "TlsConnector(tunnel): return inner connection: no Tls tunnel is requested"
            );

            return Ok(EstablishedClientConnection {
                input,
                conn: AutoTlsStream::plain(conn),
            });
        };

        let tunnel_protocol = tunnel
            .as_ref()
            .and_then(|tunnel| tunnel.application_protocol.as_ref());
        let connector_data = self
            .tunnel_connector_data(tunnel.as_ref(), tunnel_protocol)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(tunnel): build connector configuration")
            })?;

        let (conn, negotiated_params) = self
            .handshake(connector_data, maybe_server_host, conn)
            .await
            .map_err(|error| {
                ConnectionError::transport(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(tunnel): TLS handshake")
            })?;
        let conn = AutoTlsStream::secure(conn);

        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsConnector",
        });
        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, K> TlsConnector<S, K> {
    fn tunnel_connector_data(
        &self,
        tunnel: Option<&TlsTunnel>,
        application_protocol: Option<&Protocol>,
    ) -> Result<TlsConnectorData, BoxError> {
        let effective = self.tunnel_config_extensions(tunnel, application_protocol);

        let config = RustlsTlsConnectorConfig::from_extensions(&effective);
        TlsConnectorData::try_from(config)
    }

    fn tunnel_config_extensions(
        &self,
        tunnel: Option<&TlsTunnel>,
        application_protocol: Option<&Protocol>,
    ) -> Extensions {
        let effective = Extensions::new();
        if let Some(base) = &self.base_config {
            effective.extend(base.as_extensions());
        }
        if let Some(alpn) = tunnel.and_then(|tunnel| tunnel.alpn.clone()) {
            effective.insert(alpn);
        }

        apply_default_alpn(&effective, application_protocol);
        effective
    }

    fn connector_data(
        &self,
        request_extensions: &Extensions,
        application_protocol: Option<&Protocol>,
    ) -> Result<TlsConnectorData, BoxError> {
        let effective = request_extensions.fork();
        let extensions = if let Some(base) = &self.base_config {
            effective.with_base(base.as_extensions())
        } else {
            effective
        };

        apply_default_alpn(&extensions, application_protocol);

        // When HTTP pins a concrete target version, force the TLS ALPN to match
        // it before the handshake
        #[cfg(feature = "http")]
        resolve_http_alpn(&extensions, application_protocol)?;

        let config = RustlsTlsConnectorConfig::from_extensions(&extensions);
        TlsConnectorData::try_from(config)
    }

    async fn handshake<T>(
        &self,
        connector_data: TlsConnectorData,
        maybe_server_host: Option<&Host>,
        stream: T,
    ) -> Result<(RustlsTlsStream<T>, NegotiatedTlsParameters), BoxError>
    where
        T: Io + ExtensionsRef + Unpin,
    {
        #[cfg(feature = "dial9")]
        let dial9_server_name = connector_data
            .server_name
            .clone()
            .or_else(|| maybe_server_host.cloned())
            .context("server identity missing")?;

        let server_name = rama_crypto::pki_types::ServerName::rama_try_from(
            connector_data
                .server_name
                .or_else(|| maybe_server_host.cloned())
                .context("server identity missing")?,
        )?;

        let connector = RustlsConnector::from(connector_data.client_config);

        #[cfg(feature = "dial9")]
        crate::dial9::record_handshake_started(dial9_server_name.clone());

        let stream = match connector.connect(server_name, stream).await {
            Ok(stream) => stream,
            Err(err) => {
                #[cfg(feature = "dial9")]
                crate::dial9::record_handshake_failed(dial9_server_name.clone(), &err);
                return Err(err.into());
            }
        };

        let (_, conn_data_ref) = stream.get_ref();

        let server_certificate_chain = if connector_data.store_server_certificate_chain {
            conn_data_ref.peer_certificates().map(RamaInto::rama_into)
        } else {
            None
        };

        let params = NegotiatedTlsParameters {
            protocol_version: conn_data_ref
                .protocol_version()
                .context("no protocol version available")?
                .rama_into(),
            application_layer_protocol: conn_data_ref
                .alpn_protocol()
                .map(ApplicationProtocol::from),
            peer_certificate_chain: server_certificate_chain,
        };

        #[cfg(feature = "dial9")]
        {
            let depth = params
                .peer_certificate_chain
                .as_ref()
                .map_or(0, |chain| chain.len());
            crate::dial9::record_handshake_completed(
                dial9_server_name,
                params.protocol_version,
                conn_data_ref.alpn_protocol().map(ApplicationProtocol::from),
                depth,
            );
        }

        Ok((stream, params))
    }
}

fn apply_default_alpn(effective_extensions: &Extensions, application_protocol: Option<&Protocol>) {
    // Any ALPN in the effective chain is explicit connector policy, whether
    // supplied by the request or inherited from a base configuration.
    if effective_extensions.get_ref::<TlsAlpn>().is_some() {
        return;
    }
    let Some(protocol) = application_protocol else {
        return;
    };

    effective_extensions.insert(default_tls_alpn(protocol).unwrap_or_else(TlsAlpn::empty));
}

/// Force the TLS ALPN to match a concrete [`TargetHttpVersion`] when HTTP pins
/// one. Otherwise protocols like WebSocket can negotiate `h2` even though the
/// request requires an HTTP/1.1 upgrade.
#[cfg(feature = "http")]
fn resolve_http_alpn(
    ext: &Extensions,
    application_protocol: Option<&Protocol>,
) -> Result<(), BoxError> {
    if application_protocol.is_some_and(|protocol| !protocol.is_http_based()) {
        return Ok(());
    }
    let Some(target_version) = ext.get_ref::<TargetHttpVersion>() else {
        return Ok(());
    };

    let target_alpn = ApplicationProtocol::try_from(target_version.0)?;
    tracing::trace!(
        ?target_version,
        ?target_alpn,
        "override TLS ALPN to match TargetHttpVersion",
    );

    ext.insert(TlsAlpn(smallvec![target_alpn]));
    Ok(())
}

#[cfg(feature = "http")]
fn set_target_http_version(
    application_protocol: Option<&Protocol>,
    request_extensions: &Extensions,
    conn_extensions: &Extensions,
    tls_params: &NegotiatedTlsParameters,
) -> Result<(), BoxError> {
    if !application_protocol.is_some_and(Protocol::is_http_based) {
        return Ok(());
    }
    if let Some(proto) = tls_params.application_layer_protocol.as_ref() {
        let neg_version: Version = proto.try_into()?;
        if let Some(target_version) = request_extensions.get_ref::<TargetHttpVersion>()
            && target_version.0 != neg_version
        {
            return Err(BoxError::from_static_str(
                "TargetHTTPVersion incompatible with tls ALPN negotiated version",
            )
            .context_debug_field("target_version", *target_version)
            .context_debug_field("negotiated_version", neg_version));
        }

        tracing::trace!(
            "setting request TargetHttpVersion to {:?} based on negotiated APLN",
            neg_version,
        );
        conn_extensions.insert(TargetHttpVersion(neg_version));
    }

    Ok(())
}

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A connector which can be used to establish a connection to a server
/// in function of the input, meaning either it will be a secure
/// connector or it will be a plain connector.
///
/// This connector can be handy as it allows to have a single layer
/// which will work both for plain and secure connections.
pub struct ConnectorKindAuto;

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A connector which can _only_ be used to establish a secure connection,
/// regardless of the scheme of the request URI.
pub struct ConnectorKindSecure;

#[derive(Debug, Clone)]
/// A connector which can be used to use this connector to support
/// secure tls tunnel connections.
///
/// TLS is requested when [`TlsTunnel`] is present or a hardcoded server
/// identity is configured. A dedicated base-config identity takes precedence,
/// followed by the tunnel identity and then this connector fallback.
///
/// [`TlsTunnel`]: rama_tls::TlsTunnel
pub struct ConnectorKindTunnel {
    host: Option<Host>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_config_uses_only_base_and_explicit_tunnel_policy() {
        use rama_net::tls::TlsAlpn;
        use rama_tls::client::{ServerVerifyMode, TlsServerName, TlsServerVerify};

        let base_name = Host::from_static("proxy-cert.example");
        let connector = TlsConnector::tunnel((), None).with_base_config(
            TlsClientConfig::new()
                .with_alpn_http_2()
                .with_server_name(base_name.clone())
                .with_server_verify(ServerVerifyMode::Disable),
        );
        let tunnel = TlsTunnel {
            server_identity: Some(Host::from_static("proxy-route.example")),
            application_protocol: Some(Protocol::HTTPS),
            alpn: Some(TlsAlpn::http_1()),
        };

        let effective = connector.tunnel_config_extensions(Some(&tunnel), Some(&Protocol::HTTPS));
        assert_eq!(
            effective.get_ref::<TlsAlpn>().cloned(),
            Some(TlsAlpn::http_1())
        );
        assert_eq!(
            effective
                .get_ref::<TlsServerName>()
                .map(|server_name| server_name.0.clone()),
            Some(base_name)
        );
        assert_eq!(
            effective
                .get_ref::<TlsServerVerify>()
                .map(|verify| verify.0),
            Some(ServerVerifyMode::Disable)
        );
    }

    #[test]
    fn tunnel_config_isolates_all_origin_tls_extensions() {
        use crate::client::{ModifyRustlsClientConfig, RustlsClientConfigExt as _};
        use rama_crypto::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use rama_tls::{
            KeyLogIntent, ProtocolVersion, TlsKeyLog,
            client::{
                ClientAuth, ClientAuthData, ServerVerifyMode, TlsClientAuth, TlsServerCertPinCheck,
                TlsServerCertPins, TlsServerTrust,
            },
        };
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let base_modifier_used = Arc::new(AtomicBool::new(false));
        let base_modifier_flag = base_modifier_used.clone();
        let base_name = Host::from_static("proxy-cert.example");
        let base_pin = CertificateDer::from(vec![1, 2, 3]);
        let base_pins = TlsServerCertPins::new(base_pin.clone());
        let base_trust = TlsServerTrust::webpki_roots();
        let base = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(base_name.clone())
            .with_server_verify(ServerVerifyMode::Disable)
            .with_server_cert_pins(base_pins)
            .with_server_trust(base_trust.clone())
            .with_supported_versions(vec![ProtocolVersion::TLSv1_3])
            .with_keylog(KeyLogIntent::Disabled)
            .with_client_auth(ClientAuth::SelfSigned)
            .with_store_server_cert_chain(true)
            .with_modify_rustls_config(move |config| {
                base_modifier_flag.store(true, Ordering::SeqCst);
                Ok(config)
            });
        let connector = TlsConnector::tunnel((), None).with_base_config(base);

        let origin = Extensions::new();
        TlsClientConfig::new()
            .with_alpn_http_1()
            .with_server_name(Host::from_static("origin.example"))
            .with_server_verify(ServerVerifyMode::Auto)
            .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
            .with_server_trust(TlsServerTrust::default_roots())
            .with_supported_versions(vec![ProtocolVersion::TLSv1_2])
            .with_keylog(KeyLogIntent::Environment)
            .with_client_auth(ClientAuth::Single(ClientAuthData {
                cert_chain: vec![CertificateDer::from(vec![8])],
                private_key: PrivatePkcs8KeyDer::from(vec![7]).into(),
            }))
            .with_store_server_cert_chain(false)
            .write_to(&origin);
        origin.insert(ModifyRustlsClientConfig::new(|_| {
            panic!("origin rustls modifier leaked into proxy TLS")
        }));
        origin.insert(TlsTunnel {
            server_identity: Some(Host::from_static("proxy-route.example")),
            application_protocol: Some(Protocol::HTTPS),
            alpn: None,
        });

        let tunnel = origin.get_ref::<TlsTunnel>();
        let effective = connector.tunnel_config_extensions(tunnel, Some(&Protocol::HTTPS));
        let config = RustlsTlsConnectorConfig::from_extensions(&effective);

        assert_eq!(config.alpn.cloned(), Some(TlsAlpn::http_2()));
        assert_eq!(
            config.server_name.map(|name| name.0.clone()),
            Some(base_name.clone())
        );
        assert_eq!(
            config.verify.map(|verify| verify.0),
            Some(ServerVerifyMode::Disable)
        );
        assert_eq!(config.server_trust, Some(&base_trust));
        assert_eq!(
            config.versions.map(|versions| versions.0.as_slice()),
            Some([ProtocolVersion::TLSv1_3].as_slice())
        );
        assert!(matches!(
            config.keylog,
            Some(TlsKeyLog(KeyLogIntent::Disabled))
        ));
        assert!(matches!(
            config.client_auth,
            Some(TlsClientAuth(ClientAuth::SelfSigned))
        ));
        assert_eq!(config.store_chain.map(|store| store.0), Some(true));
        assert_eq!(
            config
                .server_cert_pins
                .expect("base pins")
                .check(Some(&base_name), &base_pin),
            TlsServerCertPinCheck::Matched
        );
        assert!(config.modify.is_some());

        let data = connector
            .tunnel_connector_data(tunnel, Some(&Protocol::HTTPS))
            .expect("resolved tunnel connector data");
        assert!(base_modifier_used.load(Ordering::SeqCst));
        assert_eq!(data.server_name, Some(base_name));
        assert!(data.store_server_certificate_chain);
        assert_eq!(
            data.client_config.alpn_protocols,
            vec![ApplicationProtocol::HTTP_2.as_bytes().to_vec()]
        );
    }

    #[test]
    fn explicit_empty_tunnel_alpn_overrides_base() {
        use rama_net::tls::TlsAlpn;

        let connector = TlsConnector::tunnel((), None)
            .with_base_config(TlsClientConfig::new().with_alpn_http_auto());
        let tunnel = TlsTunnel {
            server_identity: None,
            application_protocol: Some(Protocol::HTTPS),
            alpn: Some(TlsAlpn::empty()),
        };

        let effective = connector.tunnel_config_extensions(Some(&tunnel), Some(&Protocol::HTTPS));
        assert_eq!(
            effective.get_ref::<TlsAlpn>().cloned(),
            Some(TlsAlpn::empty())
        );
    }

    #[tokio::test]
    async fn tunnel_handshake_uses_proxy_base_and_keeps_version_scoped() {
        use rama_core::{ServiceInput, service::service_fn};
        use rama_crypto::{cert::generate_server_auth, pki_types::CertificateDer};
        use rama_net::{client::EstablishedClientConnection, stream::service::EchoService};
        use rama_tls::{
            ProtocolVersion,
            client::{ServerVerifyMode, TlsServerCertPins},
            server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
        };
        use std::sync::Arc;

        let (cert_chain, private_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).expect("server auth");
        let trust_anchor = cert_chain.last().expect("trust anchor").clone();
        let server_pin = cert_chain.first().expect("leaf certificate").clone();
        let server = crate::server::TlsAcceptorLayer::new(
            TlsServerConfig::new()
                .with_single_cert(ServerAuthData {
                    cert_chain,
                    private_key,
                    ocsp: None,
                })
                .with_alpn_http_2(),
        )
        .into_layer(EchoService::new());

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        let client_io = Arc::new(tokio::sync::Mutex::new(Some(client_io)));
        let transport = service_fn(move |input: ServiceInput<()>| {
            let client_io = client_io.clone();
            async move {
                let conn =
                    ServiceInput::new(client_io.lock().await.take().expect("one connection"));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            }
        });
        let proxy_base = TlsClientConfig::new()
            .with_alpn_http_2()
            .with_server_name(Host::from_static("localhost"))
            .with_server_cert_pins(TlsServerCertPins::new(server_pin))
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([trust_anchor])
            .expect("proxy trust")
            .with_supported_versions(vec![ProtocolVersion::TLSv1_3]);
        let connector = TlsConnector::tunnel(transport, None).with_base_config(proxy_base);

        let input = ServiceInput::new(());
        TlsClientConfig::new()
            .with_alpn_http_1()
            .with_server_name(Host::from_static("origin.example"))
            .with_server_verify(ServerVerifyMode::Disable)
            .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
            .write_to(input.extensions());
        #[cfg(feature = "http")]
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
        input.extensions().insert(TlsTunnel {
            server_identity: Some(Host::from_static("proxy-route.example")),
            application_protocol: Some(Protocol::HTTPS),
            alpn: None,
        });

        let established = connector.serve(input).await.expect("proxy TLS handshake");
        let negotiated = established
            .conn
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .expect("proxy TLS parameters");
        assert_eq!(
            negotiated.application_layer_protocol,
            Some(ApplicationProtocol::HTTP_2)
        );
        #[cfg(feature = "http")]
        assert!(
            established
                .conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .is_none()
        );
        drop(established);
        // The client is dropped immediately after the handshake assertions,
        // so the TLS server may finish with an EOF/close-notify error.
        let _server_result = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
            .await
            .expect("server shutdown")
            .expect("server task");
    }

    #[test]
    fn assert_send() {
        use rama_utils::test_helpers::assert_send;

        assert_send::<TlsConnectorLayer>();
    }

    #[test]
    fn assert_sync() {
        use rama_utils::test_helpers::assert_sync;

        assert_sync::<TlsConnectorLayer>();
    }

    #[cfg(feature = "http")]
    mod http_alpn_resolution {
        use super::*;
        use rama_core::extensions::Extensions;
        use rama_net::http::{FallbackHttpVersion, TargetHttpVersion, Version};
        use rama_net::tls::ApplicationProtocol;

        fn alpn_of(ext: &Extensions) -> Option<Vec<ApplicationProtocol>> {
            ext.get_ref::<TlsAlpn>().map(|a| a.0.clone().into_vec())
        }

        #[test]
        fn forces_http11_alpn_when_target_is_http11() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_11]));
        }

        #[test]
        fn forces_http2_alpn_when_target_is_http2() {
            let ext = Extensions::new();
            ext.insert(TargetHttpVersion(Version::HTTP_2));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_2]));
        }

        #[test]
        fn leaves_alpn_untouched_without_target_version() {
            let ext = Extensions::new();
            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), None);
        }

        #[test]
        fn fallback_version_does_not_constrain_alpn() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::http_auto());
            ext.insert(FallbackHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(
                alpn_of(&ext),
                Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11
                ])
            );
        }

        #[test]
        fn overrides_existing_alpn_to_match_target() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::http_auto());
            ext.insert(TargetHttpVersion(Version::HTTP_11));

            resolve_http_alpn(&ext, Some(&Protocol::HTTPS)).unwrap();
            assert_eq!(alpn_of(&ext), Some(vec![ApplicationProtocol::HTTP_11]));
        }

        #[test]
        fn inherited_alpn_is_preserved_for_any_application_protocol() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_auto());
            let request = Extensions::new();
            let effective = request.fork().with_base(&base);

            apply_default_alpn(&effective, Some(&Protocol::ICAPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11
                ])
            );
        }

        #[test]
        fn derives_default_alpn_when_no_explicit_policy_exists() {
            let effective = Extensions::new();

            apply_default_alpn(&effective, Some(&Protocol::HTTPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11
                ])
            );
        }

        #[test]
        fn derives_empty_alpn_for_icaps_without_explicit_policy() {
            let effective = Extensions::new();

            apply_default_alpn(&effective, Some(&Protocol::ICAPS));

            assert_eq!(alpn_of(&effective), Some(Vec::new()));
        }

        #[test]
        fn explicit_request_alpn_wins_for_icaps() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_auto());
            let request = Extensions::new();
            request.insert(TlsAlpn::http_1());
            let effective = request.fork().with_base(&base);

            apply_default_alpn(&effective, Some(&Protocol::ICAPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![ApplicationProtocol::HTTP_11])
            );
        }

        #[test]
        fn inherited_http_alpn_survives_for_https() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_1());
            let request = Extensions::new();
            let effective = request.fork().with_base(&base);

            apply_default_alpn(&effective, Some(&Protocol::HTTPS));

            assert_eq!(
                alpn_of(&effective),
                Some(vec![ApplicationProtocol::HTTP_11])
            );
        }

        #[test]
        fn inherited_alpn_survives_without_application_protocol() {
            let base = Extensions::new();
            base.insert(TlsAlpn::http_1());
            let effective = Extensions::new().with_base(&base);

            apply_default_alpn(&effective, None);

            assert_eq!(
                alpn_of(&effective),
                Some(vec![ApplicationProtocol::HTTP_11])
            );
        }

        #[test]
        fn icaps_ignores_http_version_hint() {
            let ext = Extensions::new();
            ext.insert(TlsAlpn::empty());
            ext.insert(TargetHttpVersion(Version::HTTP_2));

            resolve_http_alpn(&ext, Some(&Protocol::ICAPS)).unwrap();

            assert_eq!(alpn_of(&ext), Some(Vec::new()));
        }
    }
}
