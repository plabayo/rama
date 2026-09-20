//! HTTP/3 establishment using Rama DNS candidates and the existing multiplex pool.

use super::HttpClientService;
use rama_core::{
    Service, ServiceInput,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    futures::{StreamExt as _, stream},
    rt::Executor,
};
use rama_http_types::{Version, conn::TargetHttpVersion};
use rama_net::{
    ConnectorTargetInputExt, ProtocolInputExt,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorTargetStream,
        EstablishedClientConnection, EstablishedProxyRoute, ProxyRoute, race_connect,
    },
    conn::MaxConcurrency,
    stream::SocketInfo,
    tls::ApplicationProtocol,
};
use std::{marker::PhantomData, net::SocketAddr};

/// Establish authenticated HTTP/3 connections on a reusable QUIC endpoint.
///
/// Wrap this connector with Rama's DNS connector and HTTP connection pool,
/// then put [`Http3Policy`] outside the pool so TLS overrides affect lookup.
/// The connector selects `h3` ALPN; the origin hostname remains the TLS
/// verification target even when routing selects a different physical address.
/// TCP proxy routes are rejected before any UDP connection is attempted.
pub struct Http3Connector<B> {
    endpoint: rama_quic::Endpoint,
    tls: rama_tls::client::TlsClientConfig,
    options: rama_quic::tls::TlsOptions,
    config: rama_http_core::h3::connection::Config,
    executor: Executor,
    _body: PhantomData<fn(B)>,
}
impl<B> Clone for Http3Connector<B> {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            tls: self.tls.clone(),
            options: self.options,
            config: self.config.clone(),
            executor: self.executor.clone(),
            _body: PhantomData,
        }
    }
}
impl<B> std::fmt::Debug for Http3Connector<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3Connector")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
impl<B> Http3Connector<B> {
    /// Use an endpoint and TLS configuration supplied by the application.
    /// Transport receive limits come from `config`. Request TLS extensions
    /// override `tls`, following the ordinary Rama TLS connector convention.
    pub fn new(
        endpoint: rama_quic::Endpoint,
        tls: rama_tls::client::TlsClientConfig,
        options: rama_quic::tls::TlsOptions,
        config: rama_http_core::h3::connection::Config,
        executor: Executor,
    ) -> Self {
        Self {
            endpoint,
            tls,
            options,
            config,
            executor,
            _body: PhantomData,
        }
    }
}
fn invalid(message: &'static str) -> ConnectionError {
    ConnectionError::local(
        BoxError::from_static_str(message),
        ConnectionErrorKind::InvalidInput,
    )
}
impl<B: Send + 'static> Service<ConnectRequest> for Http3Connector<B> {
    type Output = EstablishedClientConnection<HttpClientService<B>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        if input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .is_some()
        {
            return Err(invalid("HTTP/3 is not available over this TCP proxy route"));
        }
        if input.protocol().is_none_or(|p| !p.is_secure()) {
            return Err(invalid("HTTP/3 requires a secure origin"));
        }
        validate_version(&input)?;
        let tls = self.tls.clone().with_overrides(input.extensions());
        let server_identity = tls
            .as_extensions()
            .get_ref::<rama_tls::client::TlsServerName>()
            .map_or_else(|| input.authority.host.clone(), |name| name.0.clone());
        let authenticated_identity =
            if rama_quic::tls::client_security_policy(tls.as_extensions()).authenticates_server {
                Some(
                    tls.as_extensions()
                        .get_ref::<rama_tls::client::TlsServerName>()
                        .map_or_else(|| input.authority.host.clone(), |name| name.0.clone()),
                )
            } else {
                None
            };
        let capture_chain = tls
            .as_extensions()
            .get_ref::<rama_tls::client::TlsStoreServerCertChain>()
            .is_some_and(|capture| capture.0);
        let tls = tls.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let mut tls = rama_quic::ClientConfig::try_from_rama_tls(&tls, self.options)
            .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))?;
        let mut transport = rama_quic::TransportConfig::default();
        self.config
            .configure_transport(&mut transport)
            .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))?;
        tls.set_transport_config(std::sync::Arc::new(transport));
        let tls = &tls;
        let target = input
            .connector_target()
            .ok_or_else(|| invalid("HTTP/3 connector target is missing"))?;
        let server_name = if let Ok(ip) = server_identity.try_as_ip() {
            ip.to_string()
        } else {
            server_identity
                .try_as_domain()
                .map_err(|_error| invalid("invalid TLS origin host"))?
                .to_string()
        };
        let server_name = &server_name;
        let attempt = input
            .extensions()
            .get_ref::<super::h3_selection::AttemptState>()
            .cloned()
            .unwrap_or_default();
        let attempt = &attempt;
        let dial = |address| async move {
            let result: Result<_, BoxError> = async {
                let connection = self
                    .endpoint
                    .connect_with(tls.clone(), address, server_name)?
                    .await?;
                connection.handshake_confirmed().await?;
                if connection
                    .handshake_data()
                    .and_then(|data| data.application_layer_protocol)
                    != Some(ApplicationProtocol::HTTP_3)
                {
                    connection.close(0u32, b"h3 ALPN required");
                    return Err(BoxError::from_static_str("HTTP/3 requires h3 ALPN"));
                }
                Ok(connection)
            }
            .await;
            if let Err(error) = &result
                && !super::h3_selection::availability_error(error.as_ref())
            {
                attempt.reject();
            }
            result
        };
        let (address, connection) = if let Ok(ip) = target.host.try_as_ip() {
            race_connect(
                stream::once(async { Ok(SocketAddr::new(ip, target.port)) }),
                1,
                dial,
            )
            .await
        } else {
            let domain = target
                .host
                .try_as_domain()
                .map_err(|_error| invalid("unsupported HTTP/3 target host"))?;
            let candidates = input
                .extensions()
                .get_ref::<ConnectorTargetStream>()
                .filter(|c| c.domain() == domain.as_ref())
                .ok_or_else(|| invalid("HTTP/3 requires DNS candidates for this domain"))?;
            let addresses = candidates
                .stream(input.extensions())
                .map(|result| result.map(|ip| SocketAddr::new(ip, target.port)));
            race_connect(addresses, 2, dial).await
        }
        .map_err(|error| {
            let error = if attempt.failed() {
                ConnectionError::application(error, ConnectionErrorKind::Authentication)
            } else {
                ConnectionError::transport(error, ConnectionErrorKind::Unavailable)
            };
            error.context("HTTP/3 connection establishment")
        })?;
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        // Connection metadata must not inherit a request store: attaching it back
        // as Egress would form a recursive extension chain and retain that request.
        let extensions = rama_core::extensions::Extensions::new();
        extensions.insert(TargetHttpVersion(Version::HTTP_3));
        extensions.insert(rama_tls::client::TlsServerAuthentication(
            authenticated_identity,
        ));
        extensions.insert(EstablishedProxyRoute::Direct);
        extensions.insert(MaxConcurrency::new(self.config.max_requests));
        extensions.insert(SocketInfo::new(
            self.endpoint.local_addr().ok().map(Into::into),
            address.into(),
        ));
        if let Some(mut parameters) = connection.handshake_data() {
            if capture_chain {
                parameters.peer_certificate_chain = connection.peer_identity();
            }
            extensions.insert(parameters);
        }
        let conn = HttpClientService::http3(
            ServiceInput {
                input: connection,
                extensions,
            },
            self.config.clone(),
            self.executor.clone(),
        )
        .map_err(|error| ConnectionError::application(error, ConnectionErrorKind::Protocol))?;
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// Apply H3 intent before DNS, route selection and pool identity calculation.
#[derive(Clone, Debug)]
pub struct Http3Policy<S> {
    inner: S,
    identity: TlsPoolIdentity,
}
impl<S> Http3Policy<S> {
    /// Wrap the complete H3 connector stack, including its pool.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            identity: TlsPoolIdentity::new(),
        }
    }
}

#[derive(Clone, Debug, rama_core::extensions::Extension)]
pub(crate) struct TlsPoolIdentity(std::sync::Arc<()>);
impl TlsPoolIdentity {
    fn new() -> Self {
        Self(std::sync::Arc::new(()))
    }
    fn apply(&self, extensions: &rama_core::extensions::Extensions) {
        // Until TLS policies have stable identities, isolate every request that
        // overrides security settings from all previously pooled connections.
        let overridden = rama_quic::tls::client_security_policy(extensions).has_overrides;
        extensions.insert(if overridden {
            Self::new()
        } else {
            self.clone()
        });
    }
}
impl PartialEq for TlsPoolIdentity {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for TlsPoolIdentity {}
impl std::hash::Hash for TlsPoolIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&std::sync::Arc::as_ptr(&self.0), state);
    }
}
/// Isolate connection pools by connector and per-request TLS security policy.
/// Apply this outside the pool so overrides are considered before lookup.
#[derive(Clone, Debug)]
pub struct TlsPoolPolicy<S> {
    inner: S,
    identity: TlsPoolIdentity,
}
impl<S> TlsPoolPolicy<S> {
    /// Wrap a pooled connector without changing its HTTP version or transport.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            identity: TlsPoolIdentity::new(),
        }
    }
}
impl<S: rama_net::client::ConnectorService<ConnectRequest>> Service<ConnectRequest>
    for TlsPoolPolicy<S>
{
    type Output = EstablishedClientConnection<S::Connection, ConnectRequest>;
    type Error = ConnectionError;
    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        self.identity.apply(input.extensions());
        self.inner.connect(input).await
    }
}

fn validate_version(input: &ConnectRequest) -> Result<(), ConnectionError> {
    if input
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .is_some_and(|version| version.0 != Version::HTTP_3)
    {
        return Err(invalid(
            "explicit HTTP version conflicts with HTTP/3 connector",
        ));
    }
    Ok(())
}
impl<S> Service<ConnectRequest> for Http3Policy<S>
where
    S: rama_net::client::ConnectorService<ConnectRequest>,
{
    type Output = EstablishedClientConnection<S::Connection, ConnectRequest>;
    type Error = ConnectionError;
    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        validate_version(&input)?;
        let extensions = input.extensions();
        self.identity.apply(extensions);
        extensions.insert(TargetHttpVersion(Version::HTTP_3));
        extensions.insert(rama_net::client::ConnectorTransportProtocol(
            rama_net::transport::TransportProtocol::Udp,
        ));
        self.inner.connect(input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{extensions::Extensions, service::service_fn};
    use rama_net::client::pool::ReqToConnID as _;

    fn request() -> ConnectRequest {
        ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(rama_net::Protocol::HTTPS)
    }
    #[tokio::test]
    async fn tcp_policy_isolates_overrides_without_changing_transport() {
        let inspect = service_fn(async |input: ConnectRequest| {
            assert!(!input.extensions().contains::<TargetHttpVersion>());
            assert!(
                !input
                    .extensions()
                    .contains::<rama_net::client::ConnectorTransportProtocol>()
            );
            let id = crate::client::HttpConnIdentifier::new().id(&input).unwrap();
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput {
                    input: id,
                    extensions: Extensions::new(),
                },
            })
        });
        let policy = TlsPoolPolicy::new(inspect);
        let cached = policy.serve(request()).await.unwrap().conn.input;
        assert_eq!(cached, policy.serve(request()).await.unwrap().conn.input);
        let changed = || {
            let request = request();
            request
                .extensions()
                .insert(rama_tls::client::TlsServerCertPins::new(
                    rama_tls::client::TlsServerCertPin::SpkiSha256([1; 32]),
                ));
            request
        };
        let fresh = policy.serve(changed()).await.unwrap().conn.input;
        assert_ne!(cached, fresh);
        assert_ne!(fresh, policy.serve(changed()).await.unwrap().conn.input);
    }

    #[tokio::test]
    async fn policy_partitions_pool_before_lookup() {
        let inspect = service_fn(async |input: ConnectRequest| {
            assert_eq!(
                input.extensions().get_ref::<TargetHttpVersion>().unwrap().0,
                Version::HTTP_3
            );
            let id = crate::client::HttpConnIdentifier::new().id(&input).unwrap();
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput {
                    input: id,
                    extensions: Extensions::new(),
                },
            })
        });
        let policy = Http3Policy::new(inspect);
        let first = policy.serve(request()).await.unwrap().conn.input;
        let second = policy.serve(request()).await.unwrap().conn.input;
        assert_eq!(first, second);
        let conflicting = request();
        conflicting
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        assert_eq!(
            policy.serve(conflicting).await.unwrap_err().kind(),
            ConnectionErrorKind::InvalidInput
        );
        let overridden = || {
            let request = request();
            request.extensions().insert(rama_tls::client::TlsServerName(
                "other.example".parse().unwrap(),
            ));
            request
        };
        let override_id = policy.serve(overridden()).await.unwrap().conn.input;
        assert_ne!(first, override_id);
        assert_ne!(
            override_id,
            policy.serve(overridden()).await.unwrap().conn.input
        );
        assert_ne!(
            first,
            crate::client::HttpConnIdentifier::new()
                .id(&request())
                .unwrap()
        );
    }
}
