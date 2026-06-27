use std::net::IpAddr;

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesUnordered},
    telemetry::tracing,
};
use rama_net::{
    ConnectorTargetInputExt, ProtocolInputExt, TransportProtocolInputExt,
    address::{Domain, Host, HostWithPort, ip::IntoCanonicalIpAddr as _},
    client::{
        ConnectorService, ConnectorTarget, EstablishedClientConnection, Request, ResolvedDomain,
    },
    mode::ConnectIpMode,
};
use rama_utils::macros::define_inner_service_accessors;

use super::{
    GlobalDnsResolver,
    resolver::{DnsAddressResolver, HappyEyeballAddressResolverExt},
};

const MAX_IN_FLIGHT_CONNECT_ATTEMPTS: usize = 3;

type ConnectAttempt<'a, C> = BoxFuture<
    'a,
    (
        IpAddr,
        Result<EstablishedClientConnection<C, Request>, BoxError>,
    ),
>;

#[derive(Debug, Clone)]
/// A [`Layer`] which wraps a transport connector with DNS resolution.
///
/// The produced [`DnsConnector`] accepts higher-level inputs, resolves their
/// [`ConnectorTargetInputExt::connector_target`] domain target to IP targets,
/// and calls the inner transport connector with a fresh L4 [`Request`] per IP.
pub struct DnsConnectorLayer<R = GlobalDnsResolver> {
    resolver: R,
}

impl DnsConnectorLayer {
    /// Create a new [`DnsConnectorLayer`] using the global DNS resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: GlobalDnsResolver::new(),
        }
    }
}

impl Default for DnsConnectorLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> DnsConnectorLayer<R> {
    /// Create a new [`DnsConnectorLayer`] using the given DNS resolver.
    #[must_use]
    pub const fn with_resolver(resolver: R) -> Self {
        Self { resolver }
    }
}

impl<S, R> Layer<S> for DnsConnectorLayer<R>
where
    R: DnsAddressResolver + Clone,
{
    type Service = DnsConnector<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsConnector::with_resolver(inner, self.resolver.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        DnsConnector::with_resolver(inner, self.resolver)
    }
}

#[derive(Debug, Clone)]
/// A connector service that resolves domain connector targets before dialing.
pub struct DnsConnector<S, R = GlobalDnsResolver> {
    inner: S,
    resolver: R,
}

impl<S> DnsConnector<S> {
    /// Create a new [`DnsConnector`] using the global DNS resolver.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            resolver: GlobalDnsResolver::new(),
        }
    }
}

impl<S, R> DnsConnector<S, R> {
    /// Create a new [`DnsConnector`] using the given DNS resolver.
    #[must_use]
    pub const fn with_resolver(inner: S, resolver: R) -> Self {
        Self { inner, resolver }
    }

    define_inner_service_accessors!();
}

impl<S, R, Input> Service<Input> for DnsConnector<S, R>
where
    S: ConnectorService<Request>,
    Input: ConnectorTargetInputExt + ProtocolInputExt + TransportProtocolInputExt + Send + 'static,
    R: DnsAddressResolver + Clone,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let target = input
            .connector_target()
            .context("dns connector: get connector target from input")?;

        match target.host.clone().try_as_ip() {
            Ok(ip) => {
                let ip = ip.into_canonical_ip_addr();
                ensure_ip_connect_mode(input.extensions(), ip)?;
                let transport_input = make_transport_input(&input, target.port, ip, None);
                let EstablishedClientConnection { conn, .. } = self
                    .inner
                    .connect(transport_input)
                    .await
                    .map_err(Into::<BoxError>::into)?;
                input.extensions().insert(ConnectorTarget(HostWithPort::new(
                    Host::Address(ip),
                    target.port,
                )));
                return Ok(EstablishedClientConnection { input, conn });
            }
            Err(_) => {}
        }

        let domain = target
            .host
            .try_into_domain()
            .context("dns connector: connector target host is not resolvable as a domain")?;

        let input_extensions = input.extensions().clone();
        let mut ip_stream = std::pin::pin!(
            self.resolver
                .happy_eyeballs_resolver(Host::Name(domain.clone()))
                .with_extensions(&input_extensions)
                .lookup_ip()
        );

        let mut resolved_count = 0usize;
        let mut last_connect_err = None;
        let mut last_resolve_err = None;
        let mut resolver_done = false;
        let mut connect_attempts: FuturesUnordered<ConnectAttempt<'_, S::Connection>> =
            FuturesUnordered::new();

        enum DnsConnectorEvent<C> {
            Resolved(Option<Result<IpAddr, BoxError>>),
            Connected(
                Option<(
                    IpAddr,
                    Result<EstablishedClientConnection<C, Request>, BoxError>,
                )>,
            ),
        }

        loop {
            if resolver_done && connect_attempts.is_empty() {
                break;
            }

            let event: DnsConnectorEvent<S::Connection> =
                if !resolver_done && connect_attempts.len() < MAX_IN_FLIGHT_CONNECT_ATTEMPTS {
                    if connect_attempts.is_empty() {
                        DnsConnectorEvent::Resolved(
                            ip_stream
                                .next()
                                .await
                                .map(|result| result.map_err(Into::<BoxError>::into)),
                        )
                    } else {
                        tokio::select! {
                            ip_result = ip_stream.next() => {
                                DnsConnectorEvent::Resolved(
                                    ip_result.map(|result| result.map_err(Into::<BoxError>::into)),
                                )
                            }
                            connect_attempt = connect_attempts.next() => {
                                DnsConnectorEvent::Connected(connect_attempt)
                            }
                        }
                    }
                } else {
                    DnsConnectorEvent::Connected(connect_attempts.next().await)
                };

            match event {
                DnsConnectorEvent::Resolved(Some(Ok(ip))) => {
                    resolved_count += 1;
                    let ip = ip.into_canonical_ip_addr();
                    queue_connect_attempt(
                        &mut connect_attempts,
                        &self.inner,
                        &input,
                        target.port,
                        ip,
                        domain.clone(),
                    );
                }
                DnsConnectorEvent::Resolved(Some(Err(err))) => {
                    tracing::debug!(%domain, error = ?err, "dns connector: failed to resolve IP");
                    last_resolve_err = Some(err);
                }
                DnsConnectorEvent::Resolved(None) => {
                    resolver_done = true;
                }
                DnsConnectorEvent::Connected(Some((ip, result))) => match result {
                    Ok(EstablishedClientConnection { conn, .. }) => {
                        input.extensions().insert(ConnectorTarget(HostWithPort::new(
                            Host::Address(ip),
                            target.port,
                        )));
                        input.extensions().insert(ResolvedDomain(domain));
                        drop(ip_stream);
                        return Ok(EstablishedClientConnection { input, conn });
                    }
                    Err(err) => {
                        tracing::trace!(
                            %domain,
                            %ip,
                            port = target.port,
                            error = ?err,
                            "dns connector: resolved IP connect attempt failed",
                        );
                        last_connect_err = Some(err);
                    }
                },
                DnsConnectorEvent::Connected(None) => {}
            }
        }

        drop(connect_attempts);

        if resolved_count > 0 {
            let err =
                BoxError::from_static_str("dns connector: failed to connect to any resolved IP")
                    .context_field("domain", domain)
                    .context_field("port", target.port)
                    .context_field("resolved_addr_count", resolved_count);
            if let Some(source) = last_connect_err {
                tracing::debug!(error = ?source, "dns connector: last connect error");
            }
            Err(err)
        } else {
            let err = BoxError::from_static_str(
                "dns connector: failed to resolve target domain into any IP address",
            )
            .context_field("domain", domain)
            .context_field("port", target.port);
            if let Some(source) = last_resolve_err {
                tracing::debug!(error = ?source, "dns connector: last resolve error");
            }
            Err(err)
        }
    }
}

fn queue_connect_attempt<'a, S, Input>(
    connect_attempts: &mut FuturesUnordered<ConnectAttempt<'a, S::Connection>>,
    inner: &'a S,
    input: &Input,
    port: u16,
    ip: IpAddr,
    domain: Domain,
) where
    S: ConnectorService<Request>,
    Input: ConnectorTargetInputExt + ProtocolInputExt + TransportProtocolInputExt,
{
    let transport_input = make_transport_input(input, port, ip, Some(domain));
    connect_attempts.push(
        async move {
            let result = inner
                .connect(transport_input)
                .await
                .map_err(Into::<BoxError>::into);
            (ip, result)
        }
        .boxed(),
    );
}

fn ensure_ip_connect_mode(
    extensions: &rama_core::extensions::Extensions,
    ip: IpAddr,
) -> Result<(), BoxError> {
    let mode = extensions.get_ref().copied().unwrap_or(ConnectIpMode::Dual);
    match (ip, mode) {
        (IpAddr::V4(_), ConnectIpMode::Ipv6) => {
            Err(BoxError::from_static_str("IPv4 address is not allowed"))
        }
        (IpAddr::V6(_), ConnectIpMode::Ipv4) => {
            Err(BoxError::from_static_str("IPv6 address is not allowed"))
        }
        (IpAddr::V4(_), ConnectIpMode::Ipv4 | ConnectIpMode::Dual)
        | (IpAddr::V6(_), ConnectIpMode::Ipv6 | ConnectIpMode::Dual) => Ok(()),
    }
}

fn make_transport_input<Input>(
    input: &Input,
    port: u16,
    ip: IpAddr,
    resolved_domain: Option<Domain>,
) -> Request
where
    Input: ConnectorTargetInputExt + ProtocolInputExt + TransportProtocolInputExt,
{
    let target = HostWithPort::new(Host::Address(ip), port);
    let extensions = input.extensions().fork();
    extensions.insert(ConnectorTarget(target.clone()));
    if let Some(domain) = resolved_domain {
        extensions.insert(ResolvedDomain(domain));
    }

    let mut req = Request::new_with_extensions(target, extensions);
    req.application_protocol = input.protocol().cloned();
    req.transport_protocol = input.transport_protocol();
    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        extensions::{Extensions, ExtensionsRef},
        futures::{Stream, stream},
    };
    use rama_net::{
        AuthorityInputExt, Protocol, address::HostWithOptPort, transport::TransportProtocol,
    };
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[derive(Clone)]
    struct StaticResolver {
        ips: Vec<Ipv4Addr>,
    }

    impl DnsAddressResolver for StaticResolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::iter(self.ips.clone().into_iter().map(Ok))
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }
    }

    struct FakeInput {
        extensions: Extensions,
        authority: HostWithPort,
    }

    impl ExtensionsRef for FakeInput {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl AuthorityInputExt for FakeInput {
        fn authority(&self) -> Option<HostWithOptPort> {
            Some(self.authority.clone().into())
        }
    }

    impl ProtocolInputExt for FakeInput {
        fn protocol(&self) -> Option<&Protocol> {
            Some(&Protocol::HTTPS)
        }
    }

    impl TransportProtocolInputExt for FakeInput {
        fn transport_protocol(&self) -> Option<TransportProtocol> {
            Some(TransportProtocol::Tcp)
        }
    }

    #[derive(Clone)]
    struct TestConn {
        extensions: Extensions,
    }

    impl ExtensionsRef for TestConn {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    #[derive(Clone, Default)]
    struct RecordingTransport {
        targets: Arc<Mutex<Vec<HostWithPort>>>,
        fail_count: Arc<AtomicUsize>,
    }

    impl RecordingTransport {
        fn with_fail_count(count: usize) -> Self {
            Self {
                targets: Arc::default(),
                fail_count: Arc::new(AtomicUsize::new(count)),
            }
        }

        fn targets(&self) -> Vec<HostWithPort> {
            self.targets.lock().unwrap().clone()
        }
    }

    impl Service<Request> for RecordingTransport {
        type Output = EstablishedClientConnection<TestConn, Request>;
        type Error = BoxError;

        async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
            self.targets.lock().unwrap().push(input.authority.clone());
            if self.fail_count.load(Ordering::Acquire) > 0 {
                self.fail_count.fetch_sub(1, Ordering::AcqRel);
                return Err(BoxError::from_static_str("intentional connect failure"));
            }
            Ok(EstablishedClientConnection {
                input,
                conn: TestConn {
                    extensions: Extensions::new(),
                },
            })
        }
    }

    fn fake_input() -> FakeInput {
        FakeInput {
            extensions: Extensions::new(),
            authority: HostWithPort::example_domain_https(),
        }
    }

    #[tokio::test]
    async fn resolves_domain_and_stamps_extensions() {
        let transport = RecordingTransport::default();
        let resolver = StaticResolver {
            ips: vec![Ipv4Addr::new(127, 0, 0, 1)],
        };
        let connector = DnsConnector::with_resolver(transport.clone(), resolver);

        let output = connector.serve(fake_input()).await.unwrap();

        let target = output
            .input
            .extensions()
            .get_ref::<ConnectorTarget>()
            .unwrap();
        assert_eq!(
            target.0,
            HostWithPort::from((Ipv4Addr::new(127, 0, 0, 1), 443))
        );
        assert_eq!(
            output
                .input
                .extensions()
                .get_ref::<ResolvedDomain>()
                .unwrap()
                .0,
            Domain::example()
        );
        assert_eq!(
            transport.targets(),
            vec![HostWithPort::from((Ipv4Addr::new(127, 0, 0, 1), 443))]
        );
    }

    #[tokio::test]
    async fn retries_next_resolved_ip_after_connect_failure() {
        let transport = RecordingTransport::with_fail_count(1);
        let resolver = StaticResolver {
            ips: vec![Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)],
        };
        let connector = DnsConnector::with_resolver(transport.clone(), resolver);

        let output = connector.serve(fake_input()).await.unwrap();

        assert_eq!(
            output
                .input
                .extensions()
                .get_ref::<ConnectorTarget>()
                .unwrap()
                .0,
            HostWithPort::from((Ipv4Addr::new(127, 0, 0, 2), 443))
        );
        assert_eq!(
            transport.targets(),
            vec![
                HostWithPort::from((Ipv4Addr::new(127, 0, 0, 1), 443)),
                HostWithPort::from((Ipv4Addr::new(127, 0, 0, 2), 443)),
            ]
        );
    }
}
