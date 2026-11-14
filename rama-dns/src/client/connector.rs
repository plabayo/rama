use std::net::IpAddr;

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::Extensions,
    extensions::ExtensionsRef,
    futures::{StreamExt, stream::BoxStream},
};
use rama_net::{
    ConnectorTargetInputExt,
    address::{Domain, Host},
    client::{
        AddressCandidates, ConnectionAttempt, ConnectionError, ConnectionErrorKind,
        ConnectorService, ConnectorTargetStream, EstablishedClientConnection,
    },
    mode::{ConnectIpMode, DnsResolveIpMode},
};
use rama_utils::macros::define_inner_service_accessors;

use crate::client::resolver::HappyEyeballAddressResolverExt;

use super::{
    GlobalDnsResolver,
    resolver::{DnsAddressResolver, DnsAddresssResolverOverwrite},
};

#[derive(Debug, Clone)]
/// A [`Layer`] which wraps a transport connector with DNS resolution.
///
/// The produced [`DnsConnector`] resolves a domain
/// [`ConnectorTargetInputExt::connector_target`] into a lazy, happy-eyeballs-
/// ordered stream of IP targets, puts it into the [`Extensions`] as a
/// [`ConnectorTargetStream`], and forwards the (untouched) input to the inner
/// transport connector, which then dials/races the candidate addresses.
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

#[derive(Debug, Clone, ExtensionsRef)]
/// A connector service that stamps a lazy DNS [`ConnectorTargetStream`] for a
/// domain target, then forwards the input to the inner transport connector.
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
    S: ConnectorService<Input>,
    Input: ConnectorTargetInputExt + Send + 'static,
    R: DnsAddressResolver + Clone,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let extensions = input.extensions();
        // Request-local DNS and address-family policy can change which peers are
        // reachable. Keep its outcomes out of shared discovery/backoff, including
        // IP literals. Include future request-level resolver controls here too.
        if extensions.contains::<DnsAddresssResolverOverwrite>()
            || extensions.contains::<ConnectIpMode>()
            || extensions.contains::<DnsResolveIpMode>()
        {
            if let Some(attempt) = extensions.get_ref::<ConnectionAttempt>() {
                attempt.restrict_to_request_policy();
            } else {
                let attempt = ConnectionAttempt::new();
                attempt.restrict_to_request_policy();
                extensions.insert(attempt);
            }
        }
        let target = input.connector_target().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("dns connector: connector target missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;

        // Already an IP target: nothing to resolve, forward the input untouched.
        if target.host.try_as_ip().is_ok() {
            return self.inner.connect(input).await;
        }

        // Explicit request resolver policy overrides upstream discovery facts.
        if !extensions.contains::<DnsAddresssResolverOverwrite>()
            && extensions
                .get_ref::<ConnectorTargetStream>()
                .is_some_and(|candidates| candidates.matches_target(&target))
        {
            return self.inner.connect(input).await;
        }

        // Domain target: stamp a lazy candidate source for the transport to
        // resolve + dial, and forward the (untouched) input.
        let domain = target.host.clone().try_into_domain().map_err(|error| {
            ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                .context("dns connector: connector target host is not resolvable as a domain")
        })?;
        input.extensions().insert(ConnectorTargetStream::new(
            target,
            DnsAddressCandidates {
                resolver: self.resolver.clone(),
                domain,
            },
        ));

        self.inner.connect(input).await
    }
}

/// [`AddressCandidates`] backed by a [`DnsAddressResolver`].
///
/// Resolves a domain target into a happy-eyeballs-ordered stream of
/// [`IpAddr`]esses.
struct DnsAddressCandidates<R> {
    resolver: R,
    domain: Domain,
}

impl<R> AddressCandidates for DnsAddressCandidates<R>
where
    R: DnsAddressResolver,
{
    fn domain(&self) -> &Domain {
        &self.domain
    }

    fn stream<'a>(&'a self, extensions: &'a Extensions) -> BoxStream<'a, Result<IpAddr, BoxError>> {
        self.resolver
            .happy_eyeballs_resolver(Host::Name(self.domain.clone()))
            .with_extensions(extensions)
            .lookup_ip()
            .map(|result| result.into_box_error())
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::EmptyDnsResolver;
    use parking_lot::Mutex;
    use rama_core::extensions::{Extensions, ExtensionsRef};
    use rama_net::{
        AuthorityInputExt, Protocol, ProtocolInputExt,
        address::{Host, HostWithOptPort, HostWithPort},
        client::{ConnectionErrorDomain, ConnectionErrorKind},
    };
    use std::sync::Arc;

    #[derive(Debug, ExtensionsRef)]
    struct FakeInput {
        extensions: Extensions,
        authority: Option<HostWithPort>,
    }

    impl FakeInput {
        fn new(authority: HostWithPort) -> Self {
            Self {
                extensions: Extensions::new(),
                authority: Some(authority),
            }
        }

        fn without_authority() -> Self {
            Self {
                extensions: Extensions::new(),
                authority: None,
            }
        }
    }

    impl AuthorityInputExt for FakeInput {
        fn authority(&self) -> Option<HostWithOptPort> {
            self.authority.clone().map(Into::into)
        }
    }

    impl ProtocolInputExt for FakeInput {
        fn protocol(&self) -> Option<&Protocol> {
            Some(&Protocol::HTTPS)
        }
    }

    #[derive(Clone, Debug, ExtensionsRef)]
    struct TestConn {
        extensions: Extensions,
    }

    /// Inner connector that records whether it was called and whether a
    /// [`ConnectorTargetStream`] was present on the (forwarded) input.
    #[derive(Clone, Default)]
    struct RecordingInner {
        saw_candidate_stream: Arc<Mutex<Option<bool>>>,
    }

    impl Service<FakeInput> for RecordingInner {
        type Output = EstablishedClientConnection<TestConn, FakeInput>;
        type Error = BoxError;

        async fn serve(&self, input: FakeInput) -> Result<Self::Output, Self::Error> {
            *self.saw_candidate_stream.lock() = Some(
                input
                    .extensions()
                    .get_ref::<ConnectorTargetStream>()
                    .is_some(),
            );
            Ok(EstablishedClientConnection {
                input,
                conn: TestConn {
                    extensions: Extensions::new(),
                },
            })
        }
    }

    #[tokio::test]
    async fn stamps_candidate_stream_for_domain_target() {
        let inner = RecordingInner::default();
        let connector = DnsConnector::with_resolver(inner.clone(), EmptyDnsResolver::new());

        let input = FakeInput::new(HostWithPort::example_domain_https());
        let out = connector.serve(input).await.unwrap();

        // inner saw the stamped candidate source on the forwarded input...
        assert_eq!(*inner.saw_candidate_stream.lock(), Some(true));
        // ...and the input flowed through untouched (still carries it).
        assert!(
            out.input
                .extensions()
                .get_ref::<ConnectorTargetStream>()
                .is_some()
        );
        assert_eq!(
            out.input
                .extensions()
                .get_ref::<ConnectorTargetStream>()
                .unwrap()
                .domain(),
            &Domain::example()
        );
    }

    #[tokio::test]
    async fn missing_target_is_local_invalid_input() {
        let connector =
            DnsConnector::with_resolver(RecordingInner::default(), EmptyDnsResolver::new());

        let error = connector
            .serve(FakeInput::without_authority())
            .await
            .expect_err("missing connector target should fail");
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn forwards_ip_target_without_stamping() {
        let inner = RecordingInner::default();
        let connector = DnsConnector::with_resolver(inner.clone(), EmptyDnsResolver::new());

        let input = FakeInput::new(HostWithPort::new(
            Host::Address(std::net::Ipv4Addr::LOCALHOST.into()),
            443,
        ));
        let out = connector.serve(input).await.unwrap();

        // no resolution needed → no candidate stream stamped.
        assert_eq!(*inner.saw_candidate_stream.lock(), Some(false));
        assert!(
            out.input
                .extensions()
                .get_ref::<ConnectorTargetStream>()
                .is_none()
        );
    }
    struct FixedCandidates(Domain);

    impl AddressCandidates for FixedCandidates {
        fn domain(&self) -> &Domain {
            &self.0
        }
        fn stream<'a>(&'a self, _: &'a Extensions) -> BoxStream<'a, Result<IpAddr, BoxError>> {
            rama_core::futures::stream::iter([Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))])
                .boxed()
        }
    }

    #[tokio::test]
    async fn preserves_matching_source_unless_target_or_caller_resolver_changes() {
        use rama_net::client::ConnectorTarget;
        for override_resolver in [false, true] {
            for target in [
                HostWithPort::example_domain_https(),
                HostWithPort::example_domain_with_port(8443),
                HostWithPort::new(Host::Name(Domain::from_static("other.example")), 443),
            ] {
                let original = HostWithPort::example_domain_https();
                let input = FakeInput::new(original.clone());
                let source = Arc::new(ConnectorTargetStream::new(
                    original.clone(),
                    FixedCandidates(Domain::example()),
                ));
                input.extensions().insert_arc(source.clone());
                if override_resolver {
                    input
                        .extensions()
                        .insert(DnsAddresssResolverOverwrite::new(EmptyDnsResolver::new()));
                }
                input.extensions().insert(ConnectorTarget(target.clone()));
                let connector =
                    DnsConnector::with_resolver(RecordingInner::default(), EmptyDnsResolver::new());
                let result = connector.serve(input).await.unwrap();
                let installed = result
                    .input
                    .extensions()
                    .get_arc::<ConnectorTargetStream>()
                    .unwrap();
                assert_eq!(installed.target(), &target);
                assert!(installed.matches_target(&target));
                assert_eq!(
                    Arc::ptr_eq(&source, &installed),
                    target == original && !override_resolver
                );
                // The empty resolver cannot supply this address: observing it proves
                // the preinstalled source survived the downstream DNS connector.
                let addresses: Vec<_> = installed.stream(result.input.extensions()).collect().await;
                if target == original && !override_resolver {
                    assert_eq!(addresses.len(), 1);
                    assert_eq!(
                        addresses.into_iter().next().unwrap().unwrap(),
                        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                    );
                } else {
                    assert!(addresses.is_empty());
                }
            }
        }
    }
}
