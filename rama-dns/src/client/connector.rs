use std::net::SocketAddr;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::Extensions,
    futures::{StreamExt, stream::BoxStream},
};
use rama_net::{
    ConnectorTargetInputExt,
    address::{Domain, Host, HostWithPort},
    client::{
        AddressCandidates, ConnectorService, ConnectorTargetStream, EstablishedClientConnection,
    },
};
use rama_utils::macros::define_inner_service_accessors;

use crate::client::resolver::HappyEyeballAddressResolverExt;

use super::{GlobalDnsResolver, resolver::DnsAddressResolver};

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

#[derive(Debug, Clone)]
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
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let HostWithPort { host, port } = input
            .connector_target()
            .context("dns connector: get connector target from input")?;

        // Already an IP target: nothing to resolve, forward the input untouched.
        if host.try_as_ip().is_ok() {
            return self.inner.connect(input).await.map_err(Into::into);
        }

        // Domain target: stamp a lazy candidate source for the transport to
        // resolve + dial, and forward the (untouched) input.
        let domain = host
            .try_into_domain()
            .context("dns connector: connector target host is not resolvable as a domain")?;
        input
            .extensions()
            .insert(ConnectorTargetStream::new(DnsAddressCandidates::new(
                self.resolver.clone(),
                domain,
                port,
            )));

        self.inner.connect(input).await.map_err(Into::into)
    }
}

/// [`AddressCandidates`] backed by a [`DnsAddressResolver`].
///
/// Resolves a domain target into a happy-eyeballs-ordered stream of
/// [`SocketAddr`]esses.
pub struct DnsAddressCandidates<R> {
    resolver: R,
    domain: Domain,
    port: u16,
}

impl<R> DnsAddressCandidates<R> {
    /// Create a new [`DnsAddressCandidates`] resolving `domain:port` via `resolver`.
    #[must_use]
    pub const fn new(resolver: R, domain: Domain, port: u16) -> Self {
        Self {
            resolver,
            domain,
            port,
        }
    }
}

impl<R> AddressCandidates for DnsAddressCandidates<R>
where
    R: DnsAddressResolver,
{
    fn stream<'a>(
        &'a self,
        extensions: &'a Extensions,
    ) -> BoxStream<'a, Result<SocketAddr, BoxError>> {
        let port = self.port;
        self.resolver
            .happy_eyeballs_resolver(Host::Name(self.domain.clone()))
            .with_extensions(extensions)
            .lookup_ip()
            .map(move |result| result.map(|ip| SocketAddr::new(ip, port)).into_box_error())
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
    };
    use std::sync::Arc;

    struct FakeInput {
        extensions: Extensions,
        authority: HostWithPort,
    }

    impl FakeInput {
        fn new(authority: HostWithPort) -> Self {
            Self {
                extensions: Extensions::new(),
                authority,
            }
        }
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

    #[derive(Clone)]
    struct TestConn {
        extensions: Extensions,
    }

    impl ExtensionsRef for TestConn {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
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
}
