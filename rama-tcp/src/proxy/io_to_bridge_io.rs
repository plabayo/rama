use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::ExtensionsRef,
    io::{BridgeIo, Io},
    rt::Executor,
    telemetry::tracing,
};
use rama_net::{
    address::HostWithPort,
    client::ConnectorTarget,
    client::{ConnectorService, EstablishedClientConnection, Request},
};
use rama_utils::macros::define_inner_service_accessors;

use crate::client::service::TcpConnector;

// TOOD: in future we can move this out of rama-tcp...
// need to find some kind of input which is not tcp specific,
// at that point it us no longer bound to tcp at all

#[derive(Debug, Clone)]
pub struct IoToProxyBridgeIo<S, C = TcpConnector> {
    inner: S,
    connector: C,
    address_provider: AddressProvider,
}

#[derive(Debug, Clone)]
enum AddressProvider {
    Static(HostWithPort),
    ExtensionConnectorTarget,
}

impl<S> IoToProxyBridgeIo<S> {
    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIo`] service,
    /// which will use the provided target info to connect to.
    ///
    /// Use [`Self::extension_connector_target`] if you wish to have it be done
    /// using the [`ConnectorTarget`] extension instead, failing the input flow
    /// in case that extension not exist.
    pub fn new(inner: S, exec: Executor, target: HostWithPort) -> Self {
        Self {
            inner,
            connector: TcpConnector::new(exec),
            address_provider: AddressProvider::Static(target),
        }
    }

    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIo`] service,
    /// which expects while serving that [`ConnectorTarget`]
    /// is available in the input's extension, and fail otherwise.
    ///
    /// Use [`Self::new`] if you wish to use a hardcoded target instead,
    pub fn extension_connector_target(exec: Executor, inner: S) -> Self {
        Self {
            inner,
            connector: TcpConnector::new(exec),
            address_provider: AddressProvider::ExtensionConnectorTarget,
        }
    }

    define_inner_service_accessors!();
}

impl<S> IoToProxyBridgeIo<S> {
    /// Set a custom "connector" for service, overwriting
    /// the default tcp forwarder which simply establishes a TCP connection.
    ///
    /// This can be useful for any custom middleware, but also to enrich with
    /// rama-provided services for tls connections, HAproxy client endoding
    /// or even an entirely custom tcp connector service.
    pub fn with_connector<C>(self, connector: C) -> IoToProxyBridgeIo<S, C> {
        IoToProxyBridgeIo {
            inner: self.inner,
            connector,
            address_provider: self.address_provider,
        }
    }
}

/// A [`Layer`] that produces [`IoToProxyBridgeIo`] services.
#[derive(Debug, Clone)]
pub struct IoToProxyBridgeIoLayer<C = TcpConnector> {
    connector: C,
    address_provider: AddressProvider,
}

impl IoToProxyBridgeIoLayer {
    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIoLayer`],
    /// which will use by the [`IoToProxyBridgeIo`] [`Service`] the provided target info to connect to.
    ///
    /// Use [`Self::extension_connector_target`] if you wish to have it be done
    /// using the [`ConnectorTarget`] extension instead, failing the input flow
    /// in case that extension not exist.
    pub fn new(exec: Executor, target: impl Into<HostWithPort>) -> Self {
        Self {
            connector: TcpConnector::new(exec),
            address_provider: AddressProvider::Static(target.into()),
        }
    }

    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIoLayer`],
    /// which will create the [`IoToProxyBridgeIo`] [`Service`]
    /// that with this constructor will expect while serving that [`ConnectorTarget`]
    /// is available in the input's extension, and fail otherwise.
    ///
    /// Use [`Self::new`] if you wish to use a hardcoded target instead,
    pub fn extension_connector_target(exec: Executor) -> Self {
        Self {
            connector: TcpConnector::new(exec),
            address_provider: AddressProvider::ExtensionConnectorTarget,
        }
    }
}

impl IoToProxyBridgeIoLayer {
    /// Set a custom "connector" for layer's service, overwriting
    /// the default tcp forwarder which simply establishes a TCP connection.
    ///
    /// This can be useful for any custom middleware, but also to enrich with
    /// rama-provided services for tls connections, HAproxy client endoding
    /// or even an entirely custom tcp connector service.
    pub fn with_connector<C>(self, connector: C) -> IoToProxyBridgeIoLayer<C> {
        IoToProxyBridgeIoLayer {
            connector,
            address_provider: self.address_provider,
        }
    }
}

impl<C> IoToProxyBridgeIoLayer<C> {
    #[inline(always)]
    /// Same as [`Self::new`] but using a custom connector.
    pub fn new_with_connector(target: impl Into<HostWithPort>, connector: C) -> Self {
        Self {
            connector,
            address_provider: AddressProvider::Static(target.into()),
        }
    }

    #[inline(always)]
    /// Same as [`Self::extension_connector_target`] but using a custom connector.
    pub fn extension_connector_target_with_connector(connector: C) -> Self {
        Self {
            connector,
            address_provider: AddressProvider::ExtensionConnectorTarget,
        }
    }
}

impl<S, C> Layer<S> for IoToProxyBridgeIoLayer<C>
where
    C: Clone,
{
    type Service = IoToProxyBridgeIo<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            connector: self.connector.clone(),
            address_provider: self.address_provider.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            connector: self.connector.clone(),
            address_provider: self.address_provider,
        }
    }
}

impl<S, Ingress, C> Service<Ingress> for IoToProxyBridgeIo<S, C>
where
    S: Service<BridgeIo<Ingress, C::Connection>, Error: Into<BoxError>>,
    Ingress: Io + ExtensionsRef,
    C: ConnectorService<Request, Connection: Io + Unpin>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, ingress: Ingress) -> Result<Self::Output, Self::Error> {
        let egress_addr = match self.address_provider.clone() {
            AddressProvider::Static(host_with_port) => host_with_port,
            AddressProvider::ExtensionConnectorTarget => {
                if let Some(ConnectorTarget(host_with_port)) =
                    ingress.extensions().get_ref().cloned()
                {
                    host_with_port
                } else {
                    return Err(BoxError::from_static_str(
                        "missing ConnectorTarget in IoToProxyBridgeIo: connector (proxy) target assumed to exist in ingress extensions",
                    ));
                }
            }
        };

        tracing::trace!(
            "try to establish connection to egress as a means to create a BridgeIo: addr = {egress_addr}"
        );

        let tcp_req =
            Request::new_with_extensions(egress_addr.clone(), ingress.extensions().fork());

        let EstablishedClientConnection {
            input: _,
            conn: egress,
        } = self
            .connector
            .connect(tcp_req)
            .await
            .context("establish tcp connection")
            .context_field("address", egress_addr)?;

        let bridge_io = BridgeIo(ingress, egress);
        self.inner.serve(bridge_io).await.into_box_error()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };

    use rama_core::{
        error::BoxError,
        extensions::{Extension, Extensions, ExtensionsRef},
        service::service_fn,
    };
    use rama_net::address::HostWithPort;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    #[derive(Debug, Clone, Extension)]
    struct InheritedMarker;

    #[derive(Debug, Clone, Extension)]
    struct ConnectorOnlyMarker;

    #[derive(Debug)]
    struct TestIo {
        extensions: Extensions,
    }

    impl TestIo {
        fn new() -> Self {
            Self {
                extensions: Extensions::new(),
            }
        }
    }

    impl ExtensionsRef for TestIo {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone)]
    struct CapturingConnector {
        expected_addr: HostWithPort,
        saw_connector_request: Arc<AtomicBool>,
    }

    impl Service<Request> for CapturingConnector {
        type Output = EstablishedClientConnection<TestIo, Request>;
        type Error = BoxError;

        async fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
            assert_eq!(input.authority, self.expected_addr);
            assert!(
                input.extensions().parent().is_some(),
                "egress request extensions should be forked from ingress extensions"
            );
            assert!(
                input.extensions().get_ref::<InheritedMarker>().is_some(),
                "egress request should inherit ingress extensions"
            );

            input.extensions().insert(ConnectorOnlyMarker);
            self.saw_connector_request.store(true, Ordering::SeqCst);

            Ok(EstablishedClientConnection {
                input,
                conn: TestIo::new(),
            })
        }
    }

    #[tokio::test]
    async fn egress_request_forks_ingress_extensions() {
        let target = HostWithPort::local_ipv4(8080);
        let saw_connector_request = Arc::new(AtomicBool::new(false));
        let saw_bridge = Arc::new(AtomicBool::new(false));

        let connector = CapturingConnector {
            expected_addr: target.clone(),
            saw_connector_request: saw_connector_request.clone(),
        };

        let inner = service_fn({
            let saw_bridge = saw_bridge.clone();
            move |bridge_io: BridgeIo<TestIo, TestIo>| {
                let saw_bridge = saw_bridge.clone();
                async move {
                    assert!(
                        bridge_io
                            .0
                            .extensions()
                            .get_ref::<InheritedMarker>()
                            .is_some(),
                        "ingress should keep its original extensions"
                    );
                    assert!(
                        bridge_io
                            .0
                            .extensions()
                            .get_ref::<ConnectorOnlyMarker>()
                            .is_none(),
                        "connector-local egress mutations must not leak back into ingress"
                    );
                    saw_bridge.store(true, Ordering::SeqCst);
                    Ok::<_, Infallible>(())
                }
            }
        });

        let service = IoToProxyBridgeIoLayer::extension_connector_target_with_connector(connector)
            .into_layer(inner);

        let ingress = TestIo::new();
        ingress.extensions().insert(InheritedMarker);
        ingress.extensions().insert(ConnectorTarget(target));

        service.serve(ingress).await.unwrap();

        assert!(saw_connector_request.load(Ordering::SeqCst));
        assert!(saw_bridge.load(Ordering::SeqCst));
    }
}
