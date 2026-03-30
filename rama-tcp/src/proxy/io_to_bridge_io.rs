use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef,
    io::{BridgeIo, Io},
    rt::Executor,
    telemetry::tracing,
};
use rama_net::{
    address::HostWithPort,
    client::{ConnectorService, EstablishedClientConnection},
    proxy::ProxyTarget,
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
    ExtensionProxyTarget,
}

impl<S> IoToProxyBridgeIo<S> {
    #[inline(always)]
    /// Creates a new [`IoToProxyBridgeIo`] service,
    /// which will use the provided target info to connect to.
    ///
    /// Use [`Self::extension_proxy_target`] if you wish to have it be done
    /// using the [`ProxyTarget`] extension instead, failing the input flow
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
    /// which expects while serving that [`ProxyTarget`]
    /// is available in the input's extension, and fail otherwise.
    ///
    /// Use [`Self::new`] if you wish to use a hardcoded target instead,
    pub fn extension_proxy_target(exec: Executor, inner: S) -> Self {
        Self {
            inner,
            connector: TcpConnector::new(exec),
            address_provider: AddressProvider::ExtensionProxyTarget,
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
    /// Use [`Self::extension_proxy_target`] if you wish to have it be done
    /// using the [`ProxyTarget`] extension instead, failing the input flow
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
    /// that with this constructor will expect while serving that [`ProxyTarget`]
    /// is available in the input's extension, and fail otherwise.
    ///
    /// Use [`Self::new`] if you wish to use a hardcoded target instead,
    pub fn extension_proxy_target(exec: Executor) -> Self {
        Self {
            connector: TcpConnector::new(exec),
            address_provider: AddressProvider::ExtensionProxyTarget,
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
    /// Same as [`Self::extension_proxy_target`] but using a custom connector.
    pub fn extension_proxy_target_with_connector(connector: C) -> Self {
        Self {
            connector,
            address_provider: AddressProvider::ExtensionProxyTarget,
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
    C: ConnectorService<crate::client::Request, Connection: Io + Unpin>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, ingress: Ingress) -> Result<Self::Output, Self::Error> {
        let egress_addr = match self.address_provider.clone() {
            AddressProvider::Static(host_with_port) => host_with_port,
            AddressProvider::ExtensionProxyTarget => {
                if let Some(ProxyTarget(host_with_port)) = ingress.extensions().get().cloned() {
                    host_with_port
                } else {
                    return Err(BoxError::from(
                        "missing ProxyTarget in IoToProxyBridgeIo: proxy target assumed to exist in ingress extensions",
                    ));
                }
            }
        };

        tracing::trace!(
            "try to establish connection to egress as a means to create a BridgeIo: addr = {egress_addr}"
        );

        let extensions = ingress.extensions().clone();
        let tcp_req = crate::client::Request::new_with_extensions(egress_addr.clone(), extensions);

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
