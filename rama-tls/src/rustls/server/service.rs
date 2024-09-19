use crate::{
    rustls::dep::{
        rustls::server::Acceptor,
        tokio_rustls::{server::TlsStream, LazyConfigAcceptor, TlsAcceptor},
    },
    types::client::ClientHello,
    types::SecureTransport,
};
use rama_core::{
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    Context, Service,
};
use rama_net::{
    stream::Stream,
    tls::{client::NegotiatedTlsParameters, ApplicationProtocol},
};
use rama_utils::macros::define_inner_service_accessors;

use super::{client_config::ServiceDataProvider, TlsAcceptorData, TlsClientConfigHandler};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
pub struct TlsAcceptorService<S, H> {
    data: TlsAcceptorData,
    client_config_handler: H,
    inner: S,
}

impl<S, H> TlsAcceptorService<S, H> {
    /// Creates a new [`TlsAcceptorService`].
    pub const fn new(data: TlsAcceptorData, inner: S, client_config_handler: H) -> Self {
        Self {
            data,
            client_config_handler,
            inner,
        }
    }

    define_inner_service_accessors!();
}

impl<S: std::fmt::Debug, H: std::fmt::Debug> std::fmt::Debug for TlsAcceptorService<S, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorService")
            .field("data", &self.data)
            .field("client_config_handler", &self.client_config_handler)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S, H> Clone for TlsAcceptorService<S, H>
where
    S: Clone,
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            client_config_handler: self.client_config_handler.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<T, S, IO> Service<T, IO> for TlsAcceptorService<S, ()>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>, Error: Into<BoxError>>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let acceptor = TlsAcceptor::from(self.data.server_config.clone());

        let stream = acceptor.accept(stream).await?;
        let (_, conn_data_ref) = stream.get_ref();
        ctx.insert(NegotiatedTlsParameters {
            protocol_version: conn_data_ref
                .protocol_version()
                .context("no protocol version available")?
                .into(),
            application_layer_protocol: conn_data_ref
                .alpn_protocol()
                .map(ApplicationProtocol::from),
        });

        ctx.insert(SecureTransport::default());
        self.inner.serve(ctx, stream).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("rustls acceptor: service error")
                .into_boxed()
        })
    }
}

impl<T, S, IO> Service<T, IO> for TlsAcceptorService<S, TlsClientConfigHandler<()>>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>, Error: Into<BoxError>>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);

        let start = acceptor.await?;

        let secure_transport = if self.client_config_handler.store_client_hello {
            SecureTransport::with_client_hello(start.client_hello().into())
        } else {
            SecureTransport::default()
        };

        let stream = start.into_stream(self.data.server_config.clone()).await?;
        let (_, conn_data_ref) = stream.get_ref();
        ctx.insert(NegotiatedTlsParameters {
            protocol_version: conn_data_ref
                .protocol_version()
                .context("no protocol version available")?
                .into(),
            application_layer_protocol: conn_data_ref
                .alpn_protocol()
                .map(ApplicationProtocol::from),
        });

        ctx.insert(secure_transport);
        self.inner.serve(ctx, stream).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("rustls acceptor: service error")
                .into_boxed()
        })
    }
}

impl<T, S, IO, F> Service<T, IO> for TlsAcceptorService<S, TlsClientConfigHandler<F>>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, TlsStream<IO>, Error: Into<BoxError>>,
    F: ServiceDataProvider<Error: Into<BoxError>>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);

        let start = acceptor.await?;

        let accepted_client_hello = ClientHello::from(start.client_hello());

        let secure_transport = if self.client_config_handler.store_client_hello {
            SecureTransport::with_client_hello(accepted_client_hello.clone())
        } else {
            SecureTransport::default()
        };

        let service_data = self
            .client_config_handler
            .service_data_provider
            .get_service_data(accepted_client_hello)
            .await
            .map_err(Into::into)?
            .unwrap_or_else(|| self.data.clone());

        let stream = start.into_stream(service_data.server_config).await?;

        let (_, conn_data_ref) = stream.get_ref();
        ctx.insert(NegotiatedTlsParameters {
            protocol_version: conn_data_ref
                .protocol_version()
                .context("no protocol version available")?
                .into(),
            application_layer_protocol: conn_data_ref
                .alpn_protocol()
                .map(ApplicationProtocol::from),
        });

        ctx.insert(secure_transport);
        self.inner.serve(ctx, stream).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("rustls acceptor: service error")
                .into_boxed()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_send() {
        use rama_utils::test_helpers::assert_send;

        assert_send::<TlsAcceptorService<(), ()>>();
        assert_send::<TlsAcceptorService<(), TlsClientConfigHandler<()>>>();
    }

    #[test]
    fn assert_sync() {
        use rama_utils::test_helpers::assert_sync;

        assert_sync::<TlsAcceptorService<(), ()>>();
        assert_sync::<TlsAcceptorService<(), TlsClientConfigHandler<()>>>();
    }
}
