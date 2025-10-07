use super::TlsAcceptorData;
use super::TlsStream;
use super::acceptor_data::ServerConfig;
use crate::dep::rustls::server::Acceptor;
use crate::dep::tokio_rustls::LazyConfigAcceptor;
use crate::types::SecureTransport;
use rama_core::{
    Service,
    conversion::RamaInto,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    extensions::ExtensionsMut,
    stream::Stream,
};
use rama_net::tls::{ApplicationProtocol, client::NegotiatedTlsParameters};
use rama_utils::macros::define_inner_service_accessors;

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
pub struct TlsAcceptorService<S> {
    data: TlsAcceptorData,
    store_client_hello: bool,
    inner: S,
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`].
    pub const fn new(data: TlsAcceptorData, inner: S, store_client_hello: bool) -> Self {
        Self {
            data,
            store_client_hello,
            inner,
        }
    }

    define_inner_service_accessors!();
}

impl<S: std::fmt::Debug> std::fmt::Debug for TlsAcceptorService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorService")
            .field("data", &self.data)
            .field("store_client_hello", &self.store_client_hello)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> Clone for TlsAcceptorService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            store_client_hello: self.store_client_hello,
            inner: self.inner.clone(),
        }
    }
}

impl<S, IO> Service<IO> for TlsAcceptorService<S>
where
    IO: Stream + Unpin + ExtensionsMut + 'static,
    S: Service<TlsStream<IO>, Error: Into<BoxError>>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, stream: IO) -> Result<Self::Response, Self::Error> {
        let tls_acceptor_data = stream
            .extensions()
            .get::<TlsAcceptorData>()
            .unwrap_or(&self.data)
            .clone();

        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), stream);

        let start = acceptor.await?;

        let secure_transport = if self.store_client_hello {
            SecureTransport::with_client_hello(start.client_hello().rama_into())
        } else {
            SecureTransport::default()
        };

        let server_config = match &tls_acceptor_data.server_config {
            ServerConfig::Stored(server_config) => server_config.clone(),
            ServerConfig::Async(dynamic) => dynamic.get_config(start.client_hello()).await?,
        };

        let stream = start.into_stream(server_config).await?;
        let mut stream = TlsStream::new(stream);

        let (_, conn_data_ref) = stream.stream.get_ref();
        let negotiated_tls_params = NegotiatedTlsParameters {
            protocol_version: conn_data_ref
                .protocol_version()
                .context("no protocol version available")?
                .rama_into(),
            application_layer_protocol: conn_data_ref
                .alpn_protocol()
                .map(ApplicationProtocol::from),
            // Currently not supported as this would mean we need to wrap rustls config
            peer_certificate_chain: None,
        };

        stream.extensions_mut().insert(negotiated_tls_params);
        stream.extensions_mut().insert(secure_transport);

        self.inner.serve(stream).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("rustls acceptor: service error")
                .into_boxed()
        })
    }
}
