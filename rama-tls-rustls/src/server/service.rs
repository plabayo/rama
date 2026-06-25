use super::TlsAcceptorData;
use super::TlsStream;
use super::acceptor_data::ServerConfig;
use super::config::RustlsTlsAcceptorConfig;
use crate::dep::rustls::server::Acceptor;
use crate::dep::tokio_rustls::LazyConfigAcceptor;
use crate::types::SecureTransport;
use rama_core::{
    Service,
    conversion::RamaInto,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    io::Io,
};
use rama_net::extensions::StreamTransformed;
use rama_tls::{ApplicationProtocol, client::NegotiatedTlsParameters, server::TlsServerConfig};
use rama_utils::macros::define_inner_service_accessors;

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
#[derive(Debug, Clone)]
pub struct TlsAcceptorService<S> {
    config: TlsServerConfig,
    store_client_hello: bool,
    inner: S,
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`].
    pub fn new(config: TlsServerConfig, inner: S, store_client_hello: bool) -> Self {
        Self {
            config,
            store_client_hello,
            inner,
        }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<IO> for TlsAcceptorService<S>
where
    IO: Io + Unpin + ExtensionsRef + 'static,
    S: Service<TlsStream<IO>, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        let merged = stream.extensions().with_base(self.config.as_extensions());
        let tls_acceptor_data =
            TlsAcceptorData::try_from(RustlsTlsAcceptorConfig::from_extensions(&merged))
                .context("rustls acceptor: build acceptor data from config")?;

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
        let stream = TlsStream::new(stream);

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

        stream.extensions().insert(negotiated_tls_params);
        stream.extensions().insert(secure_transport);
        stream.extensions().insert(StreamTransformed {
            by: "rama-tls-rustls::TlsAcceptor",
        });

        // NOTE(#1014): graceful TLS `close_notify` on this stream relies on the
        // inner service driving `poll_shutdown` before `stream` is dropped here.
        // The h1 dispatcher now does so on both clean finish and error, but inner
        // HTTP/2 (GOAWAY only), panics, and raw (non-http) tunnels still don't. A
        // bounded shutdown guard wrapping `stream` here (cf. the once-gated,
        // grace-timeout idiom in `rama_net::proxy::forward`; it must spawn via the
        // `Executor` since `Drop` is sync) would cover those paths uniformly.
        self.inner
            .serve(stream)
            .await
            .context("rustls acceptor: service error")
    }
}
