use rama_core::{Layer, Service, extensions::ExtensionsRef};
use rama_net::client::{
    ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection,
};
use rama_utils::macros::define_inner_service_accessors;

use super::{PostedRecv, PostedRecvConfig, RawTcpStream};

/// A [`Layer`] that wraps every connection a TCP connector establishes in a
/// [`PostedRecv`].
///
/// Place it right around the TCP connector (for instance
/// [`TcpConnector`](crate::client::service::TcpConnector)), below any TLS or
/// other layer that transforms the stream.
#[derive(Debug, Clone, Default)]
pub struct PostedRecvLayer {
    config: PostedRecvConfig,
}

impl PostedRecvLayer {
    /// Create a [`PostedRecvLayer`] with the default [`PostedRecvConfig`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: PostedRecvConfig::new(),
        }
    }

    /// Create a [`PostedRecvLayer`] with the given configuration.
    #[must_use]
    pub const fn with_config(config: PostedRecvConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for PostedRecvLayer {
    type Service = PostedRecvConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PostedRecvConnector {
            inner,
            config: self.config.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        PostedRecvConnector {
            inner,
            config: self.config,
        }
    }
}

/// A connector that wraps every connection its inner TCP connector
/// establishes in a [`PostedRecv`].
///
/// Created by [`PostedRecvLayer`].
#[derive(Debug, Clone)]
pub struct PostedRecvConnector<S> {
    inner: S,
    config: PostedRecvConfig,
}

impl<S> PostedRecvConnector<S> {
    /// Wrap the connections of `inner` with the given configuration.
    pub const fn new(inner: S, config: PostedRecvConfig) -> Self {
        Self { inner, config }
    }

    define_inner_service_accessors!();
}

impl<S, Input, Stream> Service<Input> for PostedRecvConnector<S>
where
    S: ConnectorService<Input, Connection = Stream>,
    Stream: RawTcpStream + ExtensionsRef,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<PostedRecv<Stream>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        let conn = PostedRecv::with_config(conn, &self.config).map_err(|err| {
            ConnectionError::local(err, ConnectionErrorKind::Internal)
                .context("posted recv: wrap established tcp connection")
        })?;
        Ok(EstablishedClientConnection { input, conn })
    }
}
