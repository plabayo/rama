use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::ExtensionsRef;
use rama_core::{Service, io::Io};
use rama_net::client::{ConnectorService, EstablishedClientConnection};

use crate::Client;

/// A rama connector that establishes a transport connection through an inner connector and
/// wraps it in a ttRPC [`Client`], so a client stack yields a ready to use `Client` instead
/// of a raw stream.
#[derive(Debug, Clone, Default)]
pub struct TtrpcConnector<C> {
    inner: C,
}

impl<C> TtrpcConnector<C> {
    /// Wrap an inner (transport) connector so it yields a ttRPC [`Client`].
    pub const fn new(inner: C) -> Self {
        Self { inner }
    }
}

impl<C, Input> Service<Input> for TtrpcConnector<C>
where
    C: ConnectorService<Input, Connection: Io>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<Client, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } =
            self.inner.connect(input).await.into_box_error()?;

        let extensions = conn.extensions().clone();
        let client = Client::new_with_extensions(conn, extensions);
        Ok(EstablishedClientConnection {
            input,
            conn: client,
        })
    }
}
