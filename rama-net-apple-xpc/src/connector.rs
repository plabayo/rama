use rama_core::Service;
use rama_net::client::EstablishedClientConnection;

use crate::{client::XpcClientConfig, connection::XpcConnection, error::XpcError};

#[derive(Debug, Clone, Copy, Default)]
pub struct XpcConnector;

impl Service<XpcClientConfig> for XpcConnector {
    type Output = EstablishedClientConnection<XpcConnection, XpcClientConfig>;
    type Error = XpcError;

    async fn serve(&self, input: XpcClientConfig) -> Result<Self::Output, Self::Error> {
        let conn = XpcConnection::connect(input.clone())?;
        Ok(EstablishedClientConnection { input, conn })
    }
}
