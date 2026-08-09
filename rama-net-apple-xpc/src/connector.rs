use rama_core::Service;
use rama_net::client::{ConnectionError, ConnectionErrorKind, EstablishedClientConnection};

use crate::{client::XpcClientConfig, connection::XpcConnection, error::XpcError};

/// A [`rama_core::Service`] that establishes XPC client connections.
///
/// Accepts an [`XpcClientConfig`] and returns an
/// [`EstablishedClientConnection<XpcConnection, XpcClientConfig>`].
/// Designed for use inside Rama client service stacks.
#[derive(Debug, Clone, Copy, Default)]
pub struct XpcConnector;

impl Service<XpcClientConfig> for XpcConnector {
    type Output = EstablishedClientConnection<XpcConnection, XpcClientConfig>;
    type Error = ConnectionError;

    async fn serve(&self, input: XpcClientConfig) -> Result<Self::Output, Self::Error> {
        let conn = XpcConnection::connect(input.clone()).map_err(|error| {
            let kind = match &error {
                XpcError::InvalidCString(_)
                | XpcError::PeerRequirementFailed { .. }
                | XpcError::UnsupportedObjectType(_)
                | XpcError::InvalidMessage(_)
                | XpcError::SerializationFailed(_)
                | XpcError::DeserializationFailed(_) => ConnectionErrorKind::InvalidInput,
                XpcError::NullConnection(_)
                | XpcError::NullObject(_)
                | XpcError::QueueCreationFailed
                | XpcError::ReplyNotExpected
                | XpcError::ReplyCanceled
                | XpcError::CallTimedOut(_)
                | XpcError::Remote { .. }
                | XpcError::Connection(_) => ConnectionErrorKind::Internal,
            };
            ConnectionError::local(error, kind).context("create XPC client connection")
        })?;
        Ok(EstablishedClientConnection { input, conn })
    }
}
