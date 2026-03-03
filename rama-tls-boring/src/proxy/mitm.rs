use rama_core::{error::BoxError, extensions, stream::Stream};
use rama_net::proxy::StreamBridge;

use crate::{client, server};

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay (and MITM a TLS connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct TlsMitmRelay {}

impl TlsMitmRelay {
    #[inline(always)]
    /// Create a new [`TlsMitmRelay`].
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for TlsMitmRelay {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl TlsMitmRelay {
    /// Establish and MITM an handshake between the client and server.
    pub async fn handshake<Left, Right>(
        &self,
        StreamBridge { left: _, right: _ }: StreamBridge<Left, Right>,
    ) -> Result<StreamBridge<server::TlsStream<Left>, client::TlsStream<Right>>, BoxError>
    where
        Left: Stream + Unpin + extensions::ExtensionsMut,
        Right: Stream + Unpin + extensions::ExtensionsMut,
    {
        Err(BoxError::from("TODO"))
    }
}
