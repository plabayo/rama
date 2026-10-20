//! Prepare a native TLS client session before opening its transport.
//!
//! Preparing checks the complete native configuration, including peer identity,
//! certificate pins and ClientHello shaping. The same session starts the eventual
//! handshake, so preflight does not build and discard a second native context.

use std::fmt;

use rama_boring::ssl::Ssl;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    io::Io,
};
use rama_net::address::Host;
use rama_tls::client::ClientHandshake;

use super::{TlsConnectError, TlsConnectorData};
use crate::TlsStream;

/// One configured client session, ready to consume a transport.
///
/// Construction does not require a stream or perform network I/O. The resolved
/// connector data must include a server identity when verification is enabled.
/// Consuming this value starts exactly one handshake with that configuration.
pub struct PreparedClient {
    ssl: Ssl,
    server_name: Option<Host>,
}

impl fmt::Debug for PreparedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedClient")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl TryFrom<TlsConnectorData> for PreparedClient {
    type Error = BoxError;

    fn try_from(data: TlsConnectorData) -> Result<Self, Self::Error> {
        if data.client_handshake == ClientHandshake::Resumed {
            return Err(BoxError::from_static_str(
                "required session offers are not supported by the TCP TLS backend",
            ));
        }
        let server_name = data.server_name.clone();
        let mut ssl = data.into_ssl()?;
        // Clients do not renegotiate; release handshake configuration afterwards.
        ssl.set_shed_handshake_config(true);
        Ok(Self { ssl, server_name })
    }
}

impl PreparedClient {
    /// Establish TLS over `stream` using the already validated native session.
    pub async fn connect<T>(self, stream: T) -> Result<TlsStream<T>, TlsConnectError<T>>
    where
        T: Io + Unpin + ExtensionsRef,
    {
        let Self { ssl, server_name } = self;
        let stream = rama_boring_tokio::SslStreamBuilder::new(ssl, stream)
            .connect()
            .await
            .map_err(|error| TlsConnectError::Handshake { error, server_name })?;
        Ok(TlsStream::new(stream))
    }
}

#[cfg(test)]
mod tests;
