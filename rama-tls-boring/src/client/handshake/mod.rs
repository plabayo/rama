//! Prepare a native TLS client session before opening its transport.
//!
//! Preparing checks the complete native configuration, including peer identity,
//! certificate pins and ClientHello shaping. The same session starts the eventual
//! handshake, so preflight does not build and discard a second native context.

use std::{fmt, sync::Arc};

use rama_boring::ssl::{NameType, Ssl};
use rama_core::{
    conversion::RamaTryFrom as _,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    io::Io,
};
use rama_net::tls::ServerName;
use rama_tls::{ProtocolVersion, client::ClientHandshake};

use super::{TlsConnectError, TlsConnectorData};
use crate::TlsStream;

/// One configured client session, ready to consume a transport.
///
/// Construction does not require a stream or perform network I/O. The resolved
/// connector data must include a server identity when verification is enabled.
/// Consuming this value starts exactly one handshake with that configuration.
pub struct PreparedClient {
    ssl: Ssl,
    server_name: Option<ServerName>,
    ech_required: bool,
    offered_versions: Option<Arc<[u16]>>,
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
        let ech_required = data.ech_required;
        let offered_versions = data.offered_versions.clone();
        let mut ssl = data.into_ssl()?;
        // Clients do not renegotiate; release handshake configuration afterwards.
        ssl.set_shed_handshake_config(true);
        Ok(Self {
            ssl,
            server_name,
            ech_required,
            offered_versions,
        })
    }
}

impl PreparedClient {
    /// Establish TLS over `stream` using the already validated native session.
    pub async fn connect<T>(self, stream: T) -> Result<TlsStream<T>, TlsConnectError<T>>
    where
        T: Io + Unpin + ExtensionsRef,
    {
        let Self {
            ssl,
            server_name,
            ech_required,
            offered_versions,
        } = self;
        let stream = rama_boring_tokio::SslStreamBuilder::new(ssl, stream)
            .connect()
            .await
            .map_err(|error| {
                let outgoing_sni = error
                    .ssl()
                    .and_then(|ssl| ssl.servername(NameType::HOST_NAME))
                    .and_then(ServerName::parse);
                TlsConnectError::Handshake {
                    error,
                    server_name,
                    outgoing_sni,
                }
            })?;
        // The engine negotiates its min..max range; a listed set with gaps is enforced here.
        if let Some(offered) = offered_versions {
            let negotiated = stream
                .ssl()
                .version()
                .and_then(|version| ProtocolVersion::rama_try_from(version).ok())
                .map(u16::from);
            if negotiated.is_none_or(|version| !offered.contains(&version)) {
                return Err(TlsConnectError::Builder(BoxError::from_static_str(
                    "server selected a TLS version the offer did not list",
                )));
            }
        }
        let accepted = stream.ssl().ech_accepted();
        if ech_required && !accepted {
            return Err(TlsConnectError::Builder(BoxError::from_static_str(
                "server did not accept required ECH",
            )));
        }
        stream
            .get_ref()
            .extensions()
            .insert(rama_tls::client::TlsEchAccepted(accepted));
        Ok(TlsStream::new(stream))
    }
}

#[cfg(test)]
mod tests;
