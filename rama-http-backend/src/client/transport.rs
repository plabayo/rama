//! Established transports accepted by the common HTTP handshake.

use super::conn::resolve_input_target_http_version;
use rama_core::{
    Service, ServiceInput,
    extensions::{Extensions, ExtensionsRef},
    io::Io,
};
use rama_http_core::h3::connection::Config;
use rama_http_types::Version;
use rama_net::{
    HttpVersionInputExt, TargetHttpVersionInputExt,
    client::{ConnectionError, ConnectorService, EstablishedClientConnection},
};

/// An established QUIC transport and the HTTP/3 settings to apply during handshake.
///
/// Custom connectors supply authenticated-origin and established-proxy metadata
/// when required by the service selector. ALPN alone does not establish these facts.
#[derive(Debug)]
pub struct Http3Transport {
    pub connection: rama_quic::Connection,
    pub config: Config,
}

impl ExtensionsRef for Http3Transport {
    fn extensions(&self) -> &Extensions {
        self.connection.extensions()
    }
}

/// The transport on which the common HTTP connector performs its handshake.
#[derive(Debug)]
pub enum HttpTransport<IO> {
    Stream(IO),
    Quic(Http3Transport),
}

impl<IO: ExtensionsRef> ExtensionsRef for HttpTransport<IO> {
    fn extensions(&self) -> &Extensions {
        match self {
            Self::Stream(io) => io.extensions(),
            Self::Quic(quic) => quic.extensions(),
        }
    }
}

/// Convert an established transport into the HTTP handshake's transport types.
/// Ordinary byte-stream connectors are supported without an adapter.
pub trait IntoHttpTransport: ExtensionsRef + Send + 'static {
    type Stream: Io + Unpin + ExtensionsRef;

    /// Whether this transport type can carry the requested HTTP version.
    ///
    /// The HTTP connector checks this before dialing. Return `false` only for
    /// impossible combinations; route-specific support remains the connector's
    /// responsibility. Custom transport types default to deferring that decision.
    fn supports_http_version(_version: Version) -> bool {
        true
    }

    fn into_http_transport(self) -> HttpTransport<Self::Stream>;
}

impl<IO: Io + Unpin + ExtensionsRef> IntoHttpTransport for IO {
    type Stream = IO;

    fn supports_http_version(version: Version) -> bool {
        version != Version::HTTP_3
    }

    fn into_http_transport(self) -> HttpTransport<Self::Stream> {
        HttpTransport::Stream(self)
    }
}

impl<IO: Io + Unpin + ExtensionsRef> IntoHttpTransport for HttpTransport<IO> {
    type Stream = IO;

    fn into_http_transport(self) -> Self {
        self
    }
}

impl IntoHttpTransport for Http3Transport {
    // This stream variant is never constructed for a QUIC-only connector.
    type Stream = ServiceInput<Box<dyn Io + Unpin>>;

    fn supports_http_version(version: Version) -> bool {
        version == Version::HTTP_3
    }

    fn into_http_transport(self) -> HttpTransport<Self::Stream> {
        HttpTransport::Quic(self)
    }
}

/// Select a stream or QUIC transport before the common HTTP handshake.
/// Each connector owns its transport capabilities, including proxy support.
#[derive(Clone, Debug)]
pub struct HttpTransportConnector<S, Q> {
    stream: S,
    quic: Q,
}

impl<S, Q> HttpTransportConnector<S, Q> {
    pub const fn new(stream: S, quic: Q) -> Self {
        Self { stream, quic }
    }
}

impl<S, Q, Input> Service<Input> for HttpTransportConnector<S, Q>
where
    S: ConnectorService<Input, Connection: IntoHttpTransport>,
    Q: ConnectorService<Input, Connection = Http3Transport>,
    Input: ExtensionsRef + HttpVersionInputExt + TargetHttpVersionInputExt + Send + 'static,
{
    type Output = EstablishedClientConnection<
        HttpTransport<<S::Connection as IntoHttpTransport>::Stream>,
        Input,
    >;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if resolve_input_target_http_version(&input) == Some(Version::HTTP_3) {
            let EstablishedClientConnection { input, conn } = self.quic.connect(input).await?;
            Ok(EstablishedClientConnection {
                input,
                conn: HttpTransport::Quic(conn),
            })
        } else {
            let EstablishedClientConnection { input, conn } = self.stream.connect(input).await?;
            Ok(EstablishedClientConnection {
                input,
                conn: conn.into_http_transport(),
            })
        }
    }
}
