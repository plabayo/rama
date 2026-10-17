//! Established transports accepted by the common HTTP handshake.

use rama_core::{
    extensions::{Extensions, ExtensionsRef},
    io::Io,
};
use rama_http_types::Version;

#[cfg(feature = "http3")]
use {
    super::conn::resolve_input_target_http_version,
    rama_core::{Service, ServiceInput},
    rama_http_core::h3::connection::Config,
    rama_net::{
        HttpVersionInputExt, TargetHttpVersionInputExt,
        client::{ConnectionError, ConnectorService, EstablishedClientConnection},
    },
};

/// An established QUIC transport and the HTTP/3 settings to apply during handshake.
///
/// Custom connectors supply authenticated-origin and established-proxy metadata
/// when required by the service selector. ALPN alone does not establish these facts.
#[cfg(feature = "http3")]
#[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
#[derive(Debug)]
pub struct Http3Transport {
    pub connection: rama_quic::Connection,
    pub config: Config,
}

#[cfg(feature = "http3")]
impl ExtensionsRef for Http3Transport {
    fn extensions(&self) -> &Extensions {
        self.connection.extensions()
    }
}

/// The transport on which the common HTTP connector performs its handshake.
///
/// The `Quic` variant is only available with the `http3` feature.
#[cfg_attr(
    feature = "http3",
    expect(
        clippy::large_enum_variant,
        reason = "Consumed once at handshake; inline settings avoid another connection allocation"
    )
)]
#[derive(Debug)]
pub enum HttpTransport<IO> {
    Stream(IO),
    #[cfg(feature = "http3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
    Quic(Http3Transport),
}

impl<IO: ExtensionsRef> ExtensionsRef for HttpTransport<IO> {
    fn extensions(&self) -> &Extensions {
        match self {
            Self::Stream(io) => io.extensions(),
            #[cfg(feature = "http3")]
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
    /// The HTTP connector checks this before dialing. Explicitly accept only
    /// understood versions; route-specific support remains the connector's
    /// responsibility. The HTTP handshake still validates the actual transport.
    fn supports_http_version(version: Version) -> bool;

    fn into_http_transport(self) -> HttpTransport<Self::Stream>;
}

impl<IO: Io + Unpin + ExtensionsRef> IntoHttpTransport for IO {
    type Stream = IO;

    fn supports_http_version(version: Version) -> bool {
        matches!(
            version,
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2
        )
    }

    fn into_http_transport(self) -> HttpTransport<Self::Stream> {
        HttpTransport::Stream(self)
    }
}

impl<IO: Io + Unpin + ExtensionsRef> IntoHttpTransport for HttpTransport<IO> {
    type Stream = IO;

    fn supports_http_version(version: Version) -> bool {
        matches!(
            version,
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2
        ) || (cfg!(feature = "http3") && version == Version::HTTP_3)
    }

    fn into_http_transport(self) -> Self {
        self
    }
}

#[cfg(feature = "http3")]
impl IntoHttpTransport for Http3Transport {
    // This stream variant is never constructed for a QUIC-only connector.
    type Stream = ServiceInput<Box<dyn Io + Unpin>>;

    fn supports_http_version(version: Version) -> bool {
        matches!(version, Version::HTTP_3)
    }

    fn into_http_transport(self) -> HttpTransport<Self::Stream> {
        HttpTransport::Quic(self)
    }
}

/// Select a stream or QUIC transport before the common HTTP handshake.
/// Each connector owns its transport capabilities, including proxy support.
#[cfg(feature = "http3")]
#[cfg_attr(docsrs, doc(cfg(feature = "http3")))]
#[derive(Clone, Debug)]
pub struct HttpTransportConnector<S, Q> {
    stream: S,
    quic: Q,
}

#[cfg(feature = "http3")]
impl<S, Q> HttpTransportConnector<S, Q> {
    pub const fn new(stream: S, quic: Q) -> Self {
        Self { stream, quic }
    }
}

#[cfg(feature = "http3")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::ServiceInput;

    #[test]
    fn transport_support_matches_understood_http_versions() {
        type Stream = ServiceInput<tokio::io::DuplexStream>;

        for (version, stream, quic) in [
            (Version::HTTP_09, true, false),
            (Version::HTTP_10, true, false),
            (Version::HTTP_11, true, false),
            (Version::HTTP_2, true, false),
            (Version::HTTP_3, false, true),
        ] {
            assert_eq!(
                Stream::supports_http_version(version),
                stream,
                "{version:?}"
            );
            #[cfg(feature = "http3")]
            assert_eq!(
                Http3Transport::supports_http_version(version),
                quic,
                "{version:?}"
            );
            assert_eq!(
                HttpTransport::<Stream>::supports_http_version(version),
                !quic || cfg!(feature = "http3"),
                "{version:?}"
            );
        }
    }
}
