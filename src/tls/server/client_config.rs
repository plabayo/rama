use crate::tls::dep::rustls::{server::ClientHello, CipherSuite, ServerConfig, SignatureScheme};
use std::{future::Future, sync::Arc};

/// A struct containing the information of the accepted client hello.
#[derive(Debug, Clone)]
pub struct IncomingClientHello {
    /// The server name indicator.
    ///
    /// `None` if the client did not supply a SNI.
    pub server_name: Option<String>,

    /// The compatible signature schemes.
    ///
    /// Standard-specified default if the client omitted this extension.
    pub signature_schemes: Vec<SignatureScheme>,

    /// The ALPN protocol identifiers submitted by the client.
    ///
    /// `None` if the client did not include an ALPN extension.
    ///
    /// Application Layer Protocol Negotiation (ALPN) is a TLS extension that lets a client
    /// submit a set of identifiers that each a represent an application-layer protocol.
    /// The server will then pick its preferred protocol from the set submitted by the client.
    /// Each identifier is represented as a byte array, although common values are often ASCII-encoded.
    /// See the official RFC-7301 specifications at <https://datatracker.ietf.org/doc/html/rfc7301>
    /// for more information on ALPN.
    ///
    /// For example, a HTTP client might specify "http/1.1" and/or "h2". Other well-known values
    /// are listed in the at IANA registry at
    /// <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
    ///
    /// The server can specify supported ALPN protocols by setting [`rustls::ServerConfig::alpn_protocols`].
    /// During the handshake, the server will select the first protocol configured that the client supports.
    pub alpn: Option<Vec<Vec<u8>>>,

    /// The cipher suites.
    pub cipher_suites: Vec<CipherSuite>,
}

impl From<ClientHello<'_>> for IncomingClientHello {
    fn from(client_hello: ClientHello<'_>) -> Self {
        Self {
            server_name: client_hello.server_name().map(|name| name.to_owned()),
            signature_schemes: client_hello.signature_schemes().to_vec(),
            alpn: client_hello
                .alpn()
                .map(|alpn| alpn.map(|alpn| alpn.to_owned()).collect()),
            cipher_suites: client_hello.cipher_suites().to_vec(),
        }
    }
}

/// A handler that allows you to define what to do with the client config,
/// upon receiving it during the Tls handshake.
#[derive(Debug, Clone)]
pub struct TlsClientConfigHandler<F> {
    /// Whether to store the client config in the [`Context`]'s [`Extension`].
    pub(crate) store_client_hello: bool,
    /// A function that returns a [`Future`] which resolves to a [`ServerConfig`],
    /// or an error.
    pub(crate) server_config_provider: F,
}

impl Default for TlsClientConfigHandler<()> {
    fn default() -> Self {
        Self::new()
    }
}

/// A trait for providing a [`ServerConfig`] based on a [`IncomingClientHello`].
pub trait ServerConfigProvider: Send + Sync + 'static {
    /// Returns a [`Future`] which resolves to a [`ServerConfig`],
    /// no [`ServerConfig`] to use the default one set for this service,
    /// or an error.
    ///
    /// Note that ideally we would be able to give a reference here (e.g. `ClientHello`),
    /// instead of owned data, but due to it being async this makes it a bit tricky...
    /// Impossible in the current design, but perhaps there is a solution possible.
    /// For now we just turn it in cloned data ¯\_(ツ)_/¯
    fn get_server_config(
        &self,
        client_hello: IncomingClientHello,
    ) -> impl Future<Output = Result<Option<Arc<ServerConfig>>, std::io::Error>> + Send + '_;
}

impl<F, Fut> ServerConfigProvider for F
where
    F: Fn(IncomingClientHello) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<Arc<ServerConfig>>, std::io::Error>> + Send + 'static,
{
    fn get_server_config(
        &self,
        client_hello: IncomingClientHello,
    ) -> impl Future<Output = Result<Option<Arc<ServerConfig>>, std::io::Error>> + Send + '_ {
        (self)(client_hello)
    }
}

impl TlsClientConfigHandler<()> {
    /// Creates a new [`TlsClientConfigHandler`] with the default configuration.
    pub fn new() -> Self {
        Self {
            store_client_hello: false,
            server_config_provider: (),
        }
    }
}

impl<F> TlsClientConfigHandler<F> {
    /// Consumes the handler and returns a new [`TlsClientConfigHandler`] which stores
    /// the client (TLS) config in the [`Context`]'s [`Extensions`].
    ///
    /// [`Context`]: crate::service::Context
    /// [`Extensions`]: crate::service::context::Extensions
    pub fn store_client_hello(self) -> Self {
        Self {
            store_client_hello: true,
            ..self
        }
    }

    /// Consumes the handler and returns a new [`TlsClientConfigHandler`] which uses
    /// the given function to provide a [`ServerConfig`].
    pub fn server_config_provider<G: ServerConfigProvider>(
        self,
        f: G,
    ) -> TlsClientConfigHandler<G> {
        TlsClientConfigHandler {
            store_client_hello: self.store_client_hello,
            server_config_provider: f,
        }
    }
}
