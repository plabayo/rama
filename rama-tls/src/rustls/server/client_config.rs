use super::TlsAcceptorData;
use crate::types::client::ClientHello;
use std::{fmt, future::Future};

/// A handler that allows you to define what to do with the client config,
/// upon receiving it during the Tls handshake.
pub struct TlsClientConfigHandler<F> {
    /// Whether to store the client config in the [`Context`]'s [`Extension`].
    pub(crate) store_client_hello: bool,
    /// A function that returns a [`Future`] which resolves to a [`ServiceData`],
    /// or an error.
    pub(crate) service_data_provider: F,
}

impl<F> fmt::Debug for TlsClientConfigHandler<F>
where
    F: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsClientConfigHandler")
            .field("store_client_hello", &self.store_client_hello)
            .field("service_data_provider", &self.service_data_provider)
            .finish()
    }
}

impl<F> Clone for TlsClientConfigHandler<F>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            store_client_hello: self.store_client_hello,
            service_data_provider: self.service_data_provider.clone(),
        }
    }
}

impl Default for TlsClientConfigHandler<()> {
    fn default() -> Self {
        Self::new()
    }
}

/// A trait for providing a [`ServiceData`] based on a [`ClientHello`].
pub trait ServiceDataProvider: Send + Sync + 'static {
    /// Error returned by the provider in case something went wrong
    /// during the [`ServiceDataProvider::get_service_data`] call.
    type Error;

    /// Returns a [`Future`] which resolves to a [`ServiceData`],
    /// no [`ServiceData`] to use the default one set for this service,
    /// or an error.
    ///
    /// Note that ideally we would be able to give a reference here (e.g. `ClientHello`),
    /// instead of owned data, but due to it being async this makes it a bit tricky...
    /// Impossible in the current design, but perhaps there is a solution possible.
    /// For now we just turn it in cloned data ¯\_(ツ)_/¯
    fn get_service_data(
        &self,
        client_hello: ClientHello,
    ) -> impl Future<Output = Result<Option<TlsAcceptorData>, Self::Error>> + Send + '_;
}

impl<F, Fut, Error> ServiceDataProvider for F
where
    F: Fn(ClientHello) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<TlsAcceptorData>, Error>> + Send + 'static,
{
    type Error = Error;
    fn get_service_data(
        &self,
        client_hello: ClientHello,
    ) -> impl Future<Output = Result<Option<TlsAcceptorData>, Self::Error>> + Send + '_ {
        (self)(client_hello)
    }
}

impl TlsClientConfigHandler<()> {
    /// Creates a new [`TlsClientConfigHandler`] with the default configuration.
    pub const fn new() -> Self {
        Self {
            store_client_hello: false,
            service_data_provider: (),
        }
    }
}

impl<F> TlsClientConfigHandler<F> {
    /// Consumes the handler and returns a new [`TlsClientConfigHandler`] which stores
    /// the client (TLS) config in the [`Context`]'s [`Extensions`].
    ///
    /// [`Context`]: rama_core::Context
    /// [`Extensions`]: rama_core::context::Extensions
    pub fn store_client_hello(self) -> Self {
        Self {
            store_client_hello: true,
            ..self
        }
    }

    /// Consumes the handler and returns a new [`TlsClientConfigHandler`] which uses
    /// the given function to provide a [`ServiceData`].
    pub fn server_config_provider<G: ServiceDataProvider>(self, f: G) -> TlsClientConfigHandler<G> {
        TlsClientConfigHandler {
            store_client_hello: self.store_client_hello,
            service_data_provider: f,
        }
    }
}
