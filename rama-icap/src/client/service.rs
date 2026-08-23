use rama_core::{Service, extensions::ExtensionsRef, io::Io};
use rama_net::client::{ConnectionError, ConnectorService, EstablishedClientConnection};

use crate::{client::ClientConnection, io::ConnectionOptions};

/// ICAP connector over an inner Rama connector stack.
///
/// The inner connector establishes the transport, including optional proxy,
/// TLS, or mTLS layers. This service preserves its input and connection
/// extensions while wrapping the resulting stream as a
/// [`ClientConnection`].
///
/// `Client` implements [`Service`] and therefore also Rama's blanket
/// [`ConnectorService`] implementation. It is the terminal adapter over a
/// transport, proxy, and TLS connector stack. Place an exclusive transport
/// pool inside this adapter; the HTTP adaptation layer holds each resulting
/// lease until its ICAP response body completes. A pool of raw transports must
/// disable `drop_connection_if_no_response`. Reusable completion only disarms
/// ICAP's local poison state. Non-reusable framing marks Rama's shared health
/// watcher broken before releasing the lease, and never resets another
/// component's broken verdict.
#[derive(Clone, Debug)]
pub struct Client<S> {
    inner: S,
    options: ConnectionOptions,
}

impl<S> Client<S> {
    /// Create an ICAP connector over `inner`.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            options: ConnectionOptions::new(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the options used by each established ICAP connection.
        pub const fn options(
            mut self,
            options: ConnectionOptions,
        ) -> Self {
            self.options = options;
            self
        }
    }

    /// Return the options used by new ICAP connections.
    #[must_use]
    pub const fn options(&self) -> &ConnectionOptions {
        &self.options
    }

    rama_utils::macros::define_inner_service_accessors!();

    /// Establish an ICAP connection with the inner connector stack.
    pub async fn connect<Input>(
        &self,
        input: Input,
    ) -> Result<EstablishedClientConnection<ClientConnection<S::Connection>, Input>, ConnectionError>
    where
        S: ConnectorService<Input>,
        S::Connection: Io + Unpin + ExtensionsRef,
    {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        Ok(EstablishedClientConnection {
            input,
            conn: ClientConnection::with_options(conn, self.options),
        })
    }
}

impl<S, Input> Service<Input> for Client<S>
where
    S: ConnectorService<Input>,
    S::Connection: Io + Unpin + ExtensionsRef,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<ClientConnection<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.connect(input).await
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rama_core::{
        ServiceInput,
        extensions::{Extension, ExtensionsRef as _},
        service::service_fn,
    };

    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct Marker(u8);

    impl Extension for Marker {}

    #[derive(Debug, Eq, PartialEq)]
    struct WrappedMarker;

    impl Extension for WrappedMarker {}

    #[tokio::test]
    async fn preserves_input_options_and_extensions() {
        let connector = service_fn(async |input: usize| {
            let (io, _peer) = tokio::io::duplex(64);
            let io = ServiceInput::new(io);
            io.extensions().insert(Marker(42));
            Ok::<_, Infallible>(EstablishedClientConnection { input, conn: io })
        });
        let options = ConnectionOptions::new().with_read_buffer_bytes(321);
        let client = Client::new(connector).with_options(options);
        assert_eq!(client.options(), &options);

        let established = ConnectorService::connect(&client, 7).await.unwrap();

        assert_eq!(established.input, 7);
        assert_eq!(established.conn.options(), &options);
        assert_eq!(
            established.conn.extensions().get_ref::<Marker>(),
            Some(&Marker(42)),
        );
        established.conn.extensions().insert(WrappedMarker);
        let io = established.conn.into_inner();
        assert_eq!(
            io.extensions().get_ref::<WrappedMarker>(),
            Some(&WrappedMarker),
        );
    }

    #[test]
    fn exposes_inner_connector() {
        let client = Client::new(42);

        assert_eq!(client.get_ref(), &42);
        assert_eq!(client.into_inner(), 42);
    }
}
