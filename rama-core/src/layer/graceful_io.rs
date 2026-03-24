use rama_utils::macros::define_inner_service_accessors;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::{
    Layer, Service,
    extensions::ExtensionsMut,
    io::{CancelIo, GracefulIo, Io},
};

/// A [`Service`] that wraps I/O input with [`GracefulIo`] and injects a [`CancelIo`] extension.
#[derive(Debug, Clone)]
pub struct GracefulIoService<S> {
    inner: S,
}

impl<S> GracefulIoService<S> {
    /// Create a new [`GracefulIoService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<IO> for GracefulIoService<S>
where
    S: Service<GracefulIo<WaitForCancellationFutureOwned, IO>>,
    IO: Io + ExtensionsMut,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut io: IO) -> Result<Self::Output, Self::Error> {
        let token = CancellationToken::new();
        io.extensions_mut().insert(CancelIo(token.clone()));
        self.inner
            .serve(GracefulIo::new(token.cancelled_owned(), io))
            .await
    }
}

/// A [`Layer`] that turns I/O input into [`GracefulIo`] and injects [`CancelIo`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GracefulIoLayer;

impl GracefulIoLayer {
    /// Create a new [`GracefulIoLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for GracefulIoLayer {
    type Service = GracefulIoService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GracefulIoService { inner }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{Service, ServiceInput, extensions::ExtensionsRef, service::service_fn};

    use super::*;

    #[tokio::test]
    async fn graceful_io_layer_injects_cancel_token() {
        let svc = GracefulIoLayer::new().into_layer(service_fn(
            async |stream: GracefulIo<WaitForCancellationFutureOwned, ServiceInput<_>>| {
                assert!(stream.extensions().get::<CancelIo>().is_some());
                let cancel = stream.extensions().get::<CancelIo>().unwrap().clone();
                cancel.0.cancel();

                let mut stream = std::pin::pin!(stream);
                let err = stream.write_all(b"abc").await.unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

                Ok::<_, Infallible>(())
            },
        ));

        let (stream, _peer) = tokio::io::duplex(64);
        svc.serve(ServiceInput::new(stream)).await.unwrap();
    }

    #[tokio::test]
    async fn graceful_io_layer_reads_eof_after_cancel() {
        let svc = GracefulIoService::new(service_fn(
            async |stream: GracefulIo<WaitForCancellationFutureOwned, ServiceInput<_>>| {
                let cancel = stream.extensions().get::<CancelIo>().unwrap().clone();
                cancel.0.cancel();

                let mut stream = std::pin::pin!(stream);
                let mut buf = [0_u8; 1];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(n, 0);

                Ok::<_, Infallible>(())
            },
        ));

        let (stream, _peer) = tokio::io::duplex(64);
        svc.serve(ServiceInput::new(stream)).await.unwrap();
    }
}
