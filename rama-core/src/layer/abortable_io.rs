use rama_utils::macros::define_inner_service_accessors;

use crate::{
    Layer, Service,
    extensions::ExtensionsRef,
    graceful::{Cause, Scope, enter_scope},
    io::{AbortableIo, Io},
};

/// A [`Service`] that runs I/O input in its own child [`Scope`] and cuts the I/O once that
/// scope is aborted, see [`AbortableIo`].
///
/// The child is made in the scope the input runs in (a new root without one, see
/// [`enter_scope`]): aborting it is how the I/O is cut on purpose. An input whose scope is
/// closing gets an aborted one.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct AbortableIoService<S> {
    inner: S,
}

impl<S> AbortableIoService<S> {
    /// Create a new [`AbortableIoService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<IO> for AbortableIoService<S>
where
    S: Service<AbortableIo<IO>>,
    IO: Io + ExtensionsRef,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, io: IO) -> Result<Self::Output, Self::Error> {
        let scope = enter_scope(io.extensions()).unwrap_or_else(|_closed| closed());
        self.inner.serve(AbortableIo::new(&scope, io)).await
    }
}

/// The scope of an input that arrived in a closing scope: aborted from the start.
pub(crate) fn closed() -> Scope {
    let scope = Scope::new();
    scope.abort(Cause::Reason("the input's scope is closed"));
    scope
}

/// A [`Layer`] that runs I/O input in its own child [`Scope`], see [`AbortableIoService`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AbortableIoLayer;

impl AbortableIoLayer {
    /// Create a new [`AbortableIoLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for AbortableIoLayer {
    type Service = AbortableIoService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AbortableIoService { inner }
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        ServiceInput,
        graceful::{Cause, WeakScope, attach_scope, scope_context},
        service::service_fn,
    };

    use super::*;

    #[tokio::test]
    async fn aborting_the_inserted_scope_fails_writes() {
        let svc = AbortableIoLayer::new().into_layer(service_fn(
            async |stream: AbortableIo<ServiceInput<_>>| {
                let scope = scope_context(stream.extensions())
                    .and_then(WeakScope::into_scope)
                    .unwrap();
                scope.abort(Cause::Owner);

                let mut stream = core::pin::pin!(stream);
                let err = stream.write_all(b"abc").await.unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

                Ok::<_, Infallible>(())
            },
        ));

        let (stream, _peer) = tokio::io::duplex(64);
        svc.serve(ServiceInput::new(stream)).await.unwrap();
    }

    #[tokio::test]
    async fn a_parent_abort_reads_eof() {
        let parent = Scope::new();
        let weak = parent.clone_weak();
        let svc =
            AbortableIoService::new(service_fn(move |stream: AbortableIo<ServiceInput<_>>| {
                let parent = weak.clone();
                async move {
                    parent.abort(Cause::Owner);

                    let mut stream = core::pin::pin!(stream);
                    let mut buf = [0_u8; 1];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert_eq!(n, 0);

                    Ok::<_, Infallible>(())
                }
            }));

        let (stream, _peer) = tokio::io::duplex(64);
        let input = ServiceInput::new(stream);
        attach_scope(input.extensions(), &parent);
        svc.serve(input).await.unwrap();
    }

    #[tokio::test]
    async fn a_child_abort_leaves_the_parent_alone() {
        let parent = Scope::new();
        let svc =
            AbortableIoService::new(service_fn(async |stream: AbortableIo<ServiceInput<_>>| {
                scope_context(stream.extensions())
                    .unwrap()
                    .abort(Cause::Owner);
                Ok::<_, Infallible>(())
            }));

        let (stream, _peer) = tokio::io::duplex(64);
        let input = ServiceInput::new(stream);
        attach_scope(input.extensions(), &parent);
        svc.serve(input).await.unwrap();
        assert!(!parent.is_cancelled());
    }
}
