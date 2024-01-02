//! Contains [`Either`] and related types and functions.
//!
//! See [`Either`] documentation for more details.

use pin_project_lite::pin_project;
use std::future::Future;

use crate::service::{Context, Layer, Service};

/// Combine two different service types into a single type.
///
/// Both services must be of the same request, response, and error types.
/// [`Either`] is useful for handling conditional branching in service middleware
/// to different inner service types.
#[derive(Copy, Debug)]
pub enum Either<A, B> {
    #[allow(missing_docs)]
    Left(A),
    #[allow(missing_docs)]
    Right(B),
}

impl<A, B> Clone for Either<A, B>
where
    A: Clone,
    B: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Either::Left(a) => Either::Left(a.clone()),
            Either::Right(b) => Either::Right(b.clone()),
        }
    }
}

impl<A, B, S, Request> Service<S, Request> for Either<A, B>
where
    A: Service<S, Request>,
    B: Service<S, Request, Response = A::Response, Error = A::Error>,
{
    type Response = A::Response;
    type Error = A::Error;

    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + '_ {
        match self {
            Either::Left(service) => EitherResponseFuture {
                kind: Kind::Left {
                    inner: service.serve(ctx, req),
                },
            },
            Either::Right(service) => EitherResponseFuture {
                kind: Kind::Right {
                    inner: service.serve(ctx, req),
                },
            },
        }
    }
}

impl<S, A, B> Layer<S> for Either<A, B>
where
    A: Layer<S>,
    B: Layer<S>,
{
    type Service = Either<A::Service, B::Service>;

    fn layer(&self, inner: S) -> Self::Service {
        match self {
            Either::Left(layer) => Either::Left(layer.layer(inner)),
            Either::Right(layer) => Either::Right(layer.layer(inner)),
        }
    }
}

pin_project! {
    /// Response future for [`Either`].
    pub struct EitherResponseFuture<A, B> {
        #[pin]
        kind: Kind<A, B>
    }
}

pin_project! {
    #[project = KindProj]
    enum Kind<A, B> {
        Left { #[pin] inner: A },
        Right { #[pin] inner: B },
    }
}

impl<A, B> Future for EitherResponseFuture<A, B>
where
    A: Future,
    B: Future<Output = A::Output>,
{
    type Output = A::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.project().kind.project() {
            KindProj::Left { inner } => inner.poll(cx),
            KindProj::Right { inner } => inner.poll(cx),
        }
    }
}
