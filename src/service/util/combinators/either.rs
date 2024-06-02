use crate::error::BoxError;
use crate::http::{self, layer::retry};
use crate::service::{
    context::Extensions, layer::limit, matcher::Matcher, Context, Layer, Service,
};
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, Error as IoError, ReadBuf, Result as IoResult};

macro_rules! create_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        #[derive(Debug)]
        /// A type to allow you to use multiple types as a single type.
        ///
        /// Implements:
        ///
        /// - the [`Service`] trait;
        /// - the [`Layer`] trait;
        /// - the [`Matcher`] trait;
        /// - the [`limit::Policy`] trait;
        /// - the [`retry::Policy`] trait;
        ///
        /// and will delegate the functionality to the type that is wrapped in the `Either` type.
        /// To keep it easy all wrapped types are expected to work with the same inputs and outputs.
        ///
        /// [`limit::Policy`]: crate::service::layer::limit::Policy
        /// [`retry::Policy`]: crate::http::layer::retry::Policy
        /// [`Matcher`]: crate::service::matcher::Matcher
        /// [`Service`]: crate::service::Service
        /// [`Layer`]: crate::service::Layer
        pub enum $id<$($param),+> {
            $(
                /// one of the Either variants
                $param($param),
            )+
        }

        impl<$($param),+> Clone for $id<$($param),+>
        where
            $($param: Clone),+
        {
            fn clone(&self) -> Self {
                match self {
                    $(
                        $id::$param(s) => $id::$param(s.clone()),
                    )+
                }
            }
        }

        impl<$($param),+, State, Request, Response> Service<State, Request> for $id<$($param),+>
        where
            $(
                $param: Service<State, Request, Response = Response>,
                $param::Error: Into<BoxError>,
            )+
            Request: Send + 'static,
            State: Send + Sync + 'static,
            Response: Send + 'static,
        {
            type Response = Response;
            type Error = BoxError;

            async fn serve(&self, ctx: Context<State>, req: Request) -> Result<Self::Response, Self::Error> {
                match self {
                    $(
                        $id::$param(s) => s.serve(ctx, req).await.map_err(Into::into),
                    )+
                }
            }
        }

        impl<$($param),+, S> Layer<S> for $id<$($param),+>
        where
            $($param: Layer<S>),+,
        {
            type Service = $id<$($param::Service),+>;

            fn layer(&self, inner: S) -> Self::Service {
                match self {
                    $(
                        $id::$param(layer) => $id::$param(layer.layer(inner)),
                    )+
                }
            }
        }

        impl<$($param),+, State, Request> Matcher<State, Request> for $id<$($param),+>
        where
            $($param: Matcher<State, Request>),+,
            Request: Send + 'static,
            State: Send + Sync + 'static,
        {
            fn matches(
                &self,
                ext: Option<&mut Extensions>,
                ctx: &Context<State>,
                req: &Request
            ) -> bool{
                match self {
                    $(
                        $id::$param(layer) => layer.matches(ext, ctx, req),
                    )+
                }
            }
        }

        impl<$($param),+, State, Request> limit::Policy<State, Request> for $id<$($param),+>
        where
            $(
                $param: limit::Policy<State, Request>,
                $param::Error: Into<BoxError>,
            )+
            Request: Send + 'static,
            State: Send + Sync + 'static,
        {
            type Guard = $id<$($param::Guard),+>;
            type Error = BoxError;

            async fn check(
                &self,
                ctx: Context<State>,
                req: Request,
            ) -> limit::policy::PolicyResult<State, Request, Self::Guard, Self::Error> {
                match self {
                    $(
                        $id::$param(policy) => {
                            let result = policy.check(ctx, req).await;
                            match result.output {
                                limit::policy::PolicyOutput::Ready(guard) => limit::policy::PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: limit::policy::PolicyOutput::Ready($id::$param(guard)),
                                },
                                limit::policy::PolicyOutput::Abort(err) => limit::policy::PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: limit::policy::PolicyOutput::Abort(err.into()),
                                },
                                limit::policy::PolicyOutput::Retry => limit::policy::PolicyResult {
                                    ctx: result.ctx,
                                    request: result.request,
                                    output: limit::policy::PolicyOutput::Retry,
                                },
                            }
                        }
                    )+
                }
            }
        }

        impl<$($param),+, State, Response, Error> retry::Policy<State, Response, Error> for $id<$($param),+>
        where
            $($param: retry::Policy<State, Response, Error>),+,
            State: Send + Sync + 'static,
            Response: Send + 'static,
            Error: Send + Sync + 'static,
        {
            async fn retry(
                &self,
                ctx: Context<State>,
                req: http::Request<retry::RetryBody>,
                result: Result<Response, Error>,
            ) -> retry::PolicyResult<State, Response, Error> {
                match self {
                    $(
                        $id::$param(policy) => policy.retry(ctx, req, result).await,
                    )+
                }
            }

            fn clone_input(
                &self,
                ctx: &Context<State>,
                req: &http::Request<retry::RetryBody>,
            ) -> Option<(Context<State>, http::Request<retry::RetryBody>)> {
                match self {
                    $(
                        $id::$param(policy) => policy.clone_input(ctx, req),
                    )+
                }
            }
        }

        impl<$($param),+> AsyncRead for $id<$($param),+>
        where
            $($param: AsyncRead + Unpin),+,
        {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<IoResult<()>> {
                match &mut *self {
                    $(
                        $id::$param(reader) => Pin::new(reader).poll_read(cx, buf),
                    )+
                }
            }
        }

        impl<$($param),+> AsyncWrite for $id<$($param),+>
        where
            $($param: AsyncWrite + Unpin),+,
        {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_write(cx, buf),
                    )+
                }
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_flush(cx),
                    )+
                }
            }

            fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_shutdown(cx),
                    )+
                }
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                bufs: &[IoSlice<'_>],
            ) -> Poll<Result<usize, IoError>> {
                match &mut *self {
                    $(
                        $id::$param(writer) => Pin::new(writer).poll_write_vectored(cx, bufs),
                    )+
                }
            }

            fn is_write_vectored(&self) -> bool {
                match self {
                    $(
                        $id::$param(reader) => reader.is_write_vectored(),
                    )+
                }
            }
        }
    };
}

create_either!(Either, A, B,);
create_either!(Either3, A, B, C,);
create_either!(Either4, A, B, C, D,);
create_either!(Either5, A, B, C, D, E,);
create_either!(Either6, A, B, C, D, E, F,);
create_either!(Either7, A, B, C, D, E, F, G,);
create_either!(Either8, A, B, C, D, E, F, G, H,);
create_either!(Either9, A, B, C, D, E, F, G, H, I,);
