use super::HttpServeResult;
use crate::http::{Request, Response};
use crate::rt::Executor;
use crate::service::Service;
use crate::service::{Context, HyperService};
use crate::stream::Stream;
use futures::FutureExt;
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper_util::{rt::TokioIo, server::conn::auto::Builder as AutoBuilder};
use std::convert::Infallible;
use std::pin::pin;
use tokio::select;

/// A utility trait to allow any of the hyper server builders to be used
/// in the same way to (http) serve a connection.
pub trait HyperConnServer: Send + Sync + private::Sealed + 'static {
    fn hyper_serve_connection<IO, State, S>(
        &self,
        ctx: Context<State>,
        io: IO,
        service: S,
    ) -> impl std::future::Future<Output = HttpServeResult> + Send + '_
    where
        IO: Stream,
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = Response, Error = Infallible> + Clone;
}

impl HyperConnServer for Http1Builder {
    #[inline]
    async fn hyper_serve_connection<IO, State, S>(
        &self,
        ctx: Context<State>,
        io: IO,
        service: S,
    ) -> HttpServeResult
    where
        IO: Stream,
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = Response, Error = Infallible> + Clone,
    {
        let stream = TokioIo::new(Box::pin(io));
        let guard = ctx.guard().cloned();
        let service = HyperService::new(ctx, service);

        let mut conn = pin!(self.serve_connection(stream, service).with_upgrades());

        if let Some(guard) = guard {
            let mut cancelled_fut = pin!(guard.cancelled().fuse());

            loop {
                select! {
                    _ = cancelled_fut.as_mut() => {
                        tracing::trace!("signal received: initiate graceful shutdown");
                        conn.as_mut().graceful_shutdown();
                    }
                    result = conn.as_mut() => {
                        tracing::trace!("connection finished");
                        result?;
                        return Ok(());
                    }
                }
            }
        } else {
            conn.await?;
            Ok(())
        }
    }
}

impl HyperConnServer for Http2Builder<Executor> {
    #[inline]
    async fn hyper_serve_connection<IO, State, S>(
        &self,
        ctx: Context<State>,
        io: IO,
        service: S,
    ) -> HttpServeResult
    where
        IO: Stream,
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = Response, Error = Infallible> + Clone,
    {
        let stream = TokioIo::new(Box::pin(io));
        let guard = ctx.guard().cloned();
        let service = HyperService::new(ctx, service);

        let mut conn = pin!(self.serve_connection(stream, service));

        if let Some(guard) = guard {
            let mut cancelled_fut = pin!(guard.cancelled().fuse());

            loop {
                select! {
                    _ = cancelled_fut.as_mut() => {
                        tracing::trace!("signal received: initiate graceful shutdown");
                        conn.as_mut().graceful_shutdown();
                    }
                    result = conn.as_mut() => {
                        tracing::trace!("connection finished");
                        result?;
                        return Ok(());
                    }
                }
            }
        } else {
            conn.await?;
            Ok(())
        }
    }
}

impl HyperConnServer for AutoBuilder<Executor> {
    #[inline]
    async fn hyper_serve_connection<IO, State, S>(
        &self,
        ctx: Context<State>,
        io: IO,
        service: S,
    ) -> HttpServeResult
    where
        IO: Stream,
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = Response, Error = Infallible> + Clone,
    {
        let stream = TokioIo::new(Box::pin(io));
        let guard = ctx.guard().cloned();
        let service = HyperService::new(ctx, service);

        let mut conn = pin!(self.serve_connection(stream, service));

        if let Some(guard) = guard {
            let mut cancelled_fut = pin!(guard.cancelled().fuse());

            loop {
                select! {
                    _ = cancelled_fut.as_mut() => {
                        tracing::trace!("signal received: nop: graceful shutdown not supported for auto builder");
                        conn.as_mut().graceful_shutdown();
                    }
                    result = conn.as_mut() => {
                        tracing::trace!("connection finished");
                        result.map_err(crate::error::Error::new)?;
                        return Ok(());
                    }
                }
            }
        } else {
            conn.await.map_err(crate::error::Error::new)?;
            Ok(())
        }
    }
}

mod private {
    pub trait Sealed {}

    impl Sealed for super::Http1Builder {}
    impl Sealed for super::Http2Builder<super::Executor> {}
    impl Sealed for super::AutoBuilder<super::Executor> {}
}
