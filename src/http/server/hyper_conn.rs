use std::error::Error as StdError;

use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper::service::service_fn;
use hyper_util::server::conn::auto::Builder as AutoBuilder;

use crate::rt::{graceful::ShutdownGuard, pin, select};
use crate::tcp::TcpStream;

use super::{GlobalExecutor, HyperIo, Response, ServeResult};

/// A private utility trait to allow any of the hyper server builders to be used
/// in the same way to (http) serve a connection.
pub trait HyperConnServer {
    fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> impl std::future::Future<Output = ServeResult>
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>;
}

impl HyperConnServer for Http1Builder {
    #[inline]
    async fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let extensions = io.extensions().clone();

        let io = Box::pin(io);
        let guard = io.extensions().get::<ShutdownGuard>().cloned();

        let stream = HyperIo::new(io);

        let conn = self
            .serve_connection(
                stream,
                service_fn(move |mut request| {
                    // insert transport extensions into the request
                    let extensions = extensions.clone();
                    request.extensions_mut().extend(extensions);

                    // call the service
                    service.call(request)
                }),
            )
            .with_upgrades();

        if let Some(guard) = guard {
            pin!(conn);

            let cancelled_fut = guard.cancelled();
            pin!(cancelled_fut);
            let mut cancelled = false;

            loop {
                select! {
                    _ = cancelled_fut.as_mut(), if !cancelled => {
                        tracing::trace!("signal received: initiate graceful shutdown");
                        conn.as_mut().graceful_shutdown();
                        cancelled = true;
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

impl HyperConnServer for Http2Builder<GlobalExecutor> {
    #[inline]
    async fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let extensions = io.extensions().clone();

        let io = Box::pin(io);
        let guard = io.extensions().get::<ShutdownGuard>().cloned();

        let stream = HyperIo::new(io);

        let conn = self.serve_connection(
            stream,
            service_fn(move |mut request| {
                // insert transport extensions into the request
                let extensions = extensions.clone();
                request.extensions_mut().extend(extensions);

                // call the service
                service.call(request)
            }),
        );

        if let Some(guard) = guard {
            pin!(conn);

            let cancelled_fut = guard.cancelled();
            pin!(cancelled_fut);
            let mut cancelled = false;

            loop {
                select! {
                    _ = cancelled_fut.as_mut(), if !cancelled => {
                        tracing::trace!("signal received: initiate graceful shutdown");
                        conn.as_mut().graceful_shutdown();
                        cancelled = true;
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

impl HyperConnServer for AutoBuilder<GlobalExecutor> {
    #[inline]
    async fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let extensions = io.extensions().clone();

        let io = Box::pin(io);
        let guard = io.extensions().get::<ShutdownGuard>().cloned();

        let stream = HyperIo::new(io);

        let conn = self.serve_connection_with_upgrades(
            stream,
            service_fn(move |mut request| {
                // insert transport extensions into the request
                let extensions = extensions.clone();
                request.extensions_mut().extend(extensions);

                // call the service
                service.call(request)
            }),
        );

        if let Some(guard) = guard {
            pin!(conn);

            let cancelled_fut = guard.cancelled();
            pin!(cancelled_fut);
            let mut cancelled = false;

            loop {
                select! {
                    _ = cancelled_fut.as_mut(), if !cancelled => {
                        tracing::trace!("signal received: nop: graceful shutdown not supported for auto builder");
                        cancelled = true;
                        // TODO: support once it is implemented:
                        // https://github.com/hyperium/hyper-util/pull/66
                        // conn.as_mut().graceful_shutdown();
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
