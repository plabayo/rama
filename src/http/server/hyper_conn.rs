use std::error::Error as StdError;

use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper_util::server::conn::auto::Builder as AutoBuilder;

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
        let io = Box::pin(io);
        let stream = HyperIo::new(io);
        self.serve_connection(stream, service)
            .with_upgrades()
            .await?;
        Ok(())
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
        let io = Box::pin(io);
        let stream = HyperIo::new(io);
        self.serve_connection(stream, service).await?;
        Ok(())
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
        let io = Box::pin(io);
        let stream = HyperIo::new(io);
        self.serve_connection_with_upgrades(stream, service).await?;
        Ok(())
    }
}
