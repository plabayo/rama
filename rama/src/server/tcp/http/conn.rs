use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoBuilder;

use crate::net::TcpStream;

type H2Executor = hyper_util::rt::TokioExecutor;

pub use crate::service::BoxError;
pub type ServeResult = Result<(), BoxError>;

pub use crate::net::http::Response;
pub use hyper::body::{Body, Incoming};
pub type Request = crate::net::http::Request<Incoming>;

#[derive(Debug)]
#[allow(dead_code)]
pub struct HttpConnector<B, S> {
    builder: B,
    with_upgrades: bool,
    stream: TcpStream<S>,
}

impl<S> HttpConnector<Http1Builder, S>
where
    S: crate::stream::Stream + Send + 'static,
{
    pub fn http1(stream: TcpStream<S>) -> Self {
        Self {
            builder: Http1Builder::new(),
            with_upgrades: false,
            stream,
        }
    }

    pub async fn serve<Service, B2>(self, service: Service) -> ServeResult
    where
        Service:
            DummyService<Request, Response = Response<B2>, call(): Send> + Send + Sync + 'static,
        Service::Error: Into<BoxError>,
        B2: Body + 'static,
        B2::Error: Into<BoxError>,
    {
        let stream = Box::pin(self.stream);
        let stream = TokioIo::new(stream);

        let service = HyperService::new(service);

        let conn = self.builder.serve_connection(stream, service);
        if self.with_upgrades {
            conn.with_upgrades().await
        } else {
            conn.await
        }?;

        Ok(())
    }
}

impl<S> HttpConnector<Http2Builder<H2Executor>, S>
where
    S: crate::stream::Stream + Send + 'static,
{
    pub fn h2(stream: TcpStream<S>) -> Self {
        Self {
            builder: Http2Builder::new(H2Executor::new()),
            with_upgrades: false,
            stream,
        }
    }

    pub async fn serve<Service, B2>(self, service: Service) -> ServeResult
    where
        Service:
            DummyService<Request, Response = Response<B2>, call(): Send> + Send + Sync + 'static,
        Service::Error: Into<BoxError>,
        B2: Body + Send + 'static,
        <B2 as Body>::Data: Send,
        B2::Error: Into<BoxError>,
    {
        let stream = Box::pin(self.stream);
        let stream = TokioIo::new(stream);

        let service = HyperService::new(service);

        self.builder.serve_connection(stream, service).await?;

        Ok(())
    }
}

impl<S> HttpConnector<AutoBuilder<H2Executor>, S>
where
    S: crate::stream::Stream + Send + 'static,
{
    pub fn auto(stream: TcpStream<S>) -> Self {
        Self {
            builder: AutoBuilder::new(H2Executor::new()),
            with_upgrades: false,
            stream,
        }
    }

    pub async fn serve<Service, B2>(self, service: Service) -> ServeResult
    where
        Service:
            DummyService<Request, Response = Response<B2>, call(): Send> + Send + Sync + 'static,
        Service::Error: Into<BoxError>,
        B2: Body + Send + 'static,
        <B2 as Body>::Data: Send,
        B2::Error: Into<BoxError>,
    {
        let steam = Box::pin(self.stream);
        let stream = TokioIo::new(steam);
        let service = HyperService::new(service);

        if self.with_upgrades {
            self.builder
                .serve_connection_with_upgrades(stream, service)
                .await?;
        } else {
            self.builder.serve_connection(stream, service).await?;
        }

        Ok(())
    }
}

struct HyperService<Service>(Arc<Service>);

impl<Service> HyperService<Service> {
    pub fn new(service: Service) -> Self {
        Self(Arc::new(service))
    }
}

impl<Service, B2> hyper::service::Service<Request> for HyperService<Service>
where
    Service: DummyService<Request, Response = Response<B2>, call(): Send> + Send + Sync + 'static,
    Service::Error: Into<BoxError>,
{
    type Response = Service::Response;
    type Error = Service::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn call(&self, req: Request) -> Self::Future {
        let service = self.0.clone();
        let future = async move { service.call(req).await };
        Box::pin(future)
    }
}

// TODO: turn '&mut self' of tower_async_service into '&self' and use it instead of this dummy
pub trait DummyService<Request> {
    /// Responses given by the service.
    type Response;

    /// Errors produced by the service.
    type Error;

    /// Process the request and return the response asynchronously.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    async fn call(&self, req: Request) -> Result<Self::Response, Self::Error>;
}
