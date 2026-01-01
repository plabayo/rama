//! Rama gRPC server module.

use std::convert::Infallible;

use rama_core::{Service, error::BoxError, graceful::ShutdownGuard, rt::Executor};
use rama_http_core::server::conn::http2::Builder as H2ConnBuilder;
use rama_http_types::Request;
use rama_net::socket::Interface;
use rama_tcp::server::TcpListener;

mod service;

#[doc(inline)]
pub use self::service::GrpcService;

/// A specialized result for gRPC server operations.
pub type GrpcServeResult = Result<(), BoxError>;

/// A builder for configuring and listening over gRPC (HTTP/2).
#[derive(Debug, Clone)]
pub struct GrpcServer {
    builder: H2ConnBuilder,
    guard: Option<ShutdownGuard>,
}

impl GrpcServer {
    /// Create a new gRPC server builder with default H2 settings.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        let guard = exec.guard().cloned();
        Self {
            builder: H2ConnBuilder::new(exec),
            guard,
        }
    }

    /// Access the underlying H2 configuration (e.g., window sizes, keepalives).
    pub fn h2_mut(&mut self) -> &mut H2ConnBuilder {
        &mut self.builder
    }

    /// Create a Rama [`Service`] that can serve an IO Byte streams as gRPC.
    pub fn service<S>(self, service: S) -> GrpcService<S> {
        GrpcService::new(self.builder, service)
    }

    /// Listen for connections on the given interface and serve gRPC.
    pub async fn listen<S, I>(self, interface: I, service: S) -> GrpcServeResult
    where
        S: Service<Request, Output = rama_http_types::Response, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        // TODO: what should output be?
        I: TryInto<Interface, Error: Into<BoxError>>,
    {
        let tcp = TcpListener::bind(interface).await?;
        let service = GrpcService::new(self.builder, service);

        match self.guard {
            Some(guard) => tcp.serve_graceful(guard, service).await,
            None => tcp.serve(service).await,
        };
        Ok(())
    }
}
