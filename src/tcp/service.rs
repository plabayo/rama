use std::future::Future;
use std::task::{Context, Poll};

use tokio::net::TcpStream;
use tower_service::Service;

pub trait TcpService {
    type Error: Into<crate::Error>;
    type Future: Future<Output = Result<(), Self::Error>>;

    /// Returns `Ready` when the service is able to handle an incoming TCP Stream.
    ///
    /// Reference [`Service::poll_ready`].
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Handle the TCP Stream and return when finished.
    ///
    /// Reference [`Service::call`].
    fn call(&mut self, stream: TcpStream) -> Self::Future;
}

impl<S> TcpService for S
where
    S: Service<TcpStream, Response = ()>,
    S::Error: Into<crate::Error>,
{
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(self, cx)
    }

    fn call(&mut self, stream: TcpStream) -> Self::Future {
        Service::call(self, stream)
    }
}
