mod graceful;
use std::{
    future::{ready, Future},
    rc::Rc,
};

use futures::TryFutureExt;
pub use graceful::*;

mod ungraceful;
use tokio::net::{TcpListener, ToSocketAddrs};
pub use ungraceful::*;

mod future;

use crate::core::transport::listener;

use super::Result;

pub fn server<A: ToSocketAddrs>(addr: A) -> ServerBuilder<A> {
    ServerBuilder { addr }
}

pub struct ServerBuilder<A: ToSocketAddrs> {
    addr: A,
}

impl<A> ServerBuilder<A>
where
    A: ToSocketAddrs,
{
    pub async fn listen<F: ServiceFactory + Send>(
        self,
        service_factory: F,
    ) -> impl Future<Output = Result<()>>
    where
        <F as ServiceFactory>::Service: Send,
        <<F as ServiceFactory>::Service as Service>::Future: Send,
    {
        let listener = match TcpListener::bind(self.addr).await {
            Ok(listener) => listener,
            Err(e) => return ready(Err(e.into())),
        };
        let listener = Listener {
            listener: Rc::new(listener),
            service_factory,
        };
        // TODO: this line does not work.... Zzzz
        listener::server(listener).listen()
    }
}
