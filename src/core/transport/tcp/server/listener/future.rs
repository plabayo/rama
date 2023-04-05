use std::future::Future;
use std::rc::Rc;
use std::task::Poll;
use std::{
    pin::Pin,
    task::{ready, Context},
};

use pin_project_lite::pin_project;
use tokio::net::{TcpListener, TcpStream};

use crate::core::transport::tcp::server::Result;

pin_project! {
    pub struct ListenerFuture {
        #[pin]
        pub listener: Rc<TcpListener>,
    }
}

impl Future for ListenerFuture {
    type Output = Result<TcpStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(self.project().listener.poll_accept(cx));
        Poll::Ready(match result {
            Ok((stream, _)) => Ok(stream),
            Err(e) => Err(e.into()),
        })
    }
}
