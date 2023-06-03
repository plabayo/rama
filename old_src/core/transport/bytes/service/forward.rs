// use std::{net::SocketAddr, future::{IntoFuture, Future}, task::{Context, Poll}, pin::Pin};

// use tokio::net::TcpStream;

// use crate::core::transport::{tcp::server::Service, bytes::ByteStream, graceful::Graceful};


// pub struct Forwarder {
//     target: TcpStream,
// }
// impl<'a, S: ByteStream + Graceful<'a>> Service<S> for Forwarder {
//     type Future = ForwarderFuture;

//     fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), String>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, stream: S) -> Self::Future {
//         ForwarderFuture {
//             stream: tokio::net::TcpStream::from_std(self.stream).unwrap(),
//         }
//     }
// }

// pub struct ForwarderFuture<F>(F);

// impl<F> Future for ForwarderFuture<F>
//     where F: Future<Output = std::io::Result<(u64, u64)>>,
// {
//     type Output = std::io::Result<()>;

//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         self.poll(cx)
//     }
// }
