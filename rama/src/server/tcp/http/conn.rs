use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper_util::server::conn::auto::Builder as AutoBuilder;

use crate::net::TcpStream;

type H2Executor = hyper_util::rt::TokioExecutor;

#[derive(Debug)]
#[allow(dead_code)]
pub struct HttpConnector<B, S> {
    builder: B,
    stream: TcpStream<S>,
}

impl<S> HttpConnector<Http1Builder, S> {
    pub fn http1(stream: TcpStream<S>) -> Self {
        Self {
            builder: Http1Builder::new(),
            stream,
        }
    }
}

impl<S> HttpConnector<Http2Builder<H2Executor>, S> {
    pub fn h2(stream: TcpStream<S>) -> Self {
        Self {
            builder: Http2Builder::new(H2Executor::new()),
            stream,
        }
    }
}

impl<S> HttpConnector<AutoBuilder<H2Executor>, S> {
    pub fn auto(stream: TcpStream<S>) -> Self {
        Self {
            builder: AutoBuilder::new(H2Executor::new()),
            stream,
        }
    }
}
