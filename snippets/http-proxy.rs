use std::pin::Pin;

use crate::{
    net::TcpStream,
    service::{Layer, Service},
    state::Extendable,
    stream::{AsyncReadExt, AsyncWriteExt, Stream},
};

pub struct HttpProxyService<S> {
    inner: S,
}

impl<S, T> Service<TcpStream<S>> for HttpProxyService<T>
where
    S: Stream,
    T: Service<TcpStream<Pin<Box<S>>>>,
{
    type Response = T::Response;
    type Error = HttpProxyError<T::Error>;

    async fn call(&self, stream: TcpStream<S>) -> Result<Self::Response, Self::Error> {
        let (stream, extensions) = stream.into_parts();
        let stream = Box::pin(stream);
        let mut stream = TcpStream::from_parts(stream, extensions);

        // read the incoming connection
        let cfg = read_http_connect_request::<T::Error>(&mut stream).await?;
        // TODO: read this better via hyper server?
        // TODO: allow layers on request, e.g. this would allow auth...?
        // ... service would be hardcoded to answer response :) 200
        // ... very similar to http router service, into response?!
        stream.extensions_mut().insert(cfg);

        // ack to incoming connection that all is good
        write_http_connect_response(&mut stream, 200).await?;

        self.inner
            .call(stream)
            .await
            .map_err(HttpProxyError::ServiceError)
    }
}

// TODO: should this implement perhaps certain traits?
// TODO: perhaps split this up so that our downstream services do not need to know
// it came from an http proxy (e.g. split into ProxyAuth and TargetSocketAddr)
#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    pub host: String,
    // TODO: should we already parse this perhaps?
    pub auth: Option<String>,
}

#[derive(Debug)]
pub enum HttpProxyError<S> {
    IoError(std::io::Error),
    ParseError(httparse::Error),
    Incomplete,
    UnexpectedMethod(Option<String>),
    MissingHost,
    ServiceError(S),
}

impl<S> From<std::io::Error> for HttpProxyError<S> {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl<S> From<httparse::Error> for HttpProxyError<S> {
    fn from(err: httparse::Error) -> Self {
        Self::ParseError(err)
    }
}

impl<S: std::fmt::Display> std::fmt::Display for HttpProxyError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpProxyError::IoError(err) => write!(f, "io error: {}", err),
            HttpProxyError::ParseError(err) => write!(f, "parse error: {}", err),
            HttpProxyError::Incomplete => write!(f, "incomplete request"),
            HttpProxyError::UnexpectedMethod(method) => {
                write!(f, "unexpected method: {:?}", method)
            }
            HttpProxyError::MissingHost => write!(f, "missing host header"),
            HttpProxyError::ServiceError(err) => write!(f, "service error: {}", err),
        }
    }
}

impl<S: std::fmt::Debug + std::fmt::Display> std::error::Error for HttpProxyError<S> {}

async fn read_http_connect_request<S>(
    stream: &mut (impl Stream + Unpin),
) -> Result<HttpProxyConfig, HttpProxyError<S>> {
    let mut buffer = [0; 512];
    let read_size = stream.read(&mut buffer).await?;

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);

    let req_status = match req.parse(&buffer[..read_size]) {
        Ok(req_status) => req_status,
        Err(err) => {
            return Err(err.into());
        }
    };
    if !req_status.is_complete() {
        return Err(HttpProxyError::Incomplete);
    }

    if !matches!(req.method, Some("CONNECT")) {
        return Err(HttpProxyError::UnexpectedMethod(
            req.method.map(|s| s.to_string()),
        ));
    }

    let mut host = String::new();
    let mut auth = None;

    for header in req.headers {
        if header.name.eq_ignore_ascii_case("Host") {
            host = String::from_utf8_lossy(header.value).to_string();
            if auth.is_some() {
                // exit early if we found both
                break;
            }
        } else if header.name.eq_ignore_ascii_case("Proxy-Authorization") {
            auth = Some(String::from_utf8_lossy(header.value).to_string());
            if !host.is_empty() {
                // exit early if we found both
                break;
            }
        }
    }

    if host.is_empty() {
        return Err(HttpProxyError::MissingHost);
    }

    Ok(HttpProxyConfig { host, auth })
}

async fn write_http_connect_response<S>(
    stream: &mut (impl Stream + Unpin),
    method: u16,
) -> Result<(), HttpProxyError<S>> {
    stream
        .write_all(format!("HTTP/1.1 {method} Connection established\r\n\r\n").as_bytes())
        .await?;
    stream.flush().await?;

    Ok(())
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpProxyLayer;

impl HttpProxyLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HttpProxyLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for HttpProxyLayer {
    type Service = HttpProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpProxyService { inner }
    }
}
