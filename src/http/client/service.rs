use crate::{
    error::Error,
    http::{
        layer::dns::DnsResolvedSocketAddresses,
        service::web::extract::{FromRequestParts, Host},
        Request, Response, Version,
    },
    service::{Context, Service},
};
use hyper_util::rt::TokioIo;

#[derive(Debug, Clone)]
#[non_exhaustive]
/// An http client that can be used to serve HTTP/1.1 and H2 requests.
///
/// This client is not intended to be used as a general purpose HTTP client, but rather as a
/// building block for creating more specialized clients.
///
/// This client does not support persistent connections, and does not support connection pooling.
/// It is yet to be defined if it will support this, among also support for upstream proxies,
/// TLS connections and more.
///
/// This client is highly experimental and it is not yet sure how we'll end up releasing it.
/// The connection with the `ua` concept and other features are also unclear.
///
/// <https://docs.rs/hyper-util/latest/hyper_util/client/legacy/struct.Client.html>
/// might serve for some inspiration for some of the above features.
pub struct HttpClient;

impl HttpClient {
    /// Create a new [`HttpClient`].
    pub fn new() -> Self {
        HttpClient
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
/// Error type for the [`HttpClient`].
pub enum HttpClientError {
    /// The HTTP version is invalid.
    InvalidVersion(Version),
    /// The host information is missing.
    ///
    /// This information is required to be able to establish an L4 connection,
    /// to serve the request over.
    MissingHost,
    /// The host information is invalid.
    ///
    /// (e.g. could not be parsed as a [`SocketAddr`])
    ///
    /// [`SocketAddr`]: std::net::SocketAddr
    InvalidHost(String),
    /// An IO error occurred.
    ///
    /// (e.g. during a handshake process)
    IoError(std::io::Error),
    /// An HTTP error occurred during the http handshake or transfer process.
    HttpError(Error),
}

impl From<std::io::Error> for HttpClientError {
    fn from(err: std::io::Error) -> Self {
        HttpClientError::IoError(err)
    }
}

impl From<hyper::Error> for HttpClientError {
    fn from(err: hyper::Error) -> Self {
        HttpClientError::HttpError(err.into())
    }
}

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpClientError::InvalidVersion(version) => {
                write!(f, "Invalid HTTP version: {:?}", version)
            }
            HttpClientError::MissingHost => {
                write!(f, "Missing host header")
            }
            HttpClientError::InvalidHost(host) => {
                write!(f, "Invalid host: {}", host)
            }
            HttpClientError::IoError(err) => {
                write!(f, "IO error: {}", err)
            }
            HttpClientError::HttpError(err) => {
                write!(f, "HTTP error: {}", err)
            }
        }
    }
}

impl std::error::Error for HttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HttpClientError::InvalidVersion(_) => None,
            HttpClientError::MissingHost => None,
            HttpClientError::InvalidHost(_) => None,
            HttpClientError::IoError(err) => Some(err),
            HttpClientError::HttpError(err) => Some(err.as_ref()),
        }
    }
}

impl<State, Body> Service<State, Request<Body>> for HttpClient
where
    State: Send + Sync + 'static,
    Body: http_body::Body + Unpin + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response;
    type Error = HttpClientError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        // TODO: should this service be able to support persistent connection?
        // TODO: should this service be able to support connection pooling?

        let (parts, body) = req.into_parts();

        // get target address
        let address = if let Some(dns_info) = ctx.get::<DnsResolvedSocketAddresses>() {
            dns_info.address().to_string()
        } else {
            let host = match Host::from_request_parts(&ctx, &parts).await {
                Ok(host) => host.0,
                Err(_) => return Err(HttpClientError::MissingHost),
            };
            if host.contains(':') {
                host
            } else {
                let port = parts.uri.port().map(|p| p.as_u16()).unwrap_or_else(|| {
                    parts
                        .uri
                        .scheme()
                        .map(|s| match s.as_str() {
                            // TODO is this scheme mapping complete enough?
                            // and should we fail on unknown schemes?
                            // should this be a shared utility somewhere?
                            "http" => 80,
                            _ => 443,
                        })
                        .unwrap_or(443)
                });
                format!("{}:{}", host, port)
            }
        };

        // TODO: should this client support upstream proxies?

        // create the tcp connection
        tokio::net::TcpStream::connect(&address).await?;

        let tcp_stream = tokio::net::TcpStream::connect(address).await?;

        // TODO: figure out how we wish to handle https here

        let tcp_stream = TokioIo::new(Box::pin(tcp_stream));

        let req = Request::from_parts(parts, body);
        let resp = match req.version() {
            Version::HTTP_2 => {
                let executor = ctx.executor().clone();
                let (mut sender, conn) =
                    hyper::client::conn::http2::handshake(executor, tcp_stream).await?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        // TOD: should this error level / handling be configurable?
                        tracing::error!("connection failed: {:?}", err);
                    }
                });

                sender.send_request(req).await?
            }
            Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                let (mut sender, conn) = hyper::client::conn::http1::handshake(tcp_stream).await?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        // TODO: should this error level / handling be configurable?
                        tracing::error!("connection failed: {:?}", err);
                    }
                });

                sender.send_request(req).await?
            }
            version => return Err(HttpClientError::InvalidVersion(version)),
        };

        let resp = resp.map(crate::http::Body::new);
        Ok(resp)
    }
}
