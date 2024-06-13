//! Client Http Proxy Support.
//!
//! As defined in <https://www.ietf.org/rfc/rfc2068.txt>.

use crate::{
    http::{
        headers::{Header, HeaderMapExt},
        HeaderMap, HeaderName, HeaderValue,
    },
    net::{address::Authority, stream::Stream},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod layer;
pub use layer::{HttpProxyConnectorLayer, HttpProxyConnectorService};

#[derive(Debug, Clone)]
/// Connector for HTTP proxies.
///
/// Used to connect as a client to a HTTP proxy server.
pub struct HttpProxyConnector {
    authority: Authority,
    headers: Option<HeaderMap>,
}

// TODO: investigate if we want to have layer support?
// Just for response or both? Or just a response headerMap callback?
// Or nothing?

impl HttpProxyConnector {
    /// Create a new [`HttpProxyConnector`] with the given authority.
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            headers: None,
        }
    }

    /// Add a header to the request.
    pub fn with_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        match self.headers {
            Some(ref mut headers) => {
                headers.insert(name, value);
            }
            None => {
                let mut headers = HeaderMap::new();
                headers.insert(name, value);
                self.headers = Some(headers);
            }
        }
        self
    }

    /// Add a typed header to the request.
    pub fn with_typed_header(&mut self, header: impl Header) -> &mut Self {
        match self.headers {
            Some(ref mut headers) => {
                headers.typed_insert(header);
            }
            None => {
                let mut headers = HeaderMap::new();
                headers.typed_insert(header);
                self.headers = Some(headers);
            }
        }
        self
    }

    /// Connect to the proxy server.
    pub async fn handshake<S: Stream + Unpin>(&self, mut stream: S) -> Result<S, std::io::Error> {
        // TODO: handle user-agent and host better
        // TODO: use h1 protocol from embedded hyper directly here!
        let mut request = format!(
            "\
             CONNECT {authority} HTTP/1.1\r\n\
             Host: {authority}\r\n\
             User-Agent: {ua_name}/{ua_version}\r\n\
             ",
            authority = self.authority.host(),
            ua_name = crate::utils::info::NAME,
            ua_version = crate::utils::info::VERSION,
        )
        .into_bytes();
        if let Some(ref headers) = self.headers {
            for (name, value) in headers.iter() {
                request.extend_from_slice(name.as_str().as_bytes());
                request.extend_from_slice(b": ");
                request.extend_from_slice(value.as_bytes());
                request.extend_from_slice(b"\r\n");
            }
        }
        request.extend_from_slice(b"\r\n");

        stream.write_all(&request).await?;

        let mut buf = [0; 8192];
        let mut pos = 0;

        loop {
            let n = stream.read(&mut buf[pos..]).await?;

            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "http conn handshake read incomplete",
                ));
            }
            pos += n;

            let recvd = &buf[..pos];
            if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
                if recvd.ends_with(b"\r\n\r\n") {
                    return Ok(stream);
                }
                if pos == buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "http conn handshake response too large",
                    ));
                }
            // else read more
            } else if recvd.starts_with(b"HTTP/1.1 407") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "http conn handshake proxy auth required",
                ));
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid http conn handshake start",
                ));
            }
        }
    }
}
