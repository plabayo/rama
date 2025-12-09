use crate::protocol::{HeaderResult, PartialResult, v1, v2};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    extensions::ExtensionsMut,
    stream::{HeapReader, PeekStream, Stream},
    telemetry::tracing,
};
use rama_net::forwarded::{Forwarded, ForwardedElement};
use rama_utils::macros::generate_set_and_with;
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;

/// Layer to decode the HaProxy Protocol
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct HaProxyLayer {
    peek: bool,
}

impl HaProxyLayer {
    /// Create a new [`HaProxyLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self { peek: false }
    }

    generate_set_and_with!(
        /// Instruct [`HaProxyLayer`] to peek prior to comitting to the `HaProxy` protocol.
        ///
        /// Doing so makes it possible to support traffic with or without the use of that data.
        /// This can be useful to run services locally (not behind a loadbalancer) as well as in the
        /// the cloud (production, behind a loadbalancer).
        pub fn peek(mut self, value: bool) -> Self {
            self.peek = value;
            self
        }
    );
}

impl<S> Layer<S> for HaProxyLayer {
    type Service = HaProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HaProxyService {
            inner,
            peek: self.peek,
        }
    }
}

/// Service to decode the HaProxy Protocol
///
/// This service will decode the HaProxy Protocol header and pass the decoded
/// information to the inner service.
#[derive(Debug, Clone)]
pub struct HaProxyService<S> {
    inner: S,
    peek: bool,
}

impl<S> HaProxyService<S> {
    /// Create a new [`HaProxyService`] with the given inner service.
    pub const fn new(inner: S) -> Self {
        Self { inner, peek: false }
    }

    generate_set_and_with!(
        /// Instruct [`HaProxyService`] to peek prior to comitting to the `HaProxy` protocol.
        ///
        /// Doing so makes it possible to support traffic with or without the use of that data.
        /// This can be useful to run services locally (not behind a loadbalancer) as well as in the
        /// the cloud (production, behind a loadbalancer).
        pub fn peek(mut self, value: bool) -> Self {
            self.peek = value;
            self
        }
    );
}

impl<S, IO> Service<IO> for HaProxyService<S>
where
    S: Service<PeekStream<HeapReader, IO>, Error: Into<BoxError>>,
    IO: Stream + Unpin + ExtensionsMut,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut stream: IO) -> Result<Self::Output, Self::Error> {
        let (mut buffer, mut read) = if self.peek {
            tracing::trace!("haproxy protocol peeking enabled: start detection");

            let mut peek_buf = [0; v2::PROTOCOL_PREFIX.len()]; // sufficient for both v1 and v2

            let n = stream
                .read(&mut peek_buf)
                .await
                .context("try to read haProxy peek data")?;

            if peek_buf == v2::PROTOCOL_PREFIX {
                tracing::trace!(
                    "haproxy protocol peeked: v2 detected: continue with haproxy handling"
                );

                let mut buf = [0; 512];
                buf[..n].copy_from_slice(&peek_buf[..n]);
                (buf, n)
            } else if n > v1::PROTOCOL_PREFIX.len()
                && &peek_buf[..v1::PROTOCOL_PREFIX.len()] == v1::PROTOCOL_PREFIX.as_bytes()
            {
                tracing::trace!(
                    "haproxy protocol peeked: v1 detected: continue with haproxy handling"
                );

                let mut buf = [0; 512];
                buf[..n].copy_from_slice(&peek_buf[..n]);
                (buf, n)
            } else {
                tracing::trace!(
                    "no haproxy protocol detected... delegating immediately to inner..."
                );

                let mem = HeapReader::new(peek_buf[..n].into());
                let stream = PeekStream::new(mem, stream);
                return self.inner.serve(stream).await.map_err(Into::into);
            }
        } else {
            tracing::trace!("haproxy protocol enforced: skip peeking");
            ([0; 512], 0)
        };

        let header = loop {
            if read >= buffer.len() {
                return Err(
                    OpaqueError::from_display("Buffer exhausted before parsing completed")
                        .into_boxed(),
                );
            }

            let n = stream.read(&mut buffer[read..]).await?;
            read += n;

            let header = HeaderResult::parse(&buffer[..read]);
            if header.is_complete() {
                break header;
            }

            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
                    .context("HaProxy header incomplete")
                    .into_boxed());
            }

            tracing::debug!("Incomplete header. Read {read} bytes so far.");
        };

        let consumed = match header {
            HeaderResult::V1(Ok(header)) => {
                match header.addresses {
                    v1::Addresses::Tcp4(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::new_forwarded_for(peer_addr);
                        let forwarded = if let Some(mut forwarded) =
                            stream.extensions_mut().get::<Forwarded>().cloned()
                        {
                            forwarded.append(el);
                            forwarded
                        } else {
                            Forwarded::new(el)
                        };
                        stream.extensions_mut().insert(forwarded);
                    }
                    v1::Addresses::Tcp6(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::new_forwarded_for(peer_addr);
                        let forwarded = if let Some(mut forwarded) =
                            stream.extensions_mut().get::<Forwarded>().cloned()
                        {
                            forwarded.append(el);
                            forwarded
                        } else {
                            Forwarded::new(el)
                        };
                        stream.extensions_mut().insert(forwarded);
                    }
                    v1::Addresses::Unknown => (),
                };
                header.header.len()
            }
            HeaderResult::V2(Ok(header)) => {
                match header.addresses {
                    v2::Addresses::IPv4(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::new_forwarded_for(peer_addr);
                        let forwarded = if let Some(mut forwarded) =
                            stream.extensions_mut().get::<Forwarded>().cloned()
                        {
                            forwarded.append(el);
                            forwarded
                        } else {
                            Forwarded::new(el)
                        };
                        stream.extensions_mut().insert(forwarded);
                    }
                    v2::Addresses::IPv6(info) => {
                        let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                        let el = ForwardedElement::new_forwarded_for(peer_addr);
                        let forwarded = if let Some(mut forwarded) =
                            stream.extensions_mut().get::<Forwarded>().cloned()
                        {
                            forwarded.append(el);
                            forwarded
                        } else {
                            Forwarded::new(el)
                        };
                        stream.extensions_mut().insert(forwarded);
                    }
                    v2::Addresses::Unix(_) | v2::Addresses::Unspecified => (),
                };
                header.header.len()
            }
            HeaderResult::V1(Err(error)) => {
                return Err(error.into());
            }
            HeaderResult::V2(Err(error)) => {
                return Err(error.into());
            }
        };

        // put back the data that is read too much
        let mem: HeapReader = buffer[consumed..read].into();
        let stream = PeekStream::new(mem, stream);

        // read the rest of the data
        self.inner.serve(stream).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use rama_core::{ServiceInput, service::service_fn};

    use super::*;

    async fn echo(mut stream: impl Stream + Unpin) -> Result<Vec<u8>, BoxError> {
        let mut v = Vec::default();
        let _ = stream.read_to_end(&mut v).await?;
        Ok(v)
    }

    #[tokio::test]
    async fn test_haproxy_peek_direct() {
        let proxy_svc = HaProxyService::new(service_fn(echo)).with_peek(true);

        let request = ServiceInput::new(std::io::Cursor::new(b"foo".to_vec()));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("foo", String::from_utf8(response).unwrap());

        let request = ServiceInput::new(std::io::Cursor::new(
            b"Hello, this is a test to check if it works.".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!(
            "Hello, this is a test to check if it works.",
            String::from_utf8(response).unwrap()
        );
    }

    #[tokio::test]
    async fn test_haproxy_peek_with_haproxy_v1() {
        let proxy_svc = HaProxyService::new(service_fn(echo));

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\n".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("", String::from_utf8(response).unwrap());

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\nfoo".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("foo", String::from_utf8(response).unwrap());

        let proxy_svc = proxy_svc.with_peek(true);

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\n".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("", String::from_utf8(response).unwrap());

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\nfoo".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("foo", String::from_utf8(response).unwrap());
    }

    #[tokio::test]
    async fn test_haproxy_peek_with_haproxy_v2() {
        const DATA: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // Signature
            0x21, // Version (0x2) + Command (PROXY = 0x1)
            0x11, // Family (IPv4 = 0x1) + Protocol (TCP = 0x1)
            0x00, 0x0C, // Address length = 12 bytes
            // Source IP: 192.0.2.1
            0xC0, 0x00, 0x02, 0x01, // Dest IP: 198.51.100.1
            0xC6, 0x33, 0x64, 0x01, // Source Port: 12345 (0x3039)
            0x30, 0x39, // Dest Port: 443 (0x01BB)
            0x01, 0xBB, // foo data
            0x66, 0x6F, 0x6F,
        ];

        let proxy_svc = HaProxyService::new(service_fn(echo));
        let request = ServiceInput::new(std::io::Cursor::new(DATA.to_vec()));
        let response = proxy_svc.serve(request).await.unwrap();
        assert_eq!("foo", String::from_utf8(response).unwrap());

        let proxy_svc = proxy_svc.with_peek(true);
        let request = ServiceInput::new(std::io::Cursor::new(DATA.to_vec()));
        let response = proxy_svc.serve(request).await.unwrap();
        assert_eq!("foo", String::from_utf8(response).unwrap());
    }
}
