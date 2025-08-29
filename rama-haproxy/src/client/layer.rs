use std::{fmt, marker::PhantomData, net::IpAddr};

use crate::protocol::{v1, v2};
use rama_core::{
    Context, Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext, OpaqueError},
};
use rama_net::{
    client::{ConnectorService, EstablishedClientConnection},
    forwarded::Forwarded,
    stream::{Socket, SocketInfo, Stream},
};
use tokio::io::AsyncWriteExt;

/// Layer to encode and write the HaProxy Protocol,
/// as a client on the connected stream.
///
/// This connector should in most cases
/// happen as the first thing after establishing the connection.
#[derive(Debug, Clone)]
pub struct HaProxyLayer<P = protocol::Tcp, V = version::Two> {
    version: V,
    _phantom: PhantomData<fn(P)>,
}

impl HaProxyLayer {
    /// Create a new [`HaProxyLayer`] for the TCP protocol (default).
    ///
    /// This is in the PROXY spec referred to as:
    ///
    /// - TCP4 (for IPv4, v1)
    /// - TCP6 (for IPv6, v1)
    /// - Stream (v2)
    #[must_use]
    pub fn tcp() -> Self {
        Self {
            version: Default::default(),
            _phantom: PhantomData,
        }
    }

    /// Use version one of PROXY protocol, instead of the
    /// default version two.
    ///
    /// Version one makes use of a less advanced text protocol,
    /// instead the more advanced binary v2 protocol.
    ///
    /// Use this only if you have no control over a v1-only server.
    pub fn v1(self) -> HaProxyLayer<protocol::Tcp, version::One> {
        HaProxyLayer {
            version: Default::default(),
            _phantom: PhantomData,
        }
    }
}

impl HaProxyLayer<protocol::Udp> {
    /// Create a new [`HaProxyLayer`] for the UDP protocol,
    /// instead of the default TCP protocol.
    ///
    /// This is in the PROXY spec referred to as:
    ///
    /// - Datagram (v2)
    #[must_use]
    pub fn udp() -> Self {
        Self {
            version: Default::default(),
            _phantom: PhantomData,
        }
    }
}

impl<P> HaProxyLayer<P> {
    rama_utils::macros::generate_set_and_with! {
        /// Attach a custom bytes payload to the PROXY header.
        ///
        /// NOTE this is only possible in Version two of the PROXY Protocol.
        /// In case you downgrade this [`HaProxyLayer`] to version one later
        /// using [`Self::v1`] this payload will be dropped.
        pub fn payload(mut self, payload: impl Into<Bytes>) -> Self {
            self.version.payload = Some(payload.into());
            self
        }
    }
}

impl<S, P, V: Clone> Layer<S> for HaProxyLayer<P, V> {
    type Service = HaProxyService<S, P, V>;

    fn layer(&self, inner: S) -> Self::Service {
        HaProxyService {
            inner,
            version: self.version.clone(),
            _phantom: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HaProxyService {
            inner,
            version: self.version,
            _phantom: PhantomData,
        }
    }
}

/// Service to encode and write the HaProxy Protocol
/// as a client on the connected stream.
///
/// This connector should in most cases
/// happen as the first thing after establishing the connection.
pub struct HaProxyService<S, P = protocol::Tcp, V = version::Two> {
    inner: S,
    version: V,
    _phantom: PhantomData<fn(P)>,
}

impl<S> HaProxyService<S> {
    /// Create a new [`HaProxyService`] for the TCP protocol (default).
    ///
    /// This is in the PROXY spec referred to as:
    ///
    /// - TCP4 (for IPv4, v1)
    /// - TCP6 (for IPv6, v1)
    /// - Stream (v2)
    pub fn tcp(inner: S) -> Self {
        Self {
            inner,
            version: Default::default(),
            _phantom: PhantomData,
        }
    }

    /// Use version one of PROXY protocol, instead of the
    /// default version two.
    ///
    /// Version one makes use of a less advanced text protocol,
    /// instead the more advanced binary v2 protocol.
    ///
    /// Use this only if you have no control over a v1-only server.
    pub fn v1(self) -> HaProxyService<S, protocol::Tcp, version::One> {
        HaProxyService {
            inner: self.inner,
            version: Default::default(),
            _phantom: PhantomData,
        }
    }
}

impl<S> HaProxyService<S, protocol::Udp> {
    /// Create a new [`HaProxyService`] for the UDP protocol,
    /// instead of the default TCP protocol.
    ///
    /// This is in the PROXY spec referred to as:
    ///
    /// - Datagram (v2)
    pub fn udp(inner: S) -> Self {
        Self {
            inner,
            version: Default::default(),
            _phantom: PhantomData,
        }
    }
}

impl<S, P> HaProxyService<S, P> {
    rama_utils::macros::generate_set_and_with! {
        /// Attach a custom bytes payload to the PROXY header.
        ///
        /// NOTE this is only possible in Version two of the PROXY Protocol.
        /// In case you downgrade this [`HaProxyLayer`] to version one later
        /// using [`Self::v1`] this payload will be dropped.
        pub fn payload(mut self, payload: impl Into<Bytes>) -> Self {
            self.version.payload = Some(payload.into());
            self
        }
    }
}

impl<S: fmt::Debug, P, V: fmt::Debug> fmt::Debug for HaProxyService<S, P, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HaProxyService")
            .field("inner", &self.inner)
            .field("version", &self.version)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(P)>()),
            )
            .finish()
    }
}

impl<S: Clone, P, V: Clone> Clone for HaProxyService<S, P, V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            version: self.version.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S, P, Request> Service<Request> for HaProxyService<S, P, version::One>
where
    S: ConnectorService<Request, Connection: Stream + Socket + Unpin, Error: Into<BoxError>>,
    P: Send + 'static,
    Request: Send + 'static,
{
    type Response = EstablishedClientConnection<S::Connection, Request>;
    type Error = BoxError;

    async fn serve(&self, ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { ctx, req, mut conn } =
            self.inner.connect(ctx, req).await.map_err(Into::into)?;

        let src = ctx
            .get::<Forwarded>()
            .and_then(|f| f.client_socket_addr())
            .or_else(|| ctx.get::<SocketInfo>().map(|info| *info.peer_addr()))
            .ok_or_else(|| {
                OpaqueError::from_display("PROXY client (v1): missing src socket address")
            })?;

        let peer_addr = conn.peer_addr()?;
        let addresses = match (src.ip(), peer_addr.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                v1::Addresses::new_tcp4(src_ip, dst_ip, src.port(), peer_addr.port())
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                v1::Addresses::new_tcp6(src_ip, dst_ip, src.port(), peer_addr.port())
            }
            (_, _) => {
                return Err(OpaqueError::from_display(
                    "PROXY client (v1): IP version mismatch between src and dest",
                )
                .into());
            }
        };

        conn.write_all(addresses.to_string().as_bytes())
            .await
            .context("PROXY client (v1): write addresses")?;

        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}

impl<S, P, Request, T> Service<Request> for HaProxyService<S, P, version::Two>
where
    S: Service<Request, Response = EstablishedClientConnection<T, Request>, Error: Into<BoxError>>,
    P: protocol::Protocol + Send + 'static,
    Request: Send + 'static,
    T: Stream + Socket + Unpin,
{
    type Response = EstablishedClientConnection<T, Request>;
    type Error = BoxError;

    async fn serve(&self, ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { ctx, req, mut conn } =
            self.inner.serve(ctx, req).await.map_err(Into::into)?;

        let src = ctx
            .get::<Forwarded>()
            .and_then(|f| f.client_socket_addr())
            .or_else(|| ctx.get::<SocketInfo>().map(|info| *info.peer_addr()))
            .ok_or_else(|| {
                OpaqueError::from_display("PROXY client (v2): missing src socket address")
            })?;

        let peer_addr = conn.peer_addr()?;
        let builder = match (src.ip(), peer_addr.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => v2::Builder::with_addresses(
                v2::Version::Two | v2::Command::Proxy,
                P::v2_protocol(),
                v2::IPv4::new(src_ip, dst_ip, src.port(), peer_addr.port()),
            ),
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => v2::Builder::with_addresses(
                v2::Version::Two | v2::Command::Proxy,
                P::v2_protocol(),
                v2::IPv6::new(src_ip, dst_ip, src.port(), peer_addr.port()),
            ),
            (_, _) => {
                return Err(OpaqueError::from_display(
                    "PROXY client (v2): IP version mismatch between src and dest",
                )
                .into());
            }
        };

        let builder = if let Some(payload) = self.version.payload.as_deref() {
            builder
                .write_payload(payload)
                .context("PROXY client (v2): write custom binary payload to to header")?
        } else {
            builder
        };

        let header = builder
            .build()
            .context("PROXY client (v2): encode header")?;
        conn.write_all(&header[..])
            .await
            .context("PROXY client (v2): write header")?;

        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}

pub mod version {
    //! Marker traits for the HaProxy (PROXY) version to be used by client layer (service).

    use super::*;

    #[derive(Debug, Clone, Default)]
    /// Use version 1 of the PROXY protocol.
    ///
    /// See [`crate::protocol`] for more information.
    #[non_exhaustive]
    pub struct One;

    #[derive(Debug, Clone, Default)]
    /// Use version 2 of the PROXY protocol.
    ///
    /// See [`crate::protocol`] for more information.
    pub struct Two {
        pub(crate) payload: Option<Bytes>,
    }
}

pub mod protocol {
    //! Marker traits for the HaProxy (PROXY) protocol to be used by client layer (service).

    use crate::protocol::v2;

    #[derive(Debug, Clone)]
    /// Encode the data for the TCP protocol (possible in [`super::version::One`] and [`super::version::Two`]).
    ///
    /// See [`crate::protocol`] for more information.
    pub struct Tcp;

    #[derive(Debug, Clone)]
    /// Encode the data for the UDP protocol (possible only in [`super::version::Two`]).
    ///
    /// See [`crate::protocol`] for more information.
    pub struct Udp;

    pub(super) trait Protocol {
        /// Return the v2 PROXY protocol linked to the protocol implementation.
        fn v2_protocol() -> v2::Protocol;
    }

    impl Protocol for Tcp {
        fn v2_protocol() -> v2::Protocol {
            v2::Protocol::Stream
        }
    }

    impl Protocol for Udp {
        fn v2_protocol() -> v2::Protocol {
            v2::Protocol::Datagram
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{Layer, service::service_fn};
    use rama_net::forwarded::{ForwardedElement, NodeId};
    use std::{convert::Infallible, net::SocketAddr, pin::Pin};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_test::io::{Builder, Mock};

    struct SocketConnection {
        conn: Mock,
        socket: SocketAddr,
    }

    impl Socket for SocketConnection {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.socket)
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.socket)
        }
    }

    impl AsyncWrite for SocketConnection {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.conn).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.conn).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.conn).poll_shutdown(cx)
        }
    }

    impl AsyncRead for SocketConnection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.conn).poll_read(cx, buf)
        }
    }

    #[tokio::test]
    async fn test_v1_tcp() {
        for (expected_line, input_ctx, target_addr) in [
            (
                "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n",
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ctx
                },
                "192.168.1.101:443",
            ),
            (
                "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n",
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                            .parse()
                            .unwrap(),
                    ));
                    ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                        NodeId::try_from("127.0.1.2:80").unwrap(),
                    )));
                    ctx
                },
                "192.168.1.101:443",
            ),
            (
                "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n",
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                            .parse()
                            .unwrap(),
                    ));
                    ctx
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
            (
                "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n",
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                        NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443").unwrap(),
                    )));
                    ctx
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
        ] {
            let svc = HaProxyLayer::tcp()
                .v1()
                .layer(service_fn(async move |ctx, req| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: SocketConnection {
                            socket: target_addr.parse().unwrap(),
                            conn: Builder::new().write(expected_line.as_bytes()).build(),
                        },
                    })
                }));
            svc.serve(input_ctx, ()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v1_tcp_ip_version_mismatch() {
        for (input_ctx, target_addr) in [
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ctx
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                        NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                    )));
                    ctx
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ctx
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                        NodeId::try_from("127.0.1.2:80").unwrap(),
                    )));
                    ctx
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
        ] {
            let svc = HaProxyLayer::tcp()
                .v1()
                .layer(service_fn(async move |ctx, req| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: SocketConnection {
                            socket: target_addr.parse().unwrap(),
                            conn: Builder::new().build(),
                        },
                    })
                }));
            assert!(svc.serve(input_ctx, ()).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_v1_tcp_missing_src() {
        for (input_ctx, target_addr) in [
            (Context::default(), "192.168.1.101:443"),
            (
                Context::default(),
                "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443",
            ),
        ] {
            let svc = HaProxyLayer::tcp()
                .v1()
                .layer(service_fn(async move |ctx, req| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: SocketConnection {
                            socket: target_addr.parse().unwrap(),
                            conn: Builder::new().build(),
                        },
                    })
                }));
            assert!(svc.serve(input_ctx, ()).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_v2_tcp4() {
        for input_ctx in [
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ctx
            },
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                        .parse()
                        .unwrap(),
                ));
                ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                    NodeId::try_from("127.0.0.1:80").unwrap(),
                )));
                ctx
            },
        ] {
            let svc = HaProxyLayer::tcp().with_payload(vec![42]).layer(service_fn(
                async move |ctx, req| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: SocketConnection {
                            socket: "192.168.1.1:443".parse().unwrap(),
                            conn: Builder::new()
                                .write(&[
                                    b'\r', b'\n', b'\r', b'\n', b'\0', b'\r', b'\n', b'Q', b'U',
                                    b'I', b'T', b'\n', 0x21, 0x11, 0, 13, 127, 0, 0, 1, 192, 168,
                                    1, 1, 0, 80, 1, 187, 42,
                                ])
                                .build(),
                        },
                    })
                },
            ));
            svc.serve(input_ctx, ()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_udp4() {
        for input_ctx in [
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ctx
            },
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                        .parse()
                        .unwrap(),
                ));
                ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                    NodeId::try_from("127.0.0.1:80").unwrap(),
                )));
                ctx
            },
        ] {
            let svc = HaProxyLayer::udp().with_payload(vec![42]).layer(service_fn(
                async move |ctx, req| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: SocketConnection {
                            socket: "192.168.1.1:443".parse().unwrap(),
                            conn: Builder::new()
                                .write(&[
                                    b'\r', b'\n', b'\r', b'\n', b'\0', b'\r', b'\n', b'Q', b'U',
                                    b'I', b'T', b'\n', 0x21, 0x12, 0, 13, 127, 0, 0, 1, 192, 168,
                                    1, 1, 0, 80, 1, 187, 42,
                                ])
                                .build(),
                        },
                    })
                },
            ));
            svc.serve(input_ctx, ()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_tcp6() {
        for input_ctx in [
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                        .parse()
                        .unwrap(),
                ));
                ctx
            },
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                    NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                )));
                ctx
            },
        ] {
            let svc = HaProxyLayer::tcp().with_payload(vec![42]).layer(service_fn(
                async move |ctx, req| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: SocketConnection {
                            socket: "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:443"
                                .parse()
                                .unwrap(),
                            conn: Builder::new()
                                .write(&[
                                    b'\r', b'\n', b'\r', b'\n', b'\0', b'\r', b'\n', b'Q', b'U',
                                    b'I', b'T', b'\n', 0x21, 0x21, 0, 37, 0x12, 0x34, 0x56, 0x78,
                                    0x90, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65,
                                    0x43, 0x21, 0x43, 0x21, 0x87, 0x65, 0xba, 0x09, 0xfe, 0xdc,
                                    0xcd, 0xef, 0x90, 0xab, 0x56, 0x78, 0x12, 0x34, 0, 80, 1, 187,
                                    42,
                                ])
                                .build(),
                        },
                    })
                },
            ));
            svc.serve(input_ctx, ()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_udp6() {
        for input_ctx in [
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                        .parse()
                        .unwrap(),
                ));
                ctx
            },
            {
                let mut ctx = Context::default();
                ctx.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                    NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                )));
                ctx
            },
        ] {
            let svc = HaProxyLayer::udp().with_payload(vec![42]).layer(service_fn(
                async move |ctx, req| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: SocketConnection {
                            socket: "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:443"
                                .parse()
                                .unwrap(),
                            conn: Builder::new()
                                .write(&[
                                    b'\r', b'\n', b'\r', b'\n', b'\0', b'\r', b'\n', b'Q', b'U',
                                    b'I', b'T', b'\n', 0x21, 0x22, 0, 37, 0x12, 0x34, 0x56, 0x78,
                                    0x90, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65,
                                    0x43, 0x21, 0x43, 0x21, 0x87, 0x65, 0xba, 0x09, 0xfe, 0xdc,
                                    0xcd, 0xef, 0x90, 0xab, 0x56, 0x78, 0x12, 0x34, 0, 80, 1, 187,
                                    42,
                                ])
                                .build(),
                        },
                    })
                },
            ));
            svc.serve(input_ctx, ()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_ip_version_mismatch() {
        for (input_ctx, target_addr) in [
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ctx
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                        NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                    )));
                    ctx
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ctx
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
            (
                {
                    let mut ctx = Context::default();
                    ctx.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ctx.insert(Forwarded::new(ForwardedElement::forwarded_for(
                        NodeId::try_from("127.0.1.2:80").unwrap(),
                    )));
                    ctx
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
        ] {
            // TCP

            let svc = HaProxyLayer::tcp().layer(service_fn(async move |ctx, req| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        conn: Builder::new().build(),
                    },
                })
            }));
            assert!(svc.serve(input_ctx.clone(), ()).await.is_err());

            // UDP

            let svc = HaProxyLayer::udp().layer(service_fn(async move |ctx, req| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        conn: Builder::new().build(),
                    },
                })
            }));
            assert!(svc.serve(input_ctx, ()).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_v2_missing_src() {
        for (input_ctx, target_addr) in [
            (Context::default(), "192.168.1.101:443"),
            (
                Context::default(),
                "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443",
            ),
        ] {
            // TCP

            let svc = HaProxyLayer::tcp().layer(service_fn(async move |ctx, req| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        conn: Builder::new().build(),
                    },
                })
            }));
            assert!(svc.serve(input_ctx.clone(), ()).await.is_err());

            // UDP

            let svc = HaProxyLayer::udp().layer(service_fn(async move |ctx, req| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        conn: Builder::new().build(),
                    },
                })
            }));
            assert!(svc.serve(input_ctx.clone(), ()).await.is_err());
        }
    }
}
