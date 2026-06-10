use std::{fmt, marker::PhantomData, net::IpAddr};

use crate::protocol::{v1, v2};
use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    extensions::ExtensionsRef,
    io::Io,
};
use rama_net::{
    client::{ConnectorService, EstablishedClientConnection},
    forwarded::Forwarded,
    stream::{Socket, SocketInfo},
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
        /// Attach a raw bytes payload to the PROXY v2 header, written
        /// verbatim after the address block.
        ///
        /// **Wire-format hazard.** Spec section 2.2 says everything after the
        /// address block is a sequence of TLVs. If your bytes are not valid
        /// TLV encoding, conforming receivers (including rama's server) will
        /// either reject the connection or mis-parse the data. Prefer
        /// [`Self::tlv`] for anything spec-compliant; treat `payload` as a
        /// raw escape hatch for testing.
        ///
        /// In particular, **combining `payload` with [`Self::crc32c`] is
        /// rejected at send time**: the CRC32C TLV would be appended after
        /// the raw payload, which means the receiver would try to interpret
        /// the payload as TLVs, fail, and the CRC would be computed over a
        /// header the receiver can't validate. Use TLVs instead.
        ///
        /// NOTE this is only possible in Version two of the PROXY Protocol.
        /// In case you downgrade this [`HaProxyLayer`] to version one later
        /// using [`Self::v1`] this payload will be dropped.
        pub fn payload(mut self, payload: impl Into<Bytes>) -> Self {
            self.version.payload = Some(payload.into());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Attach a Type-Length-Value entry to the emitted v2 header.
        ///
        /// Call this once per TLV; entries are written in insertion order.
        /// Queuing a [`v2::Type::CRC32C`] entry here is rejected at send
        /// time — a CRC value must be computed over the final header bytes,
        /// so use [`Self::crc32c`] instead.
        ///
        /// NOTE this is only possible in Version two of the PROXY Protocol.
        /// On downgrade to v1 via [`Self::v1`] all TLVs are dropped.
        pub fn tlv(mut self, kind: v2::Type, value: impl Into<Bytes>) -> Self {
            self.version.tlvs.push((kind, value.into()));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Toggle automatic emission of a valid `PP2_TYPE_CRC32C` TLV.
        ///
        /// When enabled, the CRC is computed over the final header (with the
        /// CRC field zeroed during computation, per spec section 2.2.5) and
        /// appended as the last TLV. Receivers that enforce CRC verification
        /// (rama's server default) will accept the header.
        ///
        /// Incompatible with [`Self::payload`]: setting both is rejected at
        /// send time because the raw payload would sit between the TLVs and
        /// the CRC32C TLV, which standards-conforming receivers cannot parse.
        ///
        /// NOTE this is only possible in Version two of the PROXY Protocol.
        pub fn crc32c(mut self, enabled: bool) -> Self {
            self.version.crc32c = enabled;
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

    rama_utils::macros::generate_set_and_with! {
        /// Attach a Type-Length-Value entry to the emitted v2 header.
        /// See [`HaProxyLayer::with_tlv`] for details.
        pub fn tlv(mut self, kind: v2::Type, value: impl Into<Bytes>) -> Self {
            self.version.tlvs.push((kind, value.into()));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Toggle automatic emission of a valid `PP2_TYPE_CRC32C` TLV.
        /// See [`HaProxyLayer::crc32c`] for details.
        pub fn crc32c(mut self, enabled: bool) -> Self {
            self.version.crc32c = enabled;
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

impl<S, P, Input> Service<Input> for HaProxyService<S, P, version::One>
where
    S: ConnectorService<Input, Connection: Io + Socket + Unpin>,
    P: Send + 'static,
    Input: Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, mut conn } =
            self.inner.connect(input).await.into_box_error()?;

        let src = input
            .extensions()
            .clone_to_if_absent::<Forwarded>(conn.extensions())
            .and_then(|f| f.client_socket_addr())
            .or_else(|| {
                input
                    .extensions()
                    .clone_to_if_absent::<SocketInfo>(conn.extensions())
                    .map(|info| info.peer_addr())
            })
            .ok_or_else(|| {
                OpaqueError::from_static_str("PROXY client (v1): missing src socket address")
            })?;

        let peer_addr = conn.peer_addr()?;
        let addresses = match (src.ip_addr, peer_addr.ip_addr) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                v1::Addresses::new_tcp4(src_ip, dst_ip, src.port, peer_addr.port)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                v1::Addresses::new_tcp6(src_ip, dst_ip, src.port, peer_addr.port)
            }
            (_, _) => {
                return Err(OpaqueError::from_static_str(
                    "PROXY client (v1): IP version mismatch between src and dest",
                )
                .into_box_error());
            }
        };

        conn.write_all(addresses.to_string().as_bytes())
            .await
            .context("PROXY client (v1): write addresses")?;

        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, P, Input> Service<Input> for HaProxyService<S, P, version::Two>
where
    S: ConnectorService<Input, Connection: Io + Socket + Unpin>,
    P: protocol::Protocol + Send + 'static,
    Input: Send + ExtensionsRef + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, mut conn } =
            self.inner.connect(input).await.into_box_error()?;

        let src = {
            input
                .extensions()
                .clone_to_if_absent::<Forwarded>(conn.extensions())
                .and_then(|f| f.client_socket_addr())
                .or_else(|| {
                    input
                        .extensions()
                        .clone_to_if_absent::<SocketInfo>(conn.extensions())
                        .map(|info| info.peer_addr())
                })
                .ok_or_else(|| {
                    OpaqueError::from_static_str("PROXY client (v2): missing src socket address")
                })?
        };

        let peer_addr = conn.peer_addr()?;
        let builder = match (src.ip_addr, peer_addr.ip_addr) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => v2::Builder::with_addresses(
                v2::Version::Two | v2::Command::Proxy,
                P::v2_protocol(),
                v2::IPv4::new(src_ip, dst_ip, src.port, peer_addr.port),
            ),
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => v2::Builder::with_addresses(
                v2::Version::Two | v2::Command::Proxy,
                P::v2_protocol(),
                v2::IPv6::new(src_ip, dst_ip, src.port, peer_addr.port),
            ),
            (_, _) => {
                return Err(OpaqueError::from_static_str(
                    "PROXY client (v2): IP version mismatch between src and dest",
                )
                .into_box_error());
            }
        };

        if self.version.crc32c && self.version.payload.is_some() {
            // The raw `payload` bytes sit between the TLVs and the CRC32C TLV
            // — receivers parse the entire post-address area as TLVs, so the
            // payload would be mis-interpreted (or rejected) and the CRC
            // would be computed over a header the peer can't validate.
            return Err(OpaqueError::from_static_str(
                "PROXY client (v2): `payload` and `crc32c` cannot be combined; \
                 use typed TLVs instead",
            )
            .into_box_error());
        }

        // A CRC32C TLV value is never something a sender should compute by
        // hand: it has to be computed over the *final* header bytes, which
        // only the builder can see. If the user manually queued one via
        // `with_tlv(Type::CRC32C, ...)`, reject — `crc32c(true)` is the
        // only correct way to emit a CRC32C TLV.
        if self
            .version
            .tlvs
            .iter()
            .any(|(kind, _)| *kind == v2::Type::CRC32C)
        {
            return Err(OpaqueError::from_static_str(
                "PROXY client (v2): manual `with_tlv(Type::CRC32C, ...)` is not supported; \
                 use `with_crc32c(true)` instead",
            )
            .into_box_error());
        }

        let mut builder = builder;
        for (kind, value) in &self.version.tlvs {
            builder = builder
                .write_tlv(*kind, value.as_ref())
                .context("PROXY client (v2): write TLV")?;
        }
        if let Some(payload) = self.version.payload.as_deref() {
            builder = builder
                .write_payload(payload)
                .context("PROXY client (v2): write custom binary payload to header")?;
        }
        if self.version.crc32c {
            // Spec section 2.2.5: build() will append the CRC32C TLV last
            // (covering every other TLV) and patch in the computed value.
            builder = builder.with_crc32c(true);
        }

        let header = builder
            .build()
            .context("PROXY client (v2): encode header")?;
        conn.write_all(&header[..])
            .await
            .context("PROXY client (v2): write header")?;

        Ok(EstablishedClientConnection { input, conn })
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
        pub(crate) tlvs: Vec<(crate::protocol::v2::Type, Bytes)>,
        pub(crate) crc32c: bool,
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
    use rama_core::{
        Layer, ServiceInput, extensions::Extensions, extensions::ExtensionsRef, service::service_fn,
    };
    use rama_net::{
        address::SocketAddress,
        forwarded::{ForwardedElement, NodeId},
    };
    use std::{convert::Infallible, pin::Pin};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_test::io::{Builder, Mock};

    struct SocketConnection {
        conn: Mock,
        extensions: Extensions,
        socket: SocketAddress,
    }

    impl ExtensionsRef for SocketConnection {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl Socket for SocketConnection {
        fn local_addr(&self) -> std::io::Result<SocketAddress> {
            Ok(self.socket)
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddress> {
            Ok(self.socket)
        }
    }

    #[warn(clippy::missing_trait_methods)]
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

        fn is_write_vectored(&self) -> bool {
            self.conn.is_write_vectored()
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.conn).poll_write_vectored(cx, bufs)
        }
    }

    #[warn(clippy::missing_trait_methods)]
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
        for (expected_line, ext, target_addr) in [
            (
                "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n",
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ext
                },
                "192.168.1.101:443",
            ),
            (
                "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n",
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                            .parse()
                            .unwrap(),
                    ));
                    ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                        NodeId::try_from("127.0.1.2:80").unwrap(),
                    )));
                    ext
                },
                "192.168.1.101:443",
            ),
            (
                "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n",
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                            .parse()
                            .unwrap(),
                    ));
                    ext
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
            (
                "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n",
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                        NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443").unwrap(),
                    )));
                    ext
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
        ] {
            let svc =
                HaProxyLayer::tcp()
                    .v1()
                    .layer(service_fn(async move |input: ServiceInput<()>| {
                        Ok::<_, Infallible>(EstablishedClientConnection {
                            input,
                            conn: SocketConnection {
                                socket: target_addr.parse().unwrap(),
                                conn: Builder::new().write(expected_line.as_bytes()).build(),
                                extensions: Extensions::new(),
                            },
                        })
                    }));

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            svc.serve(input).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v1_tcp_ip_version_mismatch() {
        for (ext, target_addr) in [
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ext
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                        NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                    )));
                    ext
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ext
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                        NodeId::try_from("127.0.1.2:80").unwrap(),
                    )));
                    ext
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
        ] {
            let svc =
                HaProxyLayer::tcp()
                    .v1()
                    .layer(service_fn(async move |input: ServiceInput<()>| {
                        Ok::<_, Infallible>(EstablishedClientConnection {
                            input,
                            conn: SocketConnection {
                                socket: target_addr.parse().unwrap(),
                                conn: Builder::new().build(),
                                extensions: Extensions::new(),
                            },
                        })
                    }));

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            assert!(svc.serve(input).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_v1_tcp_missing_src() {
        for target_addr in [
            "192.168.1.101:443",
            "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443",
        ] {
            let svc = HaProxyLayer::tcp()
                .v1()
                .layer(service_fn(async move |input| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: SocketConnection {
                            socket: target_addr.parse().unwrap(),
                            conn: Builder::new().build(),
                            extensions: Extensions::new(),
                        },
                    })
                }));
            assert!(svc.serve(ServiceInput::new(())).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_v2_tcp4() {
        for ext in [
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ext
            },
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                        .parse()
                        .unwrap(),
                ));
                ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                    NodeId::try_from("127.0.0.1:80").unwrap(),
                )));
                ext
            },
        ] {
            let svc = HaProxyLayer::tcp().with_payload(vec![42]).layer(service_fn(
                async move |input: ServiceInput<()>| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: SocketConnection {
                            socket: "192.168.1.1:443".parse().unwrap(),
                            extensions: Extensions::new(),
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

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            svc.serve(input).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_udp4() {
        for ext in [
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ext
            },
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443"
                        .parse()
                        .unwrap(),
                ));
                ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                    NodeId::try_from("127.0.0.1:80").unwrap(),
                )));
                ext
            },
        ] {
            let svc = HaProxyLayer::udp().with_payload(vec![42]).layer(service_fn(
                async move |input: ServiceInput<()>| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: SocketConnection {
                            socket: "192.168.1.1:443".parse().unwrap(),
                            extensions: Extensions::new(),
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

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            svc.serve(input).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_tcp6() {
        for ext in [
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                        .parse()
                        .unwrap(),
                ));
                ext
            },
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                    NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                )));
                ext
            },
        ] {
            let svc = HaProxyLayer::tcp().with_payload(vec![42]).layer(service_fn(
                async move |input: ServiceInput<()>| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: SocketConnection {
                            socket: "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:443"
                                .parse()
                                .unwrap(),
                            extensions: Extensions::new(),
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

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            svc.serve(input).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_udp6() {
        for ext in [
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(
                    None,
                    "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                        .parse()
                        .unwrap(),
                ));
                ext
            },
            {
                let ext = Extensions::new();
                ext.insert(SocketInfo::new(None, "127.0.0.1:80".parse().unwrap()));
                ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                    NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                )));
                ext
            },
        ] {
            let svc = HaProxyLayer::udp().with_payload(vec![42]).layer(service_fn(
                async move |input: ServiceInput<()>| {
                    Ok::<_, Infallible>(EstablishedClientConnection {
                        input,
                        conn: SocketConnection {
                            socket: "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:443"
                                .parse()
                                .unwrap(),
                            extensions: Extensions::new(),
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

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            svc.serve(input).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_ip_version_mismatch() {
        for (ext, target_addr) in [
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ext
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                        NodeId::try_from("[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80").unwrap(),
                    )));
                    ext
                },
                "192.168.1.101:443",
            ),
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(None, "127.0.1.2:80".parse().unwrap()));
                    ext
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
            (
                {
                    let ext = Extensions::new();
                    ext.insert(SocketInfo::new(
                        None,
                        "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:80"
                            .parse()
                            .unwrap(),
                    ));
                    ext.insert(Forwarded::new(ForwardedElement::new_forwarded_for(
                        NodeId::try_from("127.0.1.2:80").unwrap(),
                    )));
                    ext
                },
                "[4321:8765:ba09:fedc:cdef:90ab:5678:1234]:65535",
            ),
        ] {
            // TCP

            let svc = HaProxyLayer::tcp().layer(service_fn(async move |input: ServiceInput<()>| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        extensions: Extensions::new(),
                        conn: Builder::new().build(),
                    },
                })
            }));

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            assert!(svc.serve(input).await.is_err());

            // UDP

            let svc = HaProxyLayer::udp().layer(service_fn(async move |input: ServiceInput<()>| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        extensions: Extensions::new(),
                        conn: Builder::new().build(),
                    },
                })
            }));

            let input = ServiceInput::new(());
            input.extensions().extend(&ext);
            assert!(svc.serve(input).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_v2_missing_src() {
        for target_addr in [
            "192.168.1.101:443",
            "[1234:5678:90ab:cdef:fedc:ba09:8765:4321]:443",
        ] {
            // TCP

            let svc = HaProxyLayer::tcp().layer(service_fn(async move |input| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        extensions: Extensions::new(),
                        conn: Builder::new().build(),
                    },
                })
            }));
            assert!(svc.serve(ServiceInput::new(())).await.is_err());

            // UDP

            let svc = HaProxyLayer::udp().layer(service_fn(async move |input| {
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: SocketConnection {
                        socket: target_addr.parse().unwrap(),
                        extensions: Extensions::new(),
                        conn: Builder::new().build(),
                    },
                })
            }));
            assert!(svc.serve(ServiceInput::new(())).await.is_err());
        }
    }
}
