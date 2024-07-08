use std::{marker::PhantomData, net::IpAddr};

use crate::{
    error::{BoxError, ErrorContext, OpaqueError},
    http::{client::EstablishedClientConnection, headers::Forwarded, Request},
    net::stream::{SocketInfo, Stream},
    proxy::pp::protocol::{v1, v2},
    service::{Context, Layer, Service},
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
    pub fn tcp() -> Self {
        HaProxyLayer {
            version: Default::default(),
            _phantom: PhantomData,
        }
    }

    /// Attach a custom bytes payload to the PROXY header.
    ///
    /// NOTE this is only possible in Version two of the PROXY Protocol.
    /// In case you downgrade this [`HaProxyLayer`] to version one later
    /// using [`Self::v1`] this payload will be dropped.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.version.payload = Some(payload);
        self
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
    pub fn udp() -> Self {
        HaProxyLayer {
            version: Default::default(),
            _phantom: PhantomData,
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
}

/// Service to encode and write the HaProxy Protocol
/// as a client on the connected stream.
///
/// This connector should in most cases
/// happen as the first thing after establishing the connection.
#[derive(Debug, Clone)]
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
        HaProxyService {
            inner,
            version: Default::default(),
            _phantom: PhantomData,
        }
    }

    /// Attach a custom bytes payload to the PROXY header.
    ///
    /// NOTE this is only possible in Version two of the PROXY Protocol.
    /// In case you downgrade this [`HaProxyLayer`] to version one later
    /// using [`Self::v1`] this payload will be dropped.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.version.payload = Some(payload);
        self
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
        HaProxyService {
            inner,
            version: Default::default(),
            _phantom: PhantomData,
        }
    }
}

impl<S, P, State, Body, T> Service<State, Request<Body>> for HaProxyService<S, P, version::One>
where
    S: Service<State, Request<Body>, Response = EstablishedClientConnection<T, Body, State>>,
    S::Error: Into<BoxError>,
    P: Send + 'static,
    State: Send + Sync + 'static,
    Body: Send + 'static,
    T: Stream + Unpin,
{
    type Response = EstablishedClientConnection<T, Body, State>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { ctx, req, mut conn } =
            self.inner.serve(ctx, req).await.map_err(Into::into)?;

        let dst = conn.addr();
        let src = ctx
            .get::<Forwarded>()
            .and_then(|f| f.client_socket_addr())
            .or_else(|| ctx.get::<SocketInfo>().map(|info| *info.peer_addr()))
            .ok_or_else(|| {
                OpaqueError::from_display("PROXY client (v1): missing src socket address")
            })?;

        let addresses = match (src.ip(), dst.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                v1::Addresses::new_tcp4(src_ip, dst_ip, src.port(), dst.port())
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                v1::Addresses::new_tcp6(src_ip, dst_ip, src.port(), dst.port())
            }
            (_, _) => {
                return Err(OpaqueError::from_display(
                    "PROXY client (v1): IP version mismatch between src and dest",
                )
                .into())
            }
        };

        conn.write_all(addresses.to_string().as_bytes())
            .await
            .context("PROXY client (v1): write addresses")?;

        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}

impl<S, P, State, Body, T> Service<State, Request<Body>> for HaProxyService<S, P, version::Two>
where
    S: Service<State, Request<Body>, Response = EstablishedClientConnection<T, Body, State>>,
    S::Error: Into<BoxError>,
    P: protocol::Protocol + Send + 'static,
    State: Send + Sync + 'static,
    Body: Send + 'static,
    T: Stream + Unpin,
{
    type Response = EstablishedClientConnection<T, Body, State>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { ctx, req, mut conn } =
            self.inner.serve(ctx, req).await.map_err(Into::into)?;

        let dst = conn.addr();
        let src = ctx
            .get::<Forwarded>()
            .and_then(|f| f.client_socket_addr())
            .or_else(|| ctx.get::<SocketInfo>().map(|info| *info.peer_addr()))
            .ok_or_else(|| {
                OpaqueError::from_display("PROXY client (v2): missing src socket address")
            })?;

        let builder = match (src.ip(), dst.ip()) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => v2::Builder::with_addresses(
                v2::Version::Two | v2::Command::Proxy,
                P::v2_protocol(),
                v2::IPv4::new(src_ip, dst_ip, src.port(), dst.port()),
            ),
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => v2::Builder::with_addresses(
                v2::Version::Two | v2::Command::Proxy,
                P::v2_protocol(),
                v2::IPv6::new(src_ip, dst_ip, src.port(), dst.port()),
            ),
            (_, _) => {
                return Err(OpaqueError::from_display(
                    "PROXY client (v2): IP version mismatch between src and dest",
                )
                .into())
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

    #[derive(Debug, Clone, Default)]
    /// Use version 1 of the PROXY protocol.
    ///
    /// See [`crate::proxy::pp::protocol`] for more information.
    #[non_exhaustive]
    pub struct One;

    #[derive(Debug, Clone, Default)]
    /// Use version 2 of the PROXY protocol.
    ///
    /// See [`crate::proxy::pp::protocol`] for more information.
    pub struct Two {
        pub(crate) payload: Option<Vec<u8>>,
    }
}

pub mod protocol {
    //! Marker traits for the HaProxy (PROXY) protocol to be used by client layer (service).

    use crate::proxy::pp::protocol::v2;

    #[derive(Debug, Clone)]
    /// Encode the data for the TCP protocol (possible in [`super::version::One`] and [`super::version::Two`]).
    ///
    /// See [`crate::proxy::pp::protocol`] for more information.
    pub struct Tcp;

    #[derive(Debug, Clone)]
    /// Encode the data for the UDP protocol (possible only in [`super::version::Two`]).
    ///
    /// See [`crate::proxy::pp::protocol`] for more information.
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
