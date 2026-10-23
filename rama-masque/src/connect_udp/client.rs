use std::{fmt, net::IpAddr};

use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsRef as _,
    rt::Executor,
};
use rama_http::{
    Request, Response, Version, conn::TargetHttpVersion, datagram::HttpDatagramSession,
    io::upgrade::handle_upgrade, proto::ext::HttpDatagrams,
};
use rama_net::address::{Host, ProxyAddress, SocketAddress};
use rama_utils::macros::generate_set_and_with;

use super::{
    ConnectUdpSocket, ConnectUdpSocketConfig, ConnectUdpTarget, connect_udp_request,
    session_config, validate_connect_udp_response,
};

/// Opens CONNECT-UDP tunnels ([RFC 9298]) through a MASQUE proxy with any rama HTTP client.
///
/// The client must reach the proxy on the requested HTTP version and pass upgrades on:
/// HTTP/1.1 `101` responses and Extended CONNECT streams on HTTP/2 and HTTP/3.
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
pub struct ConnectUdpConnector<S> {
    client: S,
    exec: Executor,
    socket: ConnectUdpSocketConfig,
}

impl<S: fmt::Debug> fmt::Debug for ConnectUdpConnector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpConnector")
            .field("client", &self.client)
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl<S: Clone> Clone for ConnectUdpConnector<S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            exec: self.exec.clone(),
            socket: self.socket,
        }
    }
}

impl<S> ConnectUdpConnector<S> {
    /// Open tunnels with `client`; `exec` runs each tunnel's send task.
    pub fn new(client: S, exec: Executor) -> Self {
        Self {
            client,
            exec,
            socket: ConnectUdpSocketConfig::default(),
        }
    }

    generate_set_and_with! {
        /// Limits of each tunnel, including its idle timeout.
        pub fn socket_config(mut self, config: ConnectUdpSocketConfig) -> Self {
            self.socket = config;
            self
        }
    }
}

impl<S> ConnectUdpConnector<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    /// Open a tunnel to `target` through `proxy` over `version`.
    ///
    /// The socket's peer is the target when it is an IP literal, otherwise the unspecified
    /// address with the target port: the proxy resolves names, so the client never learns
    /// the address. Its local address is unspecified.
    pub async fn connect(
        &self,
        proxy: &ProxyAddress,
        target: ConnectUdpTarget,
        version: Version,
    ) -> Result<ConnectUdpSocket, BoxError> {
        let request = connect_udp_request(proxy, &target, version)?;
        // The token defines datagram semantics (RFC 9297 §2): declare them for this request.
        request.extensions().insert(HttpDatagrams);
        request.extensions().insert(TargetHttpVersion(version));
        let response = self
            .client
            .serve(request)
            .await
            .map_err(Into::into)
            .context("connect-udp request")?;
        if let Err(error) = validate_connect_udp_response(version, &response) {
            return Err(error
                .context_field("status", response.status())
                .context("connect-udp tunnel refused"));
        }
        let upgraded = handle_upgrade(&response)
            .await
            .context("connect-udp upgrade")?;
        let ip = match target.host {
            Host::Address(ip) => ip,
            _ => IpAddr::from([0, 0, 0, 0]),
        };
        let peer = SocketAddress::new(ip, target.port.get());
        Ok(ConnectUdpSocket::new(
            &self.exec,
            HttpDatagramSession::with_config(upgraded, session_config()),
            SocketAddress::default_ipv4(0),
            peer,
            self.socket,
        ))
    }
}
