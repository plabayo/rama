use std::time::Duration;

use rama_core::{
    error::{BoxError, ErrorContext as _},
    extensions,
    rt::Executor,
    stream::Stream,
    telemetry::tracing,
};
use rama_dns::client::{GlobalDnsResolver, resolver::DnsAddressResolver};
use rama_net::{
    address::HostWithPort,
    user::{ProxyCredential, credentials::DpiProxyCredential},
};
use rama_tcp::client::{TcpStreamConnector, tcp_connect};
use rama_utils::macros::generate_set_and_with;

use crate::proto;

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay a socks5 proxy connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct Socks5MitmRelay<Dns = GlobalDnsResolver, Connector = ()> {
    dns: Dns,
    tcp_connector: Connector,
    connect_timeout: Duration,
}

#[derive(Debug)]
/// Outcome of [`Socks5MitmRelay::handshake`].
pub enum Socks5MitmHandshakeOutcome<S> {
    /// Flow is not supported, skip traffic inspection and
    /// resort to proxying bytes...
    UnsupportedFlow(S),
    /// Socks5 handshake complete, continue to inspect.
    /// In case there were credentials negotiated in the flow,
    /// they will also have been inserted in the input flow via
    /// [`DpiProxyCredential`] in its extensions.
    ContinueInspection(S),
}

impl Socks5MitmRelay {
    #[inline(always)]
    /// Create a new [`Socks5MitmRelay`].
    pub fn new() -> Self {
        Self {
            dns: GlobalDnsResolver::new(),
            tcp_connector: (),
            connect_timeout: Duration::from_mins(2),
        }
    }
}

impl<Dns> Socks5MitmRelay<Dns> {
    #[inline(always)]
    /// Set the TCP connector to use
    pub fn tcp_connector<Connector>(self, connector: Connector) -> Socks5MitmRelay<Dns, Connector> {
        Socks5MitmRelay {
            dns: self.dns,
            tcp_connector: connector,
            connect_timeout: self.connect_timeout,
        }
    }
}

impl<Connector> Socks5MitmRelay<GlobalDnsResolver, Connector> {
    #[inline(always)]
    /// Set the Dns (address) resolver to use
    pub fn dns_resolver<Dns>(self, dns: Dns) -> Socks5MitmRelay<Dns, Connector> {
        Socks5MitmRelay {
            dns,
            tcp_connector: self.tcp_connector,
            connect_timeout: self.connect_timeout,
        }
    }
}

impl<Dns, Connector> Socks5MitmRelay<Dns, Connector> {
    generate_set_and_with! {
        /// Overwrite the connect timeout to be used for tcp (egress) tcp connections,
        /// to the actual intended socks5 servers.
        pub fn connect_timeout(mut self, timeout: Duration) -> Self {
            self.connect_timeout = if timeout.is_zero() {
                Duration::from_mins(2)
            } else {
                timeout
            };
            self
        }
    }
}

impl<Dns, Connector> Socks5MitmRelay<Dns, Connector>
where
    Dns: DnsAddressResolver + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    /// Establish and MITM an handshake between the client and server.
    pub async fn handshake<S>(
        &self,
        ingress_stream: &mut S,
        exec: Executor,
        socks5_proxy_address: HostWithPort,
    ) -> Result<Socks5MitmHandshakeOutcome<impl Stream>, BoxError>
    where
        S: Stream + Unpin + extensions::ExtensionsMut,
    {
        let client_header = proto::client::Header::read_from(ingress_stream)
            .await
            .context("read client header")?;

        let (mut egress_stream, _) = tokio::time::timeout(
            self.connect_timeout,
            tcp_connect(
                ingress_stream.extensions(),
                socks5_proxy_address,
                self.dns.clone(),
                self.tcp_connector.clone(),
                exec,
            ),
        )
        .await
        .context("tcp connection to egress socks5 proxy server timed out")?
        .context("tcp connection to egress socks5 proxy server failed")?;

        client_header
            .write_to(&mut egress_stream)
            .await
            .context("write client header: with ingress provided method")?;

        let server_header = proto::server::Header::read_from(ingress_stream)
            .await
            .context("read egress socks5 proxy server header")?;

        server_header
            .write_to(ingress_stream)
            .await
            .context("write server header: received from egress stream")?;

        match server_header.method {
            proto::SocksMethod::NoAuthenticationRequired => {
                proxy_socks5_handshake_request_response(
                    ingress_stream,
                    server_header.method,
                    egress_stream,
                )
                .await
            }
            proto::SocksMethod::UsernamePassword => {
                let client_auth_req = proto::client::UsernamePasswordRequest::read_from(
                    ingress_stream,
                )
                .await
                .context(
                    "read client auth sub-negotiation request from ingress: username-password",
                )?;

                client_auth_req.write_to(&mut egress_stream).await.context(
                    "write client auth-sub-negotation request to egress: received from egress stream",
                )?;

                let server_auth_reply = proto::server::UsernamePasswordResponse::read_from(
                    &mut egress_stream,
                )
                .await
                .context(
                    "read server sub-negotiation response from egress: username-password auth",
                )?;

                server_auth_reply.write_to(ingress_stream).await.context(
                    "write server auth-sub-negotation response to ingress: received from egress stream",
                )?;

                if !server_auth_reply.success() {
                    // continue regular flow even if not succesfull as it is up to the
                    // conversing pair to decide when to stop, not the proxy... if client
                    // and server continue regardless of socks5 semantics, we should support that
                    tracing::debug!(
                        "server auth flow did not succeed: attempt to continue socks5 proxy relay flow regardless..."
                    );
                }

                ingress_stream
                    .extensions_mut()
                    .insert(DpiProxyCredential(ProxyCredential::Basic(
                        client_auth_req.basic,
                    )));

                proxy_socks5_handshake_request_response(
                    ingress_stream,
                    server_header.method,
                    egress_stream,
                )
                .await
            }
            method @ (proto::SocksMethod::GSSAPI
            | proto::SocksMethod::ChallengeHandshakeAuthenticationProtocol
            | proto::SocksMethod::ChallengeResponseAuthenticationMethod
            | proto::SocksMethod::SecureSocksLayer
            | proto::SocksMethod::NDSAuthentication
            | proto::SocksMethod::MultiAuthenticationFramework
            | proto::SocksMethod::JSONParameterBlock
            | proto::SocksMethod::NoAcceptableMethods
            | proto::SocksMethod::Unknown(_)) => {
                tracing::debug!(
                    "supported SOCKS5 method {method:?}: forward bytes as is without further inspection..."
                );

                Ok(Socks5MitmHandshakeOutcome::UnsupportedFlow(egress_stream))
            }
        }
    }
}

async fn proxy_socks5_handshake_request_response<Ingress, Egress>(
    ingress_stream: &mut Ingress,
    negotiated_method: proto::SocksMethod,
    mut egress_stream: Egress,
) -> Result<Socks5MitmHandshakeOutcome<Egress>, BoxError>
where
    Ingress: Stream + Unpin + extensions::ExtensionsMut,
    Egress: Stream + Unpin + extensions::ExtensionsMut,
{
    let client_request = proto::client::Request::read_from(ingress_stream)
        .await
        .context("read client Socks5 request from ingress stream")?;

    tracing::trace!(
        "socks5 client request w/ destination {} and negotiated method {:?}: client request received cmd {:?} from ingress stream",
        client_request.destination,
        negotiated_method,
        client_request.command,
    );

    client_request
        .write_to(&mut egress_stream)
        .await
        .context("write client request: with ingress provided data")?;

    match client_request.command {
        proto::Command::Connect => {
            let server_reply = proto::server::Reply::read_from(&mut egress_stream)
                .await
                .context("read server socks5 reply from egress stream")?;

            server_reply
                .write_to(ingress_stream)
                .await
                .context("write server reply to ingress: received from egress stream")?;

            if server_reply.reply != proto::ReplyKind::Succeeded {
                // continue regular flow even if not succesfull as it is up to the
                // conversing pair to decide when to stop, not the proxy... if client
                // and server continue regardless of socks5 semantics, we should support that
                tracing::debug!(
                    "server req-resp flow did not succeed: attempt to continue socks5 proxy relay flow regardless..."
                );
            }

            tracing::trace!(
                bind_addr = %server_reply.bind_address,
                "socks5 proxy relay connector: handshake (socks5_client <-> proxy <-> socks5_server) complete",
            );

            Ok(Socks5MitmHandshakeOutcome::ContinueInspection(
                egress_stream,
            ))
        }
        cmd
        @ (proto::Command::Bind | proto::Command::UdpAssociate | proto::Command::Unknown(_)) => {
            // Note that except for the unknown cmd,
            // this unsupported flow for Bind and Udp-Associate is fine,
            // given both are anyway about new sidechannel flows, which can
            // be intercepted by the transparent proxy separately just fine without requiring
            // further support here.
            //
            // It is only for the Connect flow that we need to actually relay in-place as there's
            // no sidechannel for the data... the stream for the socks5 handshake is in that case
            // also the data channel...
            tracing::debug!(
                "unsupported SOCKS5 method {cmd:?}: forward bytes as is without further inspection..."
            );

            Ok(Socks5MitmHandshakeOutcome::UnsupportedFlow(egress_stream))
        }
    }
}
