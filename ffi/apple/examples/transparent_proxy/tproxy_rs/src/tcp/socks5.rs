use std::time::Duration;

use rama::{
    Service, ServiceInput,
    error::{BoxError, ErrorContext as _},
    net::{
        address::HostWithPort,
        proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
        user::ProxyCredential,
    },
    proxy::socks5::proto,
    rt::Executor,
    stream::Stream,
    tcp::{
        TcpStream,
        client::{default_tcp_connect, service::DefaultForwarder},
    },
    telemetry::tracing,
};

use crate::utils::executor_from_input;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(super) struct Socks5IngressService;

impl Socks5IngressService {
    #[inline(always)]
    pub(super) fn new() -> Self {
        Self
    }
}

impl<S> Service<S> for Socks5IngressService
where
    S: Stream + Unpin + rama::extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, mut input: S) -> Result<Self::Output, Self::Error> {
        let Some(ProxyTarget(socks5_proxy_address)) = input.extensions().get().cloned() else {
            tracing::warn!(
                "failed to find socks5 proxy address in input... this is unexpected (rama NE bridge bug!?)"
            );
            return Err(BoxError::from(
                "missing socks5 proxy address (ProxyTarget ext)",
            ));
        };

        match proxy_socks5_handshake(&mut input, socks5_proxy_address).await? {
            Socks5HandshakeOutcome::UnsupportedFlow(egress_stream) => {
                let proxy_req = ProxyRequest {
                    source: input,
                    target: egress_stream,
                };
                if let Err(err) = StreamForwardService::default().serve(proxy_req).await {
                    tracing::debug!(
                        "failed to L4-relay TCP traffic (not compatible with SOCKS5 intercept flow): {err}"
                    );
                }
            }
            Socks5HandshakeOutcome::ContinueInspection(egress_stream) => {
                // TODO: continue inspection flow instead of relay...
                let proxy_req = ProxyRequest {
                    source: input,
                    target: egress_stream,
                };
                if let Err(err) = StreamForwardService::default().serve(proxy_req).await {
                    tracing::debug!(
                        "failed to L4-relay TCP traffic (not compatible with SOCKS5 intercept flow): {err}"
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) struct IngressProxyCredentials(pub(super) ProxyCredential);

#[derive(Debug)]
enum Socks5HandshakeOutcome<S> {
    /// Flow is not supported, skip traffic inspection and
    /// resort to proxying bytes...
    UnsupportedFlow(S),
    /// Socks5 handshake complete, continue to inspect.
    /// In case there were credentials negotiated in the flow,
    /// they will also have been inserted in the input flow via
    /// [`IngressProxyCredentials`] in its extensions.
    ContinueInspection(S),
}

async fn proxy_socks5_handshake<S>(
    ingress_stream: &mut S,
    socks5_proxy_address: HostWithPort,
) -> Result<Socks5HandshakeOutcome<impl Stream>, BoxError>
where
    S: Stream + Unpin + rama::extensions::ExtensionsMut,
{
    let client_header = proto::client::Header::read_from(ingress_stream)
        .await
        .context("read client header")?;

    let exec = executor_from_input(ingress_stream);
    // TOOD: make timeout configurable
    let tcp_conn_timeout = Duration::from_mins(2);

    let (mut egress_stream, _) = tokio::time::timeout(
        tcp_conn_timeout,
        default_tcp_connect(ingress_stream.extensions(), socks5_proxy_address, exec),
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
            let client_auth_req = proto::client::UsernamePasswordRequest::read_from(ingress_stream)
                .await
                .context(
                    "read client auth sub-negotiation request from ingress: username-password",
                )?;

            client_auth_req.write_to(&mut egress_stream).await.context(
                "write client auth-sub-negotation request to egress: received from egress stream",
            )?;

            let server_auth_reply =
                proto::server::UsernamePasswordResponse::read_from(&mut egress_stream)
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

            Ok(Socks5HandshakeOutcome::UnsupportedFlow(egress_stream))
        }
    }
}

async fn proxy_socks5_handshake_request_response<Ingress, Egress>(
    ingress_stream: &mut Ingress,
    negotiated_method: proto::SocksMethod,
    mut egress_stream: Egress,
) -> Result<Socks5HandshakeOutcome<Egress>, BoxError>
where
    Ingress: Stream + Unpin + rama::extensions::ExtensionsMut,
    Egress: Stream + Unpin + rama::extensions::ExtensionsMut,
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

            Ok(Socks5HandshakeOutcome::ContinueInspection(egress_stream))
        }
        cmd
        @ (proto::Command::Bind | proto::Command::UdpAssociate | proto::Command::Unknown(_)) => {
            tracing::debug!(
                "supported SOCKS5 method {cmd:?}: forward bytes as is without further inspection..."
            );

            Ok(Socks5HandshakeOutcome::UnsupportedFlow(egress_stream))
        }
    }
}
