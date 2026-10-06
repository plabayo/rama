//! Serving HTTP/3 next to the TCP listener of a serve command.

use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    http::{
        core::h3::connection::Config,
        headers::{AltSvc, AlternativeService},
    },
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{
        Connection, Endpoint, ServerConfig, TransportConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::server::TlsServerConfig,
};

use clap::Args;
use std::sync::Arc;

use super::http::HttpVersions;

#[derive(Debug, Clone, Args)]
pub struct Http3Args {
    #[arg(long)]
    /// the UDP address to serve HTTP/3 on
    ///
    /// Defaults to the address of the TCP listener, or `--bind` without one.
    /// HTTP/3 is served when TLS is enabled and `--http-version` includes it.
    /// When only `auto` implies HTTP/3, failing to bind it leaves h1 and h2
    /// serving alone; this flag or `h3` in `--http-version` makes it an error.
    pub h3_bind: Option<SocketAddress>,
}

/// What a serve command listens on: TCP for HTTP/1.1 and h2, QUIC for HTTP/3.
#[derive(Debug)]
pub struct HttpListeners {
    pub tcp: Option<TcpListener>,
    pub http3: Option<Endpoint>,
}

impl HttpListeners {
    /// Bind the listeners `versions` asks for, given the TLS configuration if any.
    pub async fn bind(
        exec: Executor,
        bind: SocketAddress,
        versions: HttpVersions,
        tls: Option<&TlsServerConfig>,
        http3: &Http3Args,
    ) -> Result<Self, BoxError> {
        let serve_http3 = versions.http3(tls.is_some())?;
        if http3.h3_bind.is_some() && !serve_http3 {
            return Err(BoxError::from_static_str(
                "--h3-bind requires HTTP/3: enable TLS and serve h3 (see --http-version)",
            ));
        }
        let tcp = match versions.tcp() {
            Some(_) => Some(
                TcpListener::build(exec)
                    .bind_address(bind)
                    .await
                    .context("bind TCP listener")?,
            ),
            None => None,
        };
        let http3 = match tls.filter(|_| serve_http3) {
            Some(tls) => {
                let addr = match (http3.h3_bind, &tcp) {
                    (Some(addr), _) => addr,
                    (None, Some(tcp)) => tcp.local_addr().context("TCP listener address")?.into(),
                    (None, None) => bind,
                };
                match bind_http3(addr, tls).await {
                    Ok(endpoint) => Some(endpoint),
                    // HTTP/3 that `auto` only implied must not take h1 and h2 down with it.
                    Err(error)
                        if tcp.is_some()
                            && !versions.http3_explicit()
                            && http3.h3_bind.is_none() =>
                    {
                        tracing::error!(
                            %error,
                            network.local.address = %addr.ip_addr,
                            network.local.port = addr.port,
                            "HTTP/3 unavailable: serving HTTP/1.1 and h2 only",
                        );
                        None
                    }
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };
        Ok(Self { tcp, http3 })
    }

    /// The `Alt-Svc` value advertising the HTTP/3 endpoint, when serving one.
    pub fn alt_svc(&self) -> Result<Option<AltSvc>, BoxError> {
        self.http3
            .as_ref()
            .map(|endpoint| {
                let port = endpoint
                    .local_addr()
                    .context("QUIC endpoint address")?
                    .port();
                alt_svc(port)
            })
            .transpose()
    }
}

/// Bind QUIC on `addr` for HTTP/3, presenting the identity of `tls` and offering only `h3`.
///
/// Certificates issued per ClientHello are supported, sharing the issuer cache with `tls`;
/// a client asking for one the cache lacks first proves its address with a Retry.
/// The endpoint stays outside graceful shutdown, so HTTP/3 can drain its connections first;
/// serve it with [`serve_http3`].
pub async fn bind_http3(addr: SocketAddress, tls: &TlsServerConfig) -> Result<Endpoint, BoxError> {
    let tls = tls
        .clone()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut transport = TransportConfig::default();
    Config::default()
        .configure_transport(&mut transport)
        .context("HTTP/3 transport limits")?;
    let mut config = ServerConfig::try_from_rama_tls_with_provider(
        &tls,
        TlsOptions::default(),
        &BoringTlsProvider,
    )
    .context("QUIC TLS server config")?;
    config.set_transport_config(Arc::new(transport));
    Endpoint::build(Executor::new())
        .with_server_config(config)
        .bind_address(addr)
        .await
        .context("bind QUIC endpoint for HTTP/3")
}

/// Serve the HTTP/3 connections of `endpoint` with `service` on the graceful `exec`.
pub fn serve_http3<S>(exec: &Executor, name: &str, endpoint: Endpoint, service: S)
where
    S: Service<Connection> + Clone,
{
    match endpoint.local_addr() {
        Ok(addr) => tracing::info!(
            network.local.address = %addr.ip(),
            network.local.port = %addr.port(),
            "{name} HTTP/3 service ready: bind interface = {addr}",
        ),
        Err(error) => tracing::warn!(%error, "{name} HTTP/3 service ready: unknown address"),
    }
    exec.spawn_task(endpoint.serve(exec.clone(), service));
}

/// The `Alt-Svc` value advertising HTTP/3 on `port` of the origin host (RFC 9114 §3.1.1).
pub fn alt_svc(port: u16) -> Result<AltSvc, BoxError> {
    Ok(AltSvc::new(AlternativeService::new(
        ApplicationProtocol::HTTP_3,
        port,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::tls::server::{GeneratedServerAuthConfig, ServerAuthData};

    fn tls() -> TlsServerConfig {
        TlsServerConfig::new().with_server_auth(
            ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap(),
        )
    }

    fn localhost() -> SocketAddress {
        SocketAddress::local_ipv4(0)
    }

    #[tokio::test]
    async fn http3_shares_the_port_of_the_tcp_listener_by_default() {
        let listeners = HttpListeners::bind(
            Executor::new(),
            localhost(),
            HttpVersions::AUTO,
            Some(&tls()),
            &Http3Args { h3_bind: None },
        )
        .await
        .unwrap();
        let tcp = listeners.tcp.as_ref().unwrap().local_addr().unwrap();
        let quic = listeners.http3.as_ref().unwrap().local_addr().unwrap();
        assert_eq!(tcp, quic);
        assert_eq!(
            listeners.alt_svc().unwrap(),
            Some(alt_svc(quic.port()).unwrap())
        );
    }

    #[tokio::test]
    async fn no_http3_without_tls_or_when_left_out() {
        for (versions, tls) in [
            (HttpVersions::AUTO, None),
            ("h1,h2".parse().unwrap(), Some(tls())),
        ] {
            let listeners = HttpListeners::bind(
                Executor::new(),
                localhost(),
                versions,
                tls.as_ref(),
                &Http3Args { h3_bind: None },
            )
            .await
            .unwrap();
            assert!(listeners.tcp.is_some());
            assert!(listeners.http3.is_none());
            assert_eq!(listeners.alt_svc().unwrap(), None);
        }
    }

    #[tokio::test]
    async fn h3_bind_requires_http3() {
        let error = HttpListeners::bind(
            Executor::new(),
            localhost(),
            "h1,h2".parse().unwrap(),
            Some(&tls()),
            &Http3Args {
                h3_bind: Some(localhost()),
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("--h3-bind"), "{error}");
    }

    /// A UDP socket holding the port of a TCP listener bound next.
    fn occupied_udp_port() -> (std::net::UdpSocket, SocketAddress) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap().into();
        (socket, addr)
    }

    #[tokio::test]
    async fn implied_http3_that_cannot_bind_leaves_h1_and_h2_serving() {
        let (_held, addr) = occupied_udp_port();
        let listeners = HttpListeners::bind(
            Executor::new(),
            addr,
            HttpVersions::AUTO,
            Some(&tls()),
            &Http3Args { h3_bind: None },
        )
        .await
        .unwrap();
        assert!(listeners.tcp.is_some());
        assert!(listeners.http3.is_none());
        assert_eq!(listeners.alt_svc().unwrap(), None, "nothing to advertise");
    }

    #[tokio::test]
    async fn explicit_http3_that_cannot_bind_is_an_error() {
        let (_held, addr) = occupied_udp_port();
        let explicit: [(HttpVersions, Option<SocketAddress>); 2] = [
            ("h1,h2,h3".parse().unwrap(), None),
            (HttpVersions::AUTO, Some(addr)),
        ];
        for (versions, h3_bind) in explicit {
            let result = HttpListeners::bind(
                Executor::new(),
                addr,
                versions,
                Some(&tls()),
                &Http3Args { h3_bind },
            )
            .await;
            assert!(result.is_err(), "{versions:?} with --h3-bind {h3_bind:?}");
        }
    }

    #[tokio::test]
    async fn http3_alone_binds_no_tcp_listener() {
        let listeners = HttpListeners::bind(
            Executor::new(),
            localhost(),
            "h3".parse().unwrap(),
            Some(&tls()),
            &Http3Args { h3_bind: None },
        )
        .await
        .unwrap();
        assert!(listeners.tcp.is_none());
        let quic = listeners.http3.as_ref().unwrap().local_addr().unwrap();
        assert_eq!(
            listeners.alt_svc().unwrap(),
            Some(alt_svc(quic.port()).unwrap())
        );
    }
}
