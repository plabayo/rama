//! Discard [RFC 863] service which discards incoming TCP/UDP bytes and
//! sends no response back.
//!
//! [RFC 863]: https://github.com/plabayo/rama/blob/main/rama-net/specifications/misc/rfc863.txt

use rama::{
    Layer, Service, ServiceInput,
    combinators::Either,
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    futures::TryStreamExt,
    graceful::ShutdownGuard,
    layer::{
        ConsumeErrLayer, LimitLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, RatePolicy, UnlimitedPolicy},
    },
    net::{
        address::SocketAddress,
        stream::layer::{ThrottleLayer, ThrottleMode},
        stream::service::DiscardService,
    },
    rt::Executor,
    stream::{codec::BytesCodec, io::StreamReader},
    tcp::server::TcpListener,
    telemetry::tracing::{self, Instrument},
    tls::boring::server::TlsAcceptorLayer,
    udp::{UdpFramed, bind_udp_with_address},
};

use clap::{Args, ValueEnum};
use std::{fmt, time::Duration};

use crate::utils::{rate::opt_per_sec, tls::try_new_server_config};

#[derive(Debug, Args)]
/// rama discard (rfc863) service
pub struct CliCommandDiscard {
    /// the address to bind to
    #[arg(long, default_value_t = SocketAddress::local_ipv4(9))]
    bind: SocketAddress,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent TCP/TLS connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(long, default_value_t = Default::default())]
    /// the transport mode to use
    mode: Mode,

    #[arg(short = 't', long, default_value_t = 300)]
    /// the timeout in seconds for each TCP/TLS connection
    ///
    /// (0 = no timeout)
    timeout: u64,

    #[arg(long, default_value_t = 0)]
    /// rate limit the service in new connections per second (tcp/tls)
    ///
    /// (0 = no limit)
    rate: u64,

    #[arg(long, default_value_t = 0)]
    /// throttle the discarded ingress at the given byte rate
    /// (bytes per second, per TCP/TLS connection or aggregate UDP socket)
    ///
    /// (0 = no throttling)
    throttle: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum Mode {
    /// Bind discard service on top of TCP
    #[default]
    Tcp,
    /// Bind discard service on top of UDP
    Udp,
    /// Bind discard service on top of TCP over TLS.
    ///
    /// Meaning that the TLS connection will be established,
    /// prior to the discard (rfc863) kicking in.
    Tls,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Tcp => "tcp",
                Self::Udp => "udp",
                Self::Tls => "tls",
            }
        )
    }
}

/// run the rama echo service
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandDiscard) -> Result<(), BoxError> {
    let exec = Executor::graceful(graceful);

    match cfg.mode {
        Mode::Tcp | Mode::Tls => {
            let maybe_tls_cfg = if cfg.mode == Mode::Tls {
                tracing::info!("create tls server config...");
                Some(try_new_server_config(None, exec.clone())?)
            } else {
                None
            };
            let discard_svc = (
                ConsumeErrLayer::trace_as(tracing::Level::DEBUG),
                opt_per_sec(Some(cfg.rate)).map(|rate| LimitLayer::new(RatePolicy::abort(rate))),
                LimitLayer::new(if cfg.concurrent > 0 {
                    Either::A(ConcurrentPolicy::max(cfg.concurrent))
                } else {
                    Either::B(UnlimitedPolicy::new())
                }),
                if cfg.timeout > 0 {
                    TimeoutLayer::new(Duration::from_secs(cfg.timeout))
                } else {
                    TimeoutLayer::never()
                },
                opt_per_sec(Some(cfg.throttle))
                    .map(|rate| ThrottleLayer::read_only(ThrottleMode::per_conn(rate))),
                maybe_tls_cfg.map(TlsAcceptorLayer::new),
            )
                .into_layer(DiscardService::new());

            tracing::info!(
                "starting TCP discard service: bind interface = {:?}",
                cfg.bind
            );
            let tcp_listener = TcpListener::build(exec.clone())
                .bind_address(cfg.bind)
                .await
                .context("bind TCP discard service socket")?;

            let bind_address = tcp_listener
                .local_addr()
                .context("get local addr of tcp listener")?;

            let span = tracing::trace_root_span!(
                "discard",
                otel.kind = "server",
                network.protocol.name = "tcp"
            );

            exec.spawn_task(async move {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "discard service ready: bind interface = {}", cfg.bind,
                );

                tcp_listener.serve(discard_svc).instrument(span).await;
            });
        }
        Mode::Udp => {
            if cfg.rate > 0 {
                return Err(BoxError::from_static_str(
                    "--rate does not apply to UDP discard mode",
                ));
            }
            if cfg.concurrent > 0 {
                return Err(BoxError::from_static_str(
                    "--concurrent does not apply to UDP discard mode",
                ));
            }
            let discard_svc = (
                ConsumeErrLayer::trace_as(tracing::Level::DEBUG),
                opt_per_sec(Some(cfg.throttle))
                    .map(|rate| ThrottleLayer::read_only(ThrottleMode::per_conn(rate))),
            )
                .into_layer(DiscardService::new());

            tracing::info!(
                "starting UDP discard service: bind interface = {:?}",
                cfg.bind
            );
            let udp_socket = bind_udp_with_address(cfg.bind)
                .await
                .context("bind UDP discard service socket")?;

            let bind_address = udp_socket
                .local_addr()
                .context("get local addr of udp socket")?;

            let span = tracing::trace_root_span!(
                "discard",
                otel.kind = "server",
                network.protocol.name = "udp"
            );

            // no graceful shutdown for udp :)
            tokio::spawn(async move {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "discard service ready: bind interface = {}", cfg.bind,
                );

                let reader = StreamReader::new(
                    UdpFramed::new(udp_socket, BytesCodec::new()).map_ok(|(bytes, addr)| {
                        tracing::trace!("read bytes for addr {addr}");
                        bytes
                    }),
                );
                let stream = tokio::io::join(reader, tokio::io::empty());
                let input = ServiceInput::new(stream);

                if let Err(err) = discard_svc.serve(input).instrument(span).await {
                    tracing::error!("discard UDP svc ended with an error: {err}");
                }
            });
        }
    }

    Ok(())
}
