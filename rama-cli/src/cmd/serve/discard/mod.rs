//! Discard [RFC 863] service which discards the incomoing TCP/UDP
//! bytes and sents no response back.
//!
//! [RFC 863]: https://datatracker.ietf.org/doc/html/rfc863

use rama::{
    Layer, Service, ServiceInput,
    combinators::Either,
    error::{BoxError, ErrorContext, OpaqueError},
    futures::TryStreamExt,
    graceful::ShutdownGuard,
    layer::{
        ConsumeErrLayer, LimitLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, UnlimitedPolicy},
    },
    net::{socket::Interface, stream::service::DiscardService},
    stream::{codec::BytesCodec, io::StreamReader},
    tcp::server::TcpListener,
    telemetry::tracing::{self, Instrument},
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
    udp::UdpSocket,
};

use clap::{Args, ValueEnum};
use std::{fmt, time::Duration};

use crate::utils::tls::new_server_config;

#[derive(Debug, Args)]
/// rama discard (rfc863) service
pub struct CliCommandDiscard {
    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:9")]
    bind: Interface,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(long, default_value_t = Default::default())]
    /// the transport mode to use
    mode: Mode,

    #[arg(short = 't', long, default_value_t = 300)]
    /// the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    timeout: u64,
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
    let maybe_tls_cfg: Option<TlsAcceptorData> = if cfg.mode == Mode::Tls {
        tracing::info!("create tls server config...");
        let cfg = new_server_config(None);
        Some(cfg.try_into()?)
    } else {
        None
    };

    let middleware = (
        ConsumeErrLayer::trace(tracing::Level::DEBUG),
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
        maybe_tls_cfg.map(TlsAcceptorLayer::new),
    );
    let discard_svc = middleware.into_layer(DiscardService::new());

    match cfg.mode {
        Mode::Tcp | Mode::Tls => {
            tracing::info!(
                "starting TCP discard service: bind interface = {:?}",
                cfg.bind
            );
            let tcp_listener = TcpListener::build()
                .bind(cfg.bind.clone())
                .await
                .map_err(OpaqueError::from_boxed)
                .context("bind TCP discard service socket")?;

            let bind_address = tcp_listener
                .local_addr()
                .context("get local addr of tcp listener")?;

            let span = tracing::trace_root_span!(
                "discard",
                otel.kind = "server",
                network.protocol.name = "tcp"
            );

            graceful.into_spawn_task_fn(async move |guard| {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "discard service ready: bind interface = {}", cfg.bind,
                );

                tcp_listener
                    .serve_graceful(guard, discard_svc)
                    .instrument(span)
                    .await;
            });
        }
        Mode::Udp => {
            tracing::info!(
                "starting UDP discard service: bind interface = {:?}",
                cfg.bind
            );
            let udp_socket = UdpSocket::bind(cfg.bind.clone())
                .await
                .map_err(OpaqueError::from_boxed)
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

                let reader = StreamReader::new(udp_socket.into_framed(BytesCodec::new()).map_ok(
                    |(bytes, addr)| {
                        tracing::trace!("read bytes for addr {addr}");
                        bytes
                    },
                ));
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
