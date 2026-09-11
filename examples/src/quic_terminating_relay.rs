//! A terminating QUIC relay. It accepts client connections and carries each stream over a
//! separate connection of its own to an upstream origin.
//!
//! Terminating means the relay is the TLS peer of both sides. It presents its own identity to
//! the client and authenticates the origin as a client itself, so there are two independent
//! handshakes and nothing is forwarded at the packet level. Stream bytes are copied between
//! the two connections. No connection-level property of one side reaches the other.
//!
//! Authentication is server-only in both directions: each side authenticates the peer it
//! dials. Neither asks for a client certificate.
//!
//! It carries client-initiated bidirectional streams. Unidirectional and server-initiated
//! streams are not relayed.
//!
//! # What it bounds
//!
//! - active client connections, and concurrent relayed streams per connection, each by a
//!   permit taken before any work starts;
//! - the copy buffer, a fixed size in both directions.
//!
//! # What it preserves
//!
//! - half-close: one side finishing its writes finishes the other side's send, so a request
//!   can complete before its answer begins;
//! - cancellation: a reset or a stop on either side ends both directions of that stream,
//!   including a direction waiting on flow control, and the application's graceful shutdown
//!   ends everything.
//!
//! # Run the example
//!
//! It needs an origin to relay to, and the certificate that origin presents.
//!
//! ```sh
//! cargo run -p rama-examples --bin quic_terminating_relay --features=quic,rustls,ring -- \
//!     --upstream 127.0.0.1:62000 --upstream-ca origin-cert.pem \
//!     --cert relay-cert.pem --key relay-key.pem
//! ```
//!
//! Required: `--upstream`, `--upstream-ca`, `--cert` and `--key`. The rest have defaults:
//!
//! - `--listen <addr>`: where clients connect. Default `127.0.0.1:62060`.
//! - `--upstream <addr>`: the origin. Required.
//! - `--upstream-ca <pem>`: the certificate the origin presents. Required.
//! - `--max-connections <n>`: client connections carried at once. Default 64.
//! - `--max-streams <n>`: streams relayed at once on one connection. Default 16.
//! - `--cert <pem>` and `--key <pem>`: what this relay presents, and what a client has to
//!   trust. Required: a client cannot verify an identity it has no way to obtain.
//! - `--upstream-name <name>`: the name asked of the origin, which its certificate must carry.
//!   Default `localhost`.
//!
//! Stop it with ctrl-c. It reports the address it listens on, each connection it carries and
//! each stream it relays.
//!
//! # Expected output
//!
//! ```
//! INFO quic_terminating_relay: relay: listening on 127.0.0.1:62060, upstream 127.0.0.1:62000
//! INFO quic_terminating_relay: relay: a client connection, opening one upstream of its own
//! INFO quic_terminating_relay: relay: stream relayed, 11 up and 15 down
//! ```

use rama::{
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    error::BoxError,
    futures::{FutureExt as _, future::select_all},
    graceful::{Shutdown, WeakShutdownGuard, default_signal},
    net::tls::ApplicationProtocol,
    quic::{
        ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, StoppedError,
        VarInt, tls::TlsOptions,
    },
    rt::{Executor, spawn},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
    utils::{collections::smallvec::smallvec, octets},
};

use std::{
    future::pending,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    pin::pin,
    sync::Arc,
};
use tokio::{
    sync::{Semaphore, oneshot, watch},
    task::JoinHandle,
};

/// The protocol every hop asks for.
const ALPN: &[u8] = b"rama-quic/relay";
/// One copy's buffer, in both directions.
const COPY_BUFFER: usize = octets::kib(16);
/// The code either peer is given when a stream is ended for it.
const RELAY_CANCELLED: u32 = 1;
/// What a client is told when its upstream cannot be reached, and when it goes away.
const UPSTREAM_UNAVAILABLE: u32 = 2;
const UPSTREAM_GONE: u32 = 3;
/// What both sides are told when the relay itself is giving up.
const RELAY_STOPPING: u32 = 4;
/// The name the relay asks the origin for, unless `--upstream-name` says otherwise. The
/// origin's certificate has to carry it.
const DEFAULT_UPSTREAM_NAME: &str = "localhost";

/// How much the relay carries at once. Neither may be zero, which would carry nothing, and
/// neither may exceed what a semaphore can hold.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    /// Client connections at once.
    connections: usize,
    /// Relayed streams at once on one connection.
    streams: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            connections: 64,
            streams: 16,
        }
    }
}

/// A limit the relay can actually hold: at least one, and within a semaphore's capacity.
fn limit(what: &str, value: &str) -> Result<usize, BoxError> {
    let value: usize = value.parse()?;
    if value == 0 {
        return Err(format!("{what} must be at least 1, so the relay carries something").into());
    }
    if value > Semaphore::MAX_PERMITS {
        return Err(format!(
            "{what} is above the {} this can hold",
            Semaphore::MAX_PERMITS
        )
        .into());
    }
    Ok(value)
}

/// What this relay was told to do.
#[derive(Debug)]
struct Settings {
    listen: SocketAddr,
    upstream: SocketAddr,
    upstream_ca: PathBuf,
    upstream_name: String,
    identity: (PathBuf, PathBuf),
    bounds: Bounds,
}

impl Settings {
    /// Read the arguments. An unknown or incomplete one is an error, not a default.
    fn from_args() -> Result<Self, BoxError> {
        let mut listen = "127.0.0.1:62060".parse::<SocketAddr>()?;
        let (mut upstream, mut upstream_ca) = (None, None);
        let mut upstream_name = DEFAULT_UPSTREAM_NAME.to_owned();
        let (mut cert, mut key) = (None, None);
        let mut bounds = Bounds::default();
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("{flag} needs a value").into())
                    .map_err(|error: BoxError| error)
            };
            match flag.as_str() {
                "--listen" => listen = value()?.parse()?,
                "--upstream" => upstream = Some(value()?.parse()?),
                "--upstream-ca" => upstream_ca = Some(PathBuf::from(value()?)),
                "--upstream-name" => upstream_name = value()?,
                "--max-connections" => {
                    bounds.connections = limit("--max-connections", &value()?)?;
                }
                "--max-streams" => bounds.streams = limit("--max-streams", &value()?)?,
                "--cert" => cert = Some(PathBuf::from(value()?)),
                "--key" => key = Some(PathBuf::from(value()?)),
                other => return Err(format!("unknown argument {other}").into()),
            }
        }
        let identity = match (cert, key) {
            (Some(cert), Some(key)) => (cert, key),
            _ => return Err("--cert and --key are both required".into()),
        };
        Ok(Self {
            listen,
            upstream: upstream.ok_or("--upstream is required")?,
            upstream_ca: upstream_ca.ok_or("--upstream-ca is required")?,
            upstream_name,
            identity,
            bounds,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let settings = Settings::from_args()?;
    let (cert, key) = &settings.identity;
    let auth = ServerAuthData {
        cert_chain: CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?,
        private_key: PrivateKeyDer::from_pem_file(key)?,
        ocsp: None,
    };
    let upstream_anchor = CertificateDer::from_pem_file(&settings.upstream_ca)?;

    // The application's shutdown. Ctrl-c stops the relay, which stops its endpoints, and so
    // does the serving task ending: dropping its side of this channel resolves the receiver,
    // so a fatal failure is reported without waiting for a signal that may never come.
    let (serving_ended, serving_ends) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        tokio::select! {
            () = default_signal() => {}
            _ = serving_ends => {}
        }
    });

    let relay = Endpoint::build(Executor::graceful(shutdown.guard()))
        .with_server_config(server_config(&auth)?)
        .bind_address(settings.listen)
        .await?;
    let listening = relay.local_addr()?;
    // The outbound socket takes the upstream's family: an IPv4 listener can serve clients
    // while reaching an IPv6 origin, and the other way round.
    let outbound = match settings.upstream.is_ipv6() {
        true => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        false => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
    };
    let client = Endpoint::build(Executor::graceful(shutdown.guard()))
        .bind_address(outbound)
        .await?;
    tracing::info!(
        "relay: listening on {listening}, upstream {}",
        settings.upstream
    );

    let upstream_config = client_config(upstream_anchor)?;
    let (upstream, bounds) = (settings.upstream, settings.bounds);
    let upstream_name = settings.upstream_name;
    // What tells a connection that the relay itself is stopping, rather than its upstream.
    let stopping = shutdown.guard_weak();
    // Its outcome is joined below, so a failure in it fails this process.
    let serving = shutdown.spawn_task(async move {
        let outcome = serve_relay(
            &relay,
            &client,
            upstream_config,
            upstream,
            &upstream_name,
            bounds,
            &stopping,
        )
        .await;
        drop(serving_ended);
        outcome
    });

    // The shutdown holds that task's guard, so it has ended by the time this returns.
    let took = shutdown.shutdown().await;
    serving.await.map_err(|error| -> BoxError {
        format!("the relay's serving task failed: {error}").into()
    })??;
    tracing::info!("relay: stopped, shutdown joined in {took:?}");
    Ok(())
}

/// The relay: one upstream connection per client connection, one upstream stream per relayed
/// stream, both bounded by permits taken before any work begins.
///
/// Every task it starts is owned here. A task that fails is noticed when it fails, not when
/// the next client happens to arrive, and every exit path joins what is still running.
async fn serve_relay(
    relay: &Endpoint,
    client: &Endpoint,
    upstream: ClientConfig,
    origin: SocketAddr,
    name: &str,
    bounds: Bounds,
    stopping: &WeakShutdownGuard,
) -> Result<(), BoxError> {
    let connections = Arc::new(Semaphore::new(bounds.connections));
    let mut carrying: Vec<JoinHandle<()>> = Vec::new();
    let outcome = loop {
        let incoming = tokio::select! {
            incoming = relay.accept() => incoming,
            failed = finished(&mut carrying) => match failed {
                Ok(()) => continue,
                Err(error) => {
                    // Nothing more will be served, so stop both endpoints before joining: a
                    // connection still waiting in accept_bi would otherwise hold this open.
                    relay.close(RELAY_STOPPING.into(), b"relay stopping");
                    client.close(RELAY_STOPPING.into(), b"relay stopping");
                    break Err(error);
                }
            },
        };
        let Some(incoming) = incoming else {
            break Ok(());
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            tracing::warn!("relay: at its connection limit, refusing");
            incoming.refuse();
            continue;
        };
        let (upstream, client, name) = (upstream.clone(), client.clone(), name.to_owned());
        let stopping = stopping.clone();
        carrying.push(spawn(async move {
            match incoming.await {
                Ok(downstream) => {
                    if let Err(error) = carry(
                        downstream, &client, upstream, origin, &name, bounds, &stopping,
                    )
                    .await
                    {
                        tracing::warn!("relay: a connection ended early: {error}");
                    }
                }
                Err(error) => tracing::warn!("relay: a handshake did not complete: {error}"),
            }
            drop(permit);
        }));
    };
    // Whatever the loop ended for, the tasks it started are joined.
    let joined = join(carrying).await;
    outcome.and(joined)
}

/// Wait for whichever of these tasks finishes first and take it out of the list.
///
/// The handles are borrowed rather than moved, so dropping this future leaves every task owned
/// by the caller. With nothing running it waits forever, which is what the select wants.
async fn finished(tasks: &mut Vec<JoinHandle<()>>) -> Result<(), BoxError> {
    if tasks.is_empty() {
        return pending().await;
    }
    let (outcome, which) = {
        let (outcome, which, _rest) = select_all(tasks.iter_mut()).await;
        (outcome, which)
    };
    drop(tasks.swap_remove(which));
    outcome.map_err(|error| -> BoxError { format!("a relay task failed: {error}").into() })
}

/// Join every task, reporting the first failure once they have all ended.
async fn join(tasks: Vec<JoinHandle<()>>) -> Result<(), BoxError> {
    let mut failure = None;
    for task in tasks {
        if let Err(error) = task.await {
            failure.get_or_insert(error);
        }
    }
    match failure {
        Some(error) => Err(format!("a relay task failed: {error}").into()),
        None => Ok(()),
    }
}

/// One client connection, and the separate upstream connection it is carried over.
///
/// A client whose upstream cannot be reached is told so rather than left waiting, and an
/// upstream that ends while this is waiting for a stream ends the client connection too.
async fn carry(
    downstream: Connection,
    client: &Endpoint,
    upstream: ClientConfig,
    origin: SocketAddr,
    name: &str,
    bounds: Bounds,
    stopping: &WeakShutdownGuard,
) -> Result<(), BoxError> {
    tracing::info!("relay: a client connection, opening one upstream of its own");
    let upstream = match client.connect_with(upstream, origin, name) {
        Ok(connecting) => match connecting.await {
            Ok(upstream) => upstream,
            Err(error) => return Err(no_upstream(&downstream, error.into())),
        },
        Err(error) => return Err(no_upstream(&downstream, error.into())),
    };

    let streams = Arc::new(Semaphore::new(bounds.streams));
    let mut relaying: Vec<JoinHandle<()>> = Vec::new();
    let outcome = 'serving: loop {
        let accepted = tokio::select! {
            accepted = downstream.accept_bi() => accepted,
            failed = finished(&mut relaying) => match failed {
                Ok(()) => continue,
                Err(error) => break Err(error),
            },
            error = upstream.closed() => {
                tracing::info!("relay: the upstream ended, so this connection ends: {error}");
                upstream_gone(&downstream, stopping);
                break Ok(());
            }
        };
        // The client closed, or the connection ended; either way this connection is done.
        let Ok((down_send, down_recv)) = accepted else {
            break Ok(());
        };
        let Ok(permit) = streams.clone().try_acquire_owned() else {
            tracing::warn!("relay: at its stream limit for this connection");
            continue;
        };
        // An origin with no stream credit would otherwise hold this here, leaving a closed
        // downstream or a failed task unobserved until it answers.
        let (up_send, up_recv) = loop {
            tokio::select! {
                opened = upstream.open_bi() => match opened {
                    Ok(pair) => break pair,
                    Err(error) => {
                        upstream_gone(&downstream, stopping);
                        break 'serving Err(error.into());
                    }
                },
                error = downstream.closed() => {
                    tracing::info!("relay: the client left while a stream waited: {error}");
                    break 'serving Ok(());
                }
                failed = finished(&mut relaying) => {
                    if let Err(error) = failed {
                        break 'serving Err(error);
                    }
                }
            }
        };
        relaying.push(spawn(async move {
            if let Err(error) = relay_stream(down_send, down_recv, up_send, up_recv).await {
                tracing::warn!("relay: a stream ended early: {error}");
            }
            drop(permit);
        }));
    };
    // The upstream is closed first, so a stream still waiting on it is released and the joins
    // below cannot wait on a peer that will never answer.
    upstream.close(0u32.into(), b"done");
    let joined = join(relaying).await;
    outcome.and(joined)
}

/// Not sent while the relay is stopping: both connections are closed by their endpoints then,
/// and that is what the client should read.
fn upstream_gone(downstream: &Connection, stopping: &WeakShutdownGuard) {
    if stopping.cancelled().now_or_never().is_none() {
        downstream.close(UPSTREAM_GONE.into(), b"upstream closed");
    }
}

/// Tell the client its upstream is unreachable, rather than letting it open streams that
/// cannot be served.
fn no_upstream(downstream: &Connection, error: BoxError) -> BoxError {
    downstream.close(UPSTREAM_UNAVAILABLE.into(), b"upstream unavailable");
    error
}

/// Ends both directions of one stream. A clean finish in one direction does not set this: a
/// half-close is not a failure.
#[derive(Debug)]
struct Cancel(watch::Sender<bool>);

impl Cancel {
    fn new() -> Self {
        Self(watch::channel(false).0)
    }

    /// A receiver for one direction. Taken before either direction starts.
    fn hear(&self) -> watch::Receiver<bool> {
        self.0.subscribe()
    }

    /// There are no receivers left once both directions have ended, which is not an error.
    fn stop(&self) {
        if self.0.send(true).is_err() {
            tracing::debug!("relay: both directions of this stream had already ended");
        }
    }
}

/// Copy both ways at once. Each direction finishes the far send when its near read ends, and
/// any failure ends the other direction as well.
async fn relay_stream(
    down_send: SendStream,
    down_recv: RecvStream,
    up_send: SendStream,
    up_recv: RecvStream,
) -> Result<(), BoxError> {
    let cancel = Cancel::new();
    let (up_hear, down_hear) = (cancel.hear(), cancel.hear());
    let (up, down) = tokio::join!(
        copy(down_recv, up_send, &cancel, up_hear),
        copy(up_recv, down_send, &cancel, down_hear),
    );
    let (up, down) = (up?, down?);
    tracing::info!("relay: stream relayed, {up} up and {down} down");
    Ok(())
}

/// One direction, through a fixed buffer.
///
/// Reading and writing are both cancellable. Three things end this direction: the source
/// finishing, which finishes the destination and leaves the other direction running; the
/// destination being stopped, noticed while waiting for input and while writing; and the other
/// direction failing.
async fn copy(
    mut from: RecvStream,
    mut to: SendStream,
    cancel: &Cancel,
    mut hear: watch::Receiver<bool>,
) -> Result<usize, BoxError> {
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut carried = 0usize;
    // `stopped` borrows nothing, so one future serves every iteration and both branches.
    let mut stopped = pin!(to.stopped());
    loop {
        let read = tokio::select! {
            read = from.read(&mut buffer) => read,
            stopped = &mut stopped => {
                return Err(ended(&mut from, &mut to, cancel, why(stopped)));
            }
            changed = hear.changed() => {
                drop(changed);
                return Err(sibling_ended(&mut from, &mut to));
            }
        };
        let read = match read {
            Ok(Some(read)) => read,
            // Half-close: the source is done, so the destination is told where it ends. The
            // other direction carries on.
            Ok(None) => {
                return match to.finish() {
                    Ok(()) => Ok(carried),
                    Err(error) => Err(ended(&mut from, &mut to, cancel, error.into())),
                };
            }
            Err(error) => return Err(ended(&mut from, &mut to, cancel, error.into())),
        };
        tokio::select! {
            written = to.write_all(&buffer[..read]) => match written {
                Ok(()) => carried += read,
                Err(error) => return Err(ended(&mut from, &mut to, cancel, error.into())),
            },
            // A write waiting on the peer's flow control is still cancellable.
            stopped = &mut stopped => {
                return Err(ended(&mut from, &mut to, cancel, why(stopped)));
            }
            changed = hear.changed() => {
                drop(changed);
                return Err(sibling_ended(&mut from, &mut to));
            }
        }
    }
}

/// What a resolved `stopped()` means for this direction.
fn why(stopped: Result<Option<VarInt>, StoppedError>) -> BoxError {
    match stopped {
        Ok(Some(code)) => format!("the destination stopped this stream: {code}").into(),
        Ok(None) => "the destination ended this stream".into(),
        Err(error) => error.into(),
    }
}

/// The other direction failed. Nothing is owed to either peer on this one.
fn sibling_ended(from: &mut RecvStream, to: &mut SendStream) -> BoxError {
    drop(to.reset(RELAY_CANCELLED.into()));
    drop(from.stop(RELAY_CANCELLED.into()));
    "the other direction of this stream ended".into()
}

/// End this direction deliberately and tell the other one, rather than leaving either peer to
/// infer it from a dropped stream.
fn ended(from: &mut RecvStream, to: &mut SendStream, cancel: &Cancel, error: BoxError) -> BoxError {
    drop(to.reset(RELAY_CANCELLED.into()));
    drop(from.stop(RELAY_CANCELLED.into()));
    cancel.stop();
    error
}

/// What a hop presents: its own identity, and the one protocol it speaks.
fn server_config(auth: &ServerAuthData) -> Result<ServerConfig, BoxError> {
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .with_server_auth(auth.clone());
    Ok(ServerConfig::try_from_rama_tls(
        &tls,
        TlsOptions::default(),
    )?)
}

/// What a hop trusts: the identity of the one it is dialling, and nothing else.
fn client_config(anchor: CertificateDer<'static>) -> Result<ClientConfig, BoxError> {
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .try_with_server_trust_anchors([anchor])?;
    Ok(ClientConfig::try_from_rama_tls(
        &tls,
        TlsOptions::default(),
    )?)
}
