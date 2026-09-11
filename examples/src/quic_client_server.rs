//! An authenticated QUIC client and server on one shared graceful runtime, exchanging a
//! bidirectional request and a unidirectional upload.
//!
//! The server is given a generated identity and the client trusts that one and nothing else.
//! Authentication is server-only: the server presents a certificate and the client verifies
//! it, and no client certificate is asked for. Both ends check the protocol they negotiated
//! before any application bytes move.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin quic_client_server --features=quic,rustls,ring
//! ```
//!
//! # Expected output
//!
//! ```
//! INFO quic_client_server: server: listening on 127.0.0.1:59589
//! INFO quic_client_server: client: negotiated Unknown (rama-quic/example)
//! INFO quic_client_server: server: negotiated Unknown (rama-quic/example)
//! INFO quic_client_server: server: question of 11 bytes, answering with 15
//! INFO quic_client_server: client: answer of 15 bytes, as expected
//! INFO quic_client_server: server: upload of 4096 bytes read and checked, ended by the peer
//! INFO quic_client_server: client: the server says it read the upload
//! INFO quic_client_server: client: done, closing
//! INFO quic_client_server: server: the connection ended
//! INFO tokio_graceful::shutdown: ::shutdown: waiting for signal to trigger (read: to be cancelled)
//! INFO tokio_graceful::shutdown: ::shutdown: waiting for all guards to drop
//! INFO tokio_graceful::shutdown: ::shutdown: ready after 0.000034958s
//! INFO quic_client_server: shutdown: joined in 34.958µs
//! ```
//!
//! The port and the timings differ each run. `Unknown` is how an application protocol rama
//! does not have a name of its own for is displayed; the bytes are the ALPN above.

#![expect(
    clippy::unwrap_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

use rama::{
    crypto::pki_types::CertificateDer,
    error::BoxError,
    graceful::Shutdown,
    net::tls::ApplicationProtocol,
    quic::{ClientConfig, Connection, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::{collections::smallvec::smallvec, octets},
};

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

/// The protocol both ends ask for. A handshake that settles on anything else is a failure.
const ALPN: &[u8] = b"rama-quic/example";
/// The exchange, so both ends check the bytes rather than only their length.
const QUESTION: &[u8] = b"how are you";
const ANSWER: &[u8] = b"i am quite well";
/// What the server sends once it has read and checked the upload. The client waits for this
/// before closing: the transport acknowledging the end of a stream says nothing about the
/// application having read it.
const TAKEN: &[u8] = b"upload taken";
/// The most one read takes, so a peer sending more fails rather than filling memory.
const READ_CAP: usize = octets::mib(1);
/// How long the server side is given to finish once the client is done.
const SERVER_LIMIT: Duration = Duration::from_secs(20);

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

    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
    let anchor = auth.cert_chain.last().unwrap().clone();

    // One shutdown for the whole application, fired by this example itself once its work is
    // done. Both endpoints are built on guards of it, so stopping the application stops them;
    // neither endpoint holds the shutdown open. A real application would wait on a signal.
    let (finished, is_finished) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        // A sender dropped without sending says the same thing: the application is done.
        drop(is_finished.await);
    });

    let server = Endpoint::build(Executor::graceful(shutdown.guard()))
        .with_server_config(server_config(&auth)?)
        .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .await?;
    let addr = server.local_addr()?;
    tracing::info!("server: listening on {addr}");

    // Its outcome is joined below, so a server-side failure fails this process.
    let serving = shutdown.spawn_task(async move { serve(&server).await });

    let client = Endpoint::build(Executor::graceful(shutdown.guard()))
        .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .await?;
    let connection = client
        .connect_with(client_config(anchor)?, addr, "localhost")?
        .await?;
    let settled = connection
        .handshake_data()
        .ok_or("the handshake settled nothing")?;
    let negotiated = settled.protocol.ok_or("no protocol was negotiated")?;
    if negotiated != ApplicationProtocol::from(ALPN) {
        return Err(format!("the client negotiated {negotiated}, not the example's own").into());
    }
    tracing::info!("client: negotiated {negotiated}");

    ask(&connection).await?;
    upload(&connection).await?;
    taken(&connection).await?;

    tracing::info!("client: done, closing");
    connection.close(0u32.into(), b"done");
    client.wait_idle().await;

    // Nothing holds a guard but the endpoints' own supervisors and the serving task, so this
    // joins once they have stopped. Both endpoints are still alive here.
    // Bounded, so a server that never finishes fails rather than hanging.
    tokio::time::timeout(SERVER_LIMIT, serving)
        .await
        .map_err(|_elapsed| -> BoxError { "the server did not finish".into() })?
        .map_err(|error| -> BoxError { format!("the server task failed: {error}").into() })??;

    finished
        .send(())
        .map_err(|()| -> BoxError { "nothing is listening for the end".into() })?;
    let took = shutdown.shutdown().await;
    drop((client, addr));
    tracing::info!("shutdown: joined in {took:?}");
    Ok(())
}

/// One bidirectional exchange: a question, and a different answer read back.
async fn ask(connection: &Connection) -> Result<(), BoxError> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(QUESTION).await?;
    // Half-close: the question is complete, and the answer is still to come.
    send.finish()?;
    let answer = recv.read_to_end(READ_CAP).await?;
    if answer != ANSWER {
        return Err("the answer was not the one the server sends".into());
    }
    tracing::info!("client: answer of {} bytes, as expected", answer.len());
    Ok(())
}

/// One unidirectional upload, ended so the server sees where it stops.
///
/// `stopped` is the transport acknowledging the end of the stream, not the application having
/// read it. What says the server read it is the server's own check of the bytes, which fails
/// this process if it does not hold.
async fn upload(connection: &Connection) -> Result<(), BoxError> {
    let mut uni = connection.open_uni().await?;
    uni.write_all(&upload_payload()).await?;
    uni.finish()?;
    uni.stopped().await?;
    Ok(())
}

/// The bytes the client uploads and the server checks.
fn upload_payload() -> Vec<u8> {
    vec![0x5a; octets::kib(4)]
}

/// Wait for the server to say it read the upload, so closing does not depend on scheduling.
async fn taken(connection: &Connection) -> Result<(), BoxError> {
    let mut uni = connection.accept_uni().await?;
    let said = uni.read_to_end(READ_CAP).await?;
    if said != TAKEN {
        return Err("the server said something other than that it took the upload".into());
    }
    tracing::info!("client: the server says it read the upload");
    Ok(())
}

/// Accept one connection, answer its question, take its upload, and wait for it to end.
async fn serve(server: &Endpoint) -> Result<(), BoxError> {
    let Some(incoming) = server.accept().await else {
        return Ok(());
    };
    let connection = incoming.await?;
    let settled = connection
        .handshake_data()
        .ok_or("the handshake settled nothing")?;
    let negotiated = settled.protocol.ok_or("no protocol was negotiated")?;
    if negotiated != ApplicationProtocol::from(ALPN) {
        return Err(format!("the server negotiated {negotiated}, not the example's own").into());
    }
    tracing::info!("server: negotiated {negotiated}");

    let (mut send, mut recv) = connection.accept_bi().await?;
    let question = recv.read_to_end(READ_CAP).await?;
    if question != QUESTION {
        return Err("the question was not the one the client asks".into());
    }
    tracing::info!(
        "server: question of {} bytes, answering with {}",
        question.len(),
        ANSWER.len()
    );
    send.write_all(ANSWER).await?;
    send.finish()?;

    let mut uni = connection.accept_uni().await?;
    let upload = uni.read_to_end(READ_CAP).await?;
    if upload != upload_payload() {
        return Err("the upload was not the bytes the client sends".into());
    }
    tracing::info!(
        "server: upload of {} bytes read and checked, ended by the peer",
        upload.len()
    );
    // Said at the application level, so the client is not left inferring it from a transport
    // acknowledgement.
    let mut taken = connection.open_uni().await?;
    taken.write_all(TAKEN).await?;
    taken.finish()?;

    connection.closed().await;
    tracing::info!("server: the connection ended");
    Ok(())
}

/// What the server presents: the generated identity, and the one protocol it speaks.
fn server_config(auth: &ServerAuthData) -> Result<ServerConfig, BoxError> {
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .with_server_auth(auth.clone());
    Ok(ServerConfig::try_from_rama_tls(
        &tls,
        TlsOptions::default(),
    )?)
}

/// What the client trusts: that identity, and nothing else.
fn client_config(anchor: CertificateDer<'static>) -> Result<ClientConfig, BoxError> {
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .try_with_server_trust_anchors([anchor])?;
    Ok(ClientConfig::try_from_rama_tls(
        &tls,
        TlsOptions::default(),
    )?)
}
