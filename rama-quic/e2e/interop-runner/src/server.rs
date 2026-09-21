//! Runner server: serve bounded HTTP/0.9 request lines from the mounted document root.

use crate::{
    ALPN, BUFFER_SIZE, REQUEST_LIMIT, STREAM_LIMIT, TestCase, check_alpn, log_connection_stats,
    relative_path, shutdown_endpoint, transport,
};
use clap::Parser;
use rama::{
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    error::{BoxError, ErrorContext as _},
    graceful::{Shutdown, default_signal},
    net::{socket::SocketOptions, tls::ApplicationProtocol},
    quic::{
        Connection, Endpoint, RecvStream, SendStream, ServerConfig,
        proto::version::{ServerVersionPolicy, Version, VersionPreference},
    },
    rt::Executor,
    telemetry::tracing,
    tls::{
        KeyLogIntent,
        server::{ServerAuthData, TlsServerConfig},
    },
    udp::UdpSocketConfig,
    utils::collections::smallvec::smallvec,
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncReadExt as _, task::JoinSet};

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(long, env = "TESTCASE", default_value = "transfer")]
    pub testcase: String,
    /// Check testcase support without accessing the network or runner mounts.
    #[arg(long)]
    pub check_testcase: bool,
    #[arg(long, default_value = "[::]:443")]
    listen: SocketAddr,
    #[arg(long, env = "WWW", default_value = "/www")]
    www: PathBuf,
    #[arg(long, env = "CERTS", default_value = "/certs")]
    certs: PathBuf,
    /// Override CERTS/cert.pem for local runs.
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Override CERTS/priv.key for local runs.
    #[arg(long)]
    key: Option<PathBuf>,
}

pub async fn run(args: Args, testcase: TestCase) -> Result<(), BoxError> {
    let cert = tokio::fs::read(args.cert.unwrap_or_else(|| args.certs.join("cert.pem")))
        .await
        .context("read runner certificate chain")?;
    let key = tokio::fs::read(args.key.unwrap_or_else(|| args.certs.join("priv.key")))
        .await
        .context("read runner private key")?;
    let auth = ServerAuthData::new(
        CertificateDer::pem_slice_iter(&cert)
            .collect::<Result<Vec<_>, _>>()
            .context("parse runner certificate chain")?,
        PrivateKeyDer::from_pem_slice(&key).context("parse runner private key")?,
    );
    let root = Arc::new(
        tokio::fs::canonicalize(args.www)
            .await
            .context("resolve document root")?,
    );
    let (finished, is_finished) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        let _ = is_finished.await;
    });
    let executor = Executor::graceful(shutdown.guard());
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .with_keylog(KeyLogIntent::Environment)
        .with_server_auth(auth);
    let mut config = ServerConfig::try_from_rama_tls(&tls, crate::tls_options())?
        .with_transport_config(transport(executor.clone(), "server").await?);
    if testcase == TestCase::V2 {
        // Move a client that offers v2 to it (RFC 9368 §2.3).
        config.set_versions(
            ServerVersionPolicy::new()
                .try_with_preference(VersionPreference::Prefer(vec![Version::V2]))
                .context("a usable preference")?,
        );
    }
    let mut socket_options = SocketOptions::default_udp();
    if args.listen.is_ipv6() {
        socket_options.only_v6 = Some(false);
    }
    let endpoint = Endpoint::build(executor)
        .with_server_config(config)
        .bind_address_with_socket_config(
            args.listen,
            UdpSocketConfig::default().with_socket_options(socket_options),
        )
        .await
        .context("bind interop server")?;
    tracing::info!(address = %endpoint.local_addr()?, "interop server listening");
    let mut connections = JoinSet::new();
    let mut stopping = std::pin::pin!(default_signal());
    let outcome = loop {
        tokio::select! {
            _ = &mut stopping => break Ok(()),
            result = connections.join_next(), if !connections.is_empty() => {
                report_task(result);
            }
            incoming = endpoint.accept(), if connections.len() < 128 => {
                let Some(incoming) = incoming else { break Ok(()); };
                if testcase == TestCase::Retry && !incoming.remote_address_validated() {
                    if let Err(error) = incoming.retry() {
                        tracing::warn!(?error, "retry rejected");
                    }
                    continue;
                }
                let root = root.clone();
                connections.spawn(async move {
                    let connection = incoming.await.context("accept handshake")?;
                    check_alpn(&connection)?;
                    serve_connection(connection, root).await
                });
            }
        }
    };
    endpoint.close(0_u32, b"server stopping");
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let outcome = shutdown_endpoint(&endpoint, outcome).await;
    drop(endpoint);
    let _ = finished.send(());
    shutdown.shutdown().await;
    outcome
}

fn report_task(result: Option<Result<Result<(), BoxError>, tokio::task::JoinError>>) {
    match result {
        Some(Ok(Err(error))) => tracing::warn!(?error, "connection failed"),
        Some(Err(error)) => tracing::warn!(?error, "connection task failed"),
        _ => {}
    }
}

async fn serve_connection(connection: Connection, root: Arc<PathBuf>) -> Result<(), BoxError> {
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            result = requests.join_next(), if !requests.is_empty() => {
                let result = result.ok_or("request task missing")?.context("request task failed")?;
                if let Err(error) = result {
                    connection.close(1_u32, b"request failed");
                    return Err(error);
                }
            }
            streams = connection.accept_bi(), if requests.len() < STREAM_LIMIT => {
                let (send, recv) = match streams {
                    Ok(streams) => streams,
                    Err(_) => break,
                };
                let root = root.clone();
                requests.spawn(async move {
                    tokio::time::timeout(Duration::from_secs(180), serve_file(send, recv, &root))
                        .await.context("request timed out")?
                });
            }
        }
    }
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    log_connection_stats(&connection);
    Ok(())
}

fn parse_request(line: &[u8]) -> Result<&Path, BoxError> {
    let line = line
        .strip_suffix(b"\r\n")
        .ok_or("request line must end in CRLF")?;
    let target = line
        .strip_prefix(b"GET ")
        .ok_or("only HTTP/0.9 GET is supported")?;
    relative_path(std::str::from_utf8(target).context("request path is not UTF-8")?)
}

async fn serve_file(
    mut send: SendStream,
    mut recv: RecvStream,
    root: &Path,
) -> Result<(), BoxError> {
    let mut request = [0_u8; REQUEST_LIMIT];
    let mut used = 0;
    loop {
        if used == request.len() {
            return Err("request line exceeds limit".into());
        }
        let count = recv
            .read(&mut request[used..])
            .await?
            .ok_or("incomplete request line")?;
        used += count;
        if request[..used].contains(&b'\n') {
            break;
        }
    }
    let relative = parse_request(&request[..used])?;
    // The runner mounts a static document root. Canonicalization also rejects symlinks
    // escaping that root, beyond the lexical checks in relative_path.
    let path = tokio::fs::canonicalize(root.join(relative))
        .await
        .context("resolve requested file")?;
    if !path.starts_with(root) {
        return Err("requested file escapes document root".into());
    }
    let mut file = tokio::fs::File::open(&path)
        .await
        .context("open requested file")?;
    if !file.metadata().await?.is_file() {
        return Err("requested path is not a regular file".into());
    }
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let count = file
            .read(&mut buffer)
            .await
            .context("read requested file")?;
        if count == 0 {
            break;
        }
        send.write_all(&buffer[..count])
            .await
            .context("send file data")?;
    }
    send.finish()?;
    send.stopped().await.context("await file acknowledgement")?;
    tracing::info!(file = %relative.display(), "served file");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_single_bounded_http09_requests_are_accepted() {
        assert_eq!(parse_request(b"GET /file\r\n").unwrap(), Path::new("file"));
        for line in [
            b"GET /file\n".as_slice(),
            b"GET /file HTTP/1.1\r\n",
            b"POST /file\r\n",
            b"GET /../file\r\n",
            b"GET /file\r\nGET /second\r\n",
            b"GET /file",
        ] {
            assert!(parse_request(line).is_err(), "accepted {line:?}");
        }
    }
}
