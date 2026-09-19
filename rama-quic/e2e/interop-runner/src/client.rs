//! Runner client: bounded concurrent downloads over one connection, or one per request.

use crate::{
    ALPN, BUFFER_SIZE, REQUEST_LIMIT, STREAM_LIMIT, TestCase, check_alpn, log_connection_stats,
    relative_path, shutdown_endpoint, transport,
};
use clap::Parser;
use rama::{
    error::{BoxError, ErrorContext as _},
    graceful::{Shutdown, default_signal},
    net::{tls::ApplicationProtocol, uri::Uri},
    quic::{
        ClientConfig, Connection, Endpoint,
        proto::version::{ClientVersionPolicy, Version},
    },
    rt::Executor,
    telemetry::tracing,
    tls::{
        KeyLogIntent,
        client::{ServerVerifyMode, TlsClientConfig},
    },
    utils::collections::smallvec::smallvec,
};
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{io::AsyncWriteExt as _, task::JoinSet};

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(long, env = "TESTCASE", default_value = "transfer")]
    pub testcase: String,
    /// Check testcase support without accessing the network or runner mounts.
    #[arg(long)]
    pub check_testcase: bool,
    /// Space-separated HTTPS URLs, all sharing one authority.
    #[arg(long, env = "REQUESTS", default_value = "")]
    requests: String,
    #[arg(long, env = "DOWNLOADS", default_value = "/downloads")]
    downloads: PathBuf,
    /// Maximum duration for the complete batch of downloads.
    #[arg(long, default_value_t = 180)]
    timeout_seconds: u64,
}

#[derive(Debug)]
struct Request {
    host: String,
    port: u16,
    target: String,
    filename: String,
}

fn requests(input: &str) -> Result<Vec<Request>, BoxError> {
    let mut output = Vec::new();
    let mut filenames = BTreeSet::new();
    for value in input.split_ascii_whitespace() {
        if output.len() >= 10_000 || value.len() > REQUEST_LIMIT {
            return Err("REQUESTS exceeds the request count or URL length limit".into());
        }
        let uri: Uri = value.parse().context("parse request URL")?;
        if uri.scheme_str() != Some("https") || value.contains(['@', '?', '#']) {
            return Err("expected an HTTPS URL without userinfo, query or fragment".into());
        }
        let host = uri.host_str().ok_or("URL has no host")?.into_owned();
        let port = uri.port_u16().unwrap_or(443);
        let target = uri.path_or_root().into_owned();
        let filename = relative_path(&target)?
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("URL has no filename")?
            .to_owned();
        if !filenames.insert(filename.clone()) {
            return Err("REQUESTS contains duplicate download filenames".into());
        }
        if output
            .first()
            .is_some_and(|first: &Request| first.host != host || first.port != port)
        {
            return Err("REQUESTS must use one server authority".into());
        }
        output.push(Request {
            host,
            port,
            target,
            filename,
        });
    }
    if output.is_empty() {
        return Err("REQUESTS is empty".into());
    }
    Ok(output)
}

pub async fn run(args: Args, testcase: TestCase) -> Result<(), BoxError> {
    let requests = requests(&args.requests)?;
    let first = &requests[0];
    let address = tokio::net::lookup_host((first.host.as_str(), first.port))
        .await
        .context("resolve request server")?
        .next()
        .ok_or("server resolved to no addresses")?;
    let bind: SocketAddr = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    tokio::fs::create_dir_all(&args.downloads)
        .await
        .context("create downloads directory")?;
    let (finished, is_finished) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        let _ = is_finished.await;
    });
    let executor = Executor::graceful(shutdown.guard());
    let endpoint = Endpoint::build(executor.clone()).bind_address(bind).await?;
    // The interop runner supplies disposable test certificates without a client trust store.
    // This verifier is restricted to this test executable; it is not a production default.
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .with_keylog(KeyLogIntent::Environment)
        .with_server_verify(ServerVerifyMode::Disable);
    let mut config = ClientConfig::try_from_rama_tls(&tls, crate::tls_options())?
        .with_transport_config(transport(executor, "client").await?);
    if testcase == TestCase::V2 {
        // A v1 first flight that prefers v2, for the server to move (RFC 9368 §2.3).
        config.set_versions(
            ClientVersionPolicy::new(Version::V1)
                .context("a usable original version")?
                .try_with_compatible(vec![Version::V2, Version::V1])
                .context("a usable compatible list")?,
        )?;
    }
    let batch = tokio::time::timeout(Duration::from_secs(args.timeout_seconds), async {
        if testcase == TestCase::MultiConnect {
            for request in requests {
                let connection = endpoint
                    .connect_with(config.clone(), address, &request.host)?
                    .await?;
                check_alpn(&connection)?;
                download(connection.clone(), request, args.downloads.clone()).await?;
                log_connection_stats(&connection);
                connection.close(0_u32, b"done");
            }
        } else {
            let connection = endpoint
                .connect_with(config, address, &requests[0].host)?
                .await?;
            check_alpn(&connection)?;
            let mut tasks = JoinSet::new();
            for request in requests {
                if tasks.len() >= STREAM_LIMIT {
                    tasks
                        .join_next()
                        .await
                        .ok_or("download task missing")?
                        .context("download task failed")??;
                }
                tasks.spawn(download(
                    connection.clone(),
                    request,
                    args.downloads.clone(),
                ));
            }
            while let Some(result) = tasks.join_next().await {
                result.context("download task failed")??;
            }
            log_connection_stats(&connection);
            connection.close(0_u32, b"done");
        }
        Ok::<_, BoxError>(())
    });
    let outcome = tokio::select! {
        result = batch => result.context("download batch timed out").and_then(|result| result),
        _ = default_signal() => Err(BoxError::from("download batch interrupted by shutdown signal")),
    };
    endpoint.close(0_u32, b"client finished");
    let outcome = shutdown_endpoint(&endpoint, outcome).await;
    drop(endpoint);
    let _ = finished.send(());
    shutdown.shutdown().await;
    outcome
}

async fn download(
    connection: Connection,
    request: Request,
    directory: PathBuf,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = connection.open_bi().await.context("open request stream")?;
    send.write_all(format!("GET {}\r\n", request.target).as_bytes())
        .await?;
    send.finish()?;
    // Never overwrite a previous result or follow an existing symlink in the mount.
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(&request.filename))
        .await
        .context("create download file")?;
    // A read gathers what has arrived into one buffer, so each file write carries as much as
    // possible; reading chunk by chunk would hand the file one packet's worth at a time.
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut bytes = 0_u64;
    while let Some(count) = recv.read(&mut buffer).await.context("receive file data")? {
        file.write_all(&buffer[..count])
            .await
            .context("write download file")?;
        bytes += count as u64;
    }
    file.flush().await.context("flush download file")?;
    tracing::info!(file = request.filename, bytes, "download complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_urls_preserve_authority_and_safe_paths() {
        let parsed =
            requests("https://localhost:4443/nested/a.bin https://localhost:4443/b.bin").unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].port, 4443);
        assert_eq!(parsed[0].target, "/nested/a.bin");
        assert_eq!(parsed[0].filename, "a.bin");
        assert_eq!(requests("https://[::1]:4443/a").unwrap()[0].host, "::1");
    }

    #[test]
    fn invalid_request_batches_are_rejected() {
        for input in [
            "",
            "http://localhost/a",
            "https://localhost/../a",
            "https://localhost/%2e%2e/a",
            "https://localhost/a?b",
            "https://user@localhost/a",
            "https://localhost/a https://other/b",
            "https://localhost/a https://localhost/nested/a",
        ] {
            assert!(requests(input).is_err(), "accepted {input}");
        }
    }
}
