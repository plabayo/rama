//! Bounded HTTP/3 file transfers for the independent interop runner.

use crate::{
    BUFFER_SIZE, REQUEST_LIMIT, STREAM_LIMIT, client::Request as DownloadRequest, relative_path,
};
use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        core::h3::{Error as H3Error, client, connection::Config, qpack::ErrorScope, server},
        proto::h3::Code,
    },
    quic::Connection,
    rt::Executor,
    stream::io::ReaderStream,
    telemetry::tracing,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt as _, task::JoinSet};

fn clean_close(error: H3Error) -> bool {
    error.scope() == ErrorScope::Connection && error.code() == Code::H3_NO_ERROR
}

pub(crate) fn config() -> Config {
    Config {
        max_requests: STREAM_LIMIT,
        max_pushes: 0,
        ..Config::default()
    }
}

pub(crate) async fn download_batch(
    connection: Connection,
    requests: Vec<DownloadRequest>,
    directory: PathBuf,
    executor: Executor,
) -> Result<(), BoxError> {
    let (sender, driver) = client::handshake::<Body>(connection.clone(), config(), executor)?;
    let mut tasks: JoinSet<Result<(), BoxError>> = JoinSet::new();
    let batch = async {
        for request in requests {
            if tasks.len() >= STREAM_LIMIT {
                tasks
                    .join_next()
                    .await
                    .ok_or("download task missing")?
                    .context("download task failed")??;
            }
            let mut sender = sender.clone();
            let directory = directory.clone();
            tasks.spawn(async move {
                let host = if request.host.contains(':') {
                    format!("[{}]", request.host)
                } else {
                    request.host
                };
                let uri = format!("https://{host}:{}{}", request.port, request.target);
                let response = sender
                    .send_request(
                        Request::get(uri)
                            .version(Version::HTTP_3)
                            .body(Body::empty())?,
                    )
                    .await?;
                if response.status() != StatusCode::OK || response.version() != Version::HTTP_3 {
                    return Err(BoxError::from("HTTP/3 download status or version mismatch"));
                }
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory.join(&request.filename))
                    .await
                    .context("create download file")?;
                let mut body = response.into_body();
                let mut bytes = 0_u64;
                while let Some(frame) = body.frame().await {
                    let frame = frame?;
                    if let Some(data) = frame.data_ref() {
                        file.write_all(data).await.context("write download file")?;
                        bytes = bytes
                            .checked_add(data.len() as u64)
                            .ok_or("download byte count overflow")?;
                    }
                }
                file.flush().await.context("flush download file")?;
                tracing::info!(file = request.filename, bytes, "HTTP/3 download complete");
                Ok::<_, BoxError>(())
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.context("download task failed")??;
        }
        Ok::<_, BoxError>(())
    };
    let outcome = tokio::select! {
        result = batch => result,
        result = driver.run() => Err(result.err().map_or_else(|| BoxError::from("HTTP/3 driver ended before downloads"), BoxError::from)),
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    outcome
}

pub(crate) async fn serve_connection(
    connection: Connection,
    root: Arc<PathBuf>,
) -> Result<(), BoxError> {
    let (mut server, driver) = server::handshake(connection.clone(), config())?;
    let mut driver = std::pin::pin!(driver.run());
    let mut tasks: JoinSet<Result<(), BoxError>> = JoinSet::new();
    let outcome = async {
        loop {
            tokio::select! {
                result = &mut driver => {
                    match result { Ok(()) => {}, Err(error) if clean_close(error) => {}, Err(error) => return Err(BoxError::from(error)) }
                    break;
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result.ok_or("request task missing")?.context("request task failed")? {
                        if error.downcast_ref::<H3Error>().is_some_and(|error| clean_close(*error)) { break; }
                        return Err(error);
                    }
                }
                request = server.accept(), if tasks.len() < STREAM_LIMIT => {
                    let request = match request {
                        Ok(request) => request,
                        Err(error) => {
                            if clean_close(error) { break; }
                            return Err(BoxError::from(error));
                        }
                    };
                    let root = root.clone();
                    tasks.spawn(async move {
                        tokio::time::timeout(Duration::from_secs(180), async move {
                            let (request, response) = request.resolve().await?;
                            if request.method() != Method::GET { return Err(BoxError::from("only HTTP/3 GET is supported")); }
                            let target = request.uri().path_or_root();
                            if target.len() > REQUEST_LIMIT { return Err(BoxError::from("HTTP/3 request path exceeds limit")); }
                            let relative = relative_path(&target)?;
                            let path = tokio::fs::canonicalize(root.join(relative)).await.context("resolve requested file")?;
                            if !path.starts_with(root.as_path()) { return Err(BoxError::from("requested file escapes document root")); }
                            let file = tokio::fs::File::open(path).await.context("open requested file")?;
                            let metadata = file.metadata().await?;
                            if !metadata.is_file() { return Err(BoxError::from("requested path is not a regular file")); }
                            let body = Body::from_stream(ReaderStream::with_capacity(file, BUFFER_SIZE));
                            response.send_response(Response::builder().status(StatusCode::OK).header("content-length", metadata.len()).body(body)?).await?;
                            Ok::<_, BoxError>(())
                        }).await.context("HTTP/3 request timed out")?
                    });
                }
            }
        }
        Ok(())
    }.await;
    if outcome.is_err() {
        connection.close(0x102_u32, b"HTTP/3 request failed");
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    outcome
}
