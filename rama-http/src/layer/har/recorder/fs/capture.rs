//! Capture live HTTP and WebSocket traffic into private file artifacts.

use std::path::PathBuf;

use rama_core::error::{BoxError, ErrorContext as _};
use rama_utils::fs::{TempPath, TempPathCleanup};
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
    sync::{mpsc, oneshot, watch},
    time::Instant,
};

use crate::{
    BodyCaptureEvent, CaptureOutcome,
    layer::har::{
        recorder::{
            BodyCaptureStream, HttpRequestCapture, HttpResponseCapture, WebSocketCapture,
            WebSocketCaptureCloseHandle, WebSocketCaptureRecorder,
        },
        spec,
        stream::write_web_socket_message,
    },
};

use super::{
    BodyArtifact, CaptureWorkerMessage, FileWebSocketCaptureRecorder, RecordedWebSocketMessage,
    WebSocketArtifact, WebSocketCaptureCompletion, build_entry_artifact, create_temp_file,
    elapsed_millis,
};

impl WebSocketCaptureRecorder for FileWebSocketCaptureRecorder {
    async fn record(&self, message: spec::WebSocketMessage) -> Result<(), BoxError> {
        self.sender
            .send(RecordedWebSocketMessage {
                message,
                observed_at: Instant::now(),
            })
            .await
            .map_err(|err| std::io::Error::other(err).into())
    }
}

pub(super) async fn create_web_socket_capture(
    dir: PathBuf,
    temp_cleanup: TempPathCleanup,
) -> Result<
    (
        WebSocketCapture,
        WebSocketCaptureCompletion,
        WebSocketCaptureCloseHandle,
    ),
    BoxError,
> {
    let (path, file) = create_temp_file(dir, "websocket", temp_cleanup).await?;
    let (sender, receiver) = mpsc::channel(1);
    let (closed_at, closed_at_rx) = watch::channel(None);
    let capture = WebSocketCapture::new(FileWebSocketCaptureRecorder { sender }, {
        move || {
            closed_at.send_replace(Some(Instant::now()));
        }
    });
    let closer = capture.close_handle();
    let (done, completion) = oneshot::channel();
    rama_core::rt::spawn(async move {
        _ = done.send(write_web_socket_capture(file, path, receiver, closed_at_rx).await);
    });
    Ok((capture, completion, closer))
}

pub(super) async fn write_web_socket_capture(
    file: File,
    path: TempPath,
    mut receiver: mpsc::Receiver<RecordedWebSocketMessage>,
    mut closed_at: watch::Receiver<Option<Instant>>,
) -> Result<WebSocketArtifact, BoxError> {
    let mut writer = BufWriter::new(file);
    let mut has_messages = false;
    let mut cancelled = false;
    let mut last_activity_at = None;
    loop {
        let message = if cancelled {
            receiver.recv().await
        } else {
            tokio::select! {
                message = receiver.recv() => message,
                changed = closed_at.changed() => {
                    if changed.is_err() || closed_at.borrow().is_some() {
                        receiver.close();
                        cancelled = true;
                    }
                    continue;
                }
            }
        };
        let Some(message) = message else {
            break;
        };
        if has_messages {
            writer
                .write_all(b",")
                .await
                .context("write WebSocket HAR separator")?;
        }
        let spec::WebSocketMessage {
            r#type,
            time,
            opcode,
            data,
        } = &message.message;
        write_web_socket_message(&mut writer, *r#type, *time, *opcode, data.as_bytes(), true)
            .await
            .context("write WebSocket HAR message")?;
        has_messages = true;
        last_activity_at = Some(message.observed_at);
    }
    writer
        .flush()
        .await
        .context("flush WebSocket HAR artifact")?;
    drop(writer);
    Ok(WebSocketArtifact {
        path,
        last_activity_at,
        closed_at: closed_at.borrow().unwrap_or_else(Instant::now),
    })
}

pub(super) async fn capture_http_entry(
    request: HttpRequestCapture,
    mut rx: mpsc::Receiver<CaptureWorkerMessage>,
    dir: PathBuf,
    temp_cleanup: TempPathCleanup,
    mut cancel: watch::Receiver<bool>,
    web_socket: Option<(WebSocketCaptureCloseHandle, WebSocketCaptureCompletion)>,
) -> Result<TempPath, BoxError> {
    let HttpRequestCapture {
        started_date_time,
        begin,
        request,
        body_mime_type,
        body: request_body,
        web_socket: _,
    } = request;
    let request_capture = spool_body(
        request_body,
        dir.clone(),
        temp_cleanup.clone(),
        cancel.clone(),
    );
    tokio::pin!(request_capture);
    let mut request_artifact = None;

    let command = loop {
        tokio::select! {
            biased;
            result = &mut request_capture, if request_artifact.is_none() => {
                request_artifact = Some(result?);
            }
            command = rx.recv() => break command.unwrap_or(CaptureWorkerMessage::RequestOnly),
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break CaptureWorkerMessage::RequestOnly;
                }
            }
        }
    };

    let is_web_socket = web_socket.is_some();
    let (request_artifact, response, mut completed_at) = match command {
        CaptureWorkerMessage::Response {
            response,
            headers_at,
        } => {
            let HttpResponseCapture { response, body } = *response;
            let response_capture =
                spool_body(body, dir.clone(), temp_cleanup.clone(), cancel.clone());
            let (request_artifact, response_artifact) =
                if let Some(request_artifact) = request_artifact {
                    let response_artifact = response_capture.await?;
                    (request_artifact, response_artifact)
                } else {
                    let (request_artifact, response_artifact) =
                        tokio::join!(&mut request_capture, response_capture);
                    (request_artifact?, response_artifact?)
                };
            let completed_at = if is_web_socket {
                headers_at
            } else {
                request_artifact
                    .finished_at
                    .max(response_artifact.finished_at)
            };
            (
                request_artifact,
                Some((response, response_artifact)),
                completed_at,
            )
        }
        CaptureWorkerMessage::RequestOnly => {
            let request_artifact = match request_artifact {
                Some(artifact) => artifact,
                None => request_capture.await?,
            };
            let completed_at = request_artifact.finished_at;
            (request_artifact, None, completed_at)
        }
    };

    let web_socket = match web_socket {
        Some((closer, completion)) => {
            let (artifact, stopped) =
                await_web_socket_capture(closer, completion, cancel.clone()).await?;
            completed_at = if stopped {
                artifact.last_activity_at.unwrap_or(completed_at)
            } else {
                artifact.closed_at.max(completed_at)
            };
            Some(artifact)
        }
        None => None,
    };

    build_entry_artifact(
        dir,
        started_date_time,
        elapsed_millis(begin, completed_at),
        request,
        body_mime_type,
        request_artifact,
        response,
        web_socket,
        temp_cleanup,
    )
    .await
}

async fn await_web_socket_capture(
    closer: WebSocketCaptureCloseHandle,
    mut completion: WebSocketCaptureCompletion,
    mut cancel: watch::Receiver<bool>,
) -> Result<(WebSocketArtifact, bool), BoxError> {
    if *cancel.borrow() {
        closer.close();
    } else {
        tokio::select! {
            biased;
            result = &mut completion => {
                return result
                    .context("WebSocket HAR capture completion dropped")?
                    .map(|artifact| (artifact, false));
            },
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    closer.close();
                }
            }
        }
    }
    completion
        .await
        .context("WebSocket HAR capture completion dropped")?
        .map(|artifact| (artifact, true))
}

async fn spool_body(
    mut stream: BodyCaptureStream,
    dir: PathBuf,
    temp_cleanup: TempPathCleanup,
    mut cancel: watch::Receiver<bool>,
) -> Result<BodyArtifact, BoxError> {
    let (path, file) = create_temp_file(dir, "body", temp_cleanup).await?;
    let mut file = BufWriter::new(file);
    let mut size = 0_i64;
    let outcome = loop {
        if *cancel.borrow() {
            if let Some(BodyCaptureEvent::Frame(frame)) = stream.try_next_event()
                && let Ok(data) = frame.into_data()
            {
                file.write_all(&data)
                    .await
                    .context("spool accepted HAR body frame during stop")?;
                size = size.saturating_add(i64::try_from(data.len()).unwrap_or(i64::MAX));
            }
            break CaptureOutcome::Aborted;
        }
        tokio::select! {
            biased;
            event = stream.next_event() => match event {
                Some(BodyCaptureEvent::Frame(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        file.write_all(&data).await.context("spool HAR body frame")?;
                        size = size.saturating_add(i64::try_from(data.len()).unwrap_or(i64::MAX));
                    }
                }
                Some(BodyCaptureEvent::End(outcome)) => break outcome,
                None => break CaptureOutcome::Aborted,
            },
            _ = cancel.changed() => {}
        }
    };
    let finished_at = Instant::now();
    file.flush().await.context("flush HAR body artifact")?;
    drop(file);
    Ok(BodyArtifact {
        path,
        size,
        outcome,
        finished_at,
    })
}
