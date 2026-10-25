use rama::{
    Service,
    error::{BoxError, BoxErrorExt, ErrorContext as _, ErrorExt},
    extensions::{Extension, ExtensionsRef as _},
    graceful::{self, Shutdown},
    http::{
        HeaderValue, StatusCode,
        body::util::BodyExt as _,
        layer::har::recorder::{FileRecorder, Recorder as _},
    },
    rt::Executor,
    telemetry::tracing,
    utils::collections::NonEmptySmallVec,
};

use std::time::Duration;

use crate::utils::error::ErrorWithExitCode;

use super::{RequestArgs, SendCommand};

pub mod arg;

mod client;
mod feed;
mod request;
mod trace;
mod ws;

/// A request whose response is read but not written to command output.
#[derive(Debug, Clone, Copy, Extension)]
pub(super) struct DiscardedResponse;

/// A request followed by another `--next` segment; only the last may use the feed reader.
#[derive(Debug, Clone, Copy, Extension)]
pub(super) struct PrecedingSegment;

/// The request's own `--user` credential.
#[derive(Debug, Clone, Extension)]
pub(super) struct RequestAuthorization(HeaderValue);

const CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn run(
    cfg: SendCommand,
    following: Vec<RequestArgs>,
    is_ws: bool,
) -> Result<(), BoxError> {
    trace::init_logger(cfg.trace.clone(), is_ws)?;

    run_inner(&cfg, &following, is_ws)
        .await
        .context("send command")?;

    Ok(())
}

/// Send the first request and each `--next` request in order; the last may be a WebSocket.
pub(super) async fn run_inner(
    cfg: &SendCommand,
    following: &[RequestArgs],
    is_ws: bool,
) -> Result<(), BoxError> {
    // The feed reader only applies to plain HTTP responses going to an
    // interactive terminal; ws has its own TUI and redirected/file output is
    // left untouched.
    let feed_tui = !is_ws && feed::tui_gate_open(cfg);

    let har_recorder = cfg
        .har
        .as_ref()
        .map(|path| FileRecorder::try_new_at(path.clone()))
        .transpose()?;
    let (finished, completed) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = completed => {},
            _ = graceful::default_signal() => {},
        }
    });
    let guard = shutdown.guard();
    let executor = Executor::graceful(shutdown.guard());
    // Connections to MASQUE proxies close last: the connections tunneled through them close first.
    let (proxy_finished, proxy_completed) = tokio::sync::oneshot::channel::<()>();
    let proxy_shutdown = Shutdown::new(async move {
        _ = proxy_completed.await;
    });
    let proxy_executor = Executor::graceful(proxy_shutdown.guard());
    let exchange = async {
        // Every request is built and validated before any transport I/O.
        let mut requests = Vec::with_capacity(following.len() + 1);
        requests.push(request::build(cfg, &cfg.req, is_ws && following.is_empty()).await?);
        for (index, req) in following.iter().enumerate() {
            let last = index + 1 == following.len();
            let request = request::build(cfg, req, is_ws && last).await?;
            // Its own pins only, not the first request's client-wide ones.
            request.extensions().insert(request::variant_pins(req));
            requests.push(request);
        }
        let request = requests.pop().context("at least one request")?;
        let preceding = requests;
        let https_client = client::new(
            cfg,
            feed_tui,
            har_recorder.clone(),
            executor.clone(),
            proxy_executor.clone(),
        )
        .await?;
        for request in preceding {
            request.extensions().insert(PrecedingSegment);
            if cfg.last_response_only {
                request.extensions().insert(DiscardedResponse);
            }
            let resp = https_client.serve(request).await?;
            fail_on_error_status(cfg, resp.status())?;
            // Drain on this connection so the next request can reuse it.
            resp.into_body()
                .collect()
                .await
                .context("read preceding response body")?;
        }

        if is_ws {
            ws::run(
                request,
                https_client,
                cfg.subprotocol
                    .clone()
                    .map(|p| {
                        NonEmptySmallVec::from_slice(&p)
                            .context("create non-empty-vec of sub protocols")
                    })
                    .transpose()?,
            )
            .await?;
        } else {
            let resp = https_client.serve(request).await?;
            fail_on_error_status(cfg, resp.status())?;

            // The body logger leaves feed responses unwritten and tags them so we
            // can hand the (still-streaming) body to the reader here.
            if let Some(candidate) = feed::candidate_of(&resp) {
                feed::run(resp, candidate).await?;
            }
        }

        Ok::<_, BoxError>(())
    };

    // Keep the command-sized exchange off worker stacks and out of timeout wrappers.
    let exchange = Box::pin(exchange);
    let exchange = async {
        tokio::select! {
            result = exchange => result,
            _ = guard.cancelled() => Err(BoxError::from_static_str("request cancelled")),
        }
    };
    let result = if let Some(max_time) = cfg.max_time
        && max_time > 0.
    {
        match tokio::time::timeout(Duration::from_secs_f64(max_time), exchange).await {
            Ok(result) => result,
            Err(err) => Err(err.context("max timeout")),
        }
    } else {
        exchange.await
    };

    drop(executor);
    drop(proxy_executor);
    drop(guard);
    finished.send(()).unwrap_or_default();
    drain_client(shutdown).await;
    proxy_finished.send(()).unwrap_or_default();
    drain_client(proxy_shutdown).await;
    if let Some(recorder) = &har_recorder {
        recorder.stop_record().await;
    }
    if result.is_ok()
        && let Some(path) = &cfg.har
    {
        let metadata = tokio::fs::metadata(path)
            .await
            .context("HAR output file was not created")?;
        if !metadata.is_file() {
            return Err(BoxError::from_static_str(
                "HAR output path is not a regular file",
            ));
        }
    }

    result
}

/// Like curl's --fail-with-body: error statuses fail the command with exit code 22.
fn fail_on_error_status(cfg: &SendCommand, code: StatusCode) -> Result<(), BoxError> {
    if cfg.fail && (code.is_client_error() || code.is_server_error()) {
        return Err(Box::new(ErrorWithExitCode {
            error: BoxError::from_static_str("http failure status code")
                .context_field("code", code),
            code: 22,
        }));
    }
    Ok(())
}

async fn drain_client(shutdown: Shutdown) {
    // A successful exchange has already consumed or written its response.
    // Waiting for pooled connections to close is best-effort cleanup; it must
    // not change that exchange's outcome. HAR finalization is handled separately.
    if let Err(error) = shutdown.shutdown_with_limit(CLIENT_DRAIN_TIMEOUT).await {
        tracing::warn!(%error, "timed out draining HTTP client tasks");
    }
}

#[cfg(test)]
mod tests {
    use super::{CLIENT_DRAIN_TIMEOUT, drain_client};
    use rama::graceful::Shutdown;
    use tokio::time::Instant;

    #[tokio::test(start_paused = true)]
    async fn client_drain_timeout_is_bounded_best_effort_cleanup() {
        let shutdown = Shutdown::new(async {});
        let guard = shutdown.guard();
        let start = Instant::now();

        drain_client(shutdown).await;

        assert_eq!(start.elapsed(), CLIENT_DRAIN_TIMEOUT);
        guard.cancelled().await;
        drop(guard);
    }

    #[tokio::test(start_paused = true)]
    async fn client_drain_completes_without_waiting_for_timeout() {
        let shutdown = Shutdown::new(async {});
        let guard = shutdown.guard();
        let start = Instant::now();

        tokio::spawn(async move {
            guard.cancelled().await;
        });
        drain_client(shutdown).await;

        assert!(start.elapsed() < CLIENT_DRAIN_TIMEOUT);
    }
}
