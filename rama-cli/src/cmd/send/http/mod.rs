use rama::{
    Service,
    error::{BoxError, ErrorContext as _, ErrorExt, extra::OpaqueError},
    utils::collections::NonEmptySmallVec,
};

use std::time::Duration;

use crate::utils::error::ErrorWithExitCode;

use super::SendCommand;

pub mod arg;

mod client;
mod feed;
mod request;
mod trace;
mod ws;

pub async fn run(cfg: SendCommand, is_ws: bool) -> Result<(), BoxError> {
    trace::init_logger(cfg.trace.clone(), is_ws)?;

    if let Some(max_time) = cfg.max_time
        && max_time > 0.
    {
        tokio::time::timeout(Duration::from_secs_f64(max_time), run_inner(&cfg, is_ws))
            .await
            .context("max timeout")?
    } else {
        run_inner(&cfg, is_ws).await
    }
    .context("send command")?;

    Ok(())
}

pub async fn run_inner(cfg: &SendCommand, is_ws: bool) -> Result<(), BoxError> {
    // The feed reader only applies to plain HTTP responses going to an
    // interactive terminal; ws has its own TUI and redirected/file output is
    // left untouched.
    let feed_tui = !is_ws && feed::tui_gate_open(cfg);

    let https_client = client::new(cfg, feed_tui).await?;
    let request = request::build(cfg, is_ws).await?;

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

        if cfg.fail {
            // supposed to work like curl's --fail-with-body
            let code = resp.status();
            if code.is_client_error() || code.is_server_error() {
                return Err(Box::new(ErrorWithExitCode {
                    error: OpaqueError::from_static_str("http failure status code")
                        .context_field("code", code),
                    code: 22,
                }));
            }
        }

        // The body logger leaves feed responses unwritten and tags them so we
        // can hand the (still-streaming) body to the reader here.
        if let Some(candidate) = feed::candidate_of(&resp) {
            feed::run(resp, candidate).await?;
        }
    }

    Ok(())
}
