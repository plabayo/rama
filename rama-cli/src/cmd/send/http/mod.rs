use rama::{
    Service,
    error::{BoxError, ErrorContext as _, OpaqueError},
    utils::collections::NonEmptySmallVec,
};

use std::time::Duration;

use crate::utils::error::ErrorWithExitCode;

use super::SendCommand;

pub mod arg;

mod client;
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
    .map_err(OpaqueError::from_boxed)
    .context("send command")?;

    Ok(())
}

pub async fn run_inner(cfg: &SendCommand, is_ws: bool) -> Result<(), BoxError> {
    let https_client = client::new(cfg).await?;
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
                    error: OpaqueError::from_display("http failure status code: {code:?}")
                        .into_boxed(),
                    code: 22,
                }));
            }
        }
    }

    Ok(())
}
