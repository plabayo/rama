use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, OpaqueError},
    http::{BodyExtractExt, Response},
};

use crate::utils::error::ErrorWithExitCode;

use super::SendCommand;

pub mod arg;

mod client;
mod request;
mod writer;

pub async fn run(cfg: SendCommand) -> Result<(), BoxError> {
    let resp = if let Some(max_time) = cfg.max_time
        && max_time > 0.
    {
        tokio::time::timeout(Duration::from_secs_f64(max_time), run_inner(&cfg))
            .await
            .context("max timeout")?
    } else {
        run_inner(&cfg).await
    }
    .map_err(OpaqueError::from_boxed)
    .context("send command")?;

    if cfg.fail {
        // supposed to work like curl's --fail-with-body
        let code = resp.status();
        if code.is_client_error() || code.is_server_error() {
            return Err(Box::new(ErrorWithExitCode {
                error: OpaqueError::from_display("http failure status code: {code:?}").into_boxed(),
                code: 22,
            }));
        }
    }

    // TOOD: delete, and instead use proper writers + file support
    let s = resp
        .try_into_string()
        .await
        .context("try collect response into string")?;
    println!("{s}");

    Ok(())
}

pub async fn run_inner(cfg: &SendCommand) -> Result<Response, BoxError> {
    let https_client = client::new(&cfg).await?;
    let request = request::build(&cfg)?;
    https_client.serve(request).await
}
