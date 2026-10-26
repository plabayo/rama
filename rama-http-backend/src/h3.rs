//! Shared HTTP/3 dispatch completion: received input still belongs to accepted work.

use rama_core::{
    error::BoxError,
    futures::{StreamExt as _, stream::FuturesUnordered, try_zip},
    telemetry::tracing,
};
use rama_http_core::h3::{Error, qpack::ErrorScope};
use rama_http_types::proto::h3::Code;
use std::{io, time::Duration};

pub(crate) fn clean_close(error: Error) -> bool {
    error.scope() == ErrorScope::Connection && error.code() == Code::H3_NO_ERROR
}

pub(crate) fn completed(result: Result<(), Error>) -> Result<(), BoxError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if clean_close(error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Poll the driver and accepted requests together after transport closure. A service
/// can own its tunnel inside its request future, so awaiting the driver alone loses input.
pub(crate) async fn drain<F>(
    driver: impl Future<Output = Result<(), Error>>,
    requests: &mut FuturesUnordered<F>,
    timeout: Duration,
    cancelled: Option<impl Future<Output = ()>>,
) -> Result<(), BoxError>
where
    F: Future<Output = Result<(), Error>>,
{
    let work = try_zip(async { completed(driver.await) }, async {
        while let Some(result) = requests.next().await {
            if let Err(error) = result {
                if error.scope() == ErrorScope::Connection {
                    completed(Err(error))?;
                } else {
                    tracing::debug!(%error, "HTTP/3 request ended during connection drain");
                }
            }
        }
        Ok(())
    });
    tokio::select! {
        result = tokio::time::timeout(timeout, work) => {
            result.map_err(|_elapsed| io::Error::new(io::ErrorKind::TimedOut, "HTTP/3 connection drain timeout"))??;
            Ok(())
        }
        () = async {
            match cancelled {
                Some(cancelled) => cancelled.await,
                None => std::future::pending().await,
            }
        } => Err(io::Error::new(io::ErrorKind::Interrupted, "HTTP/3 connection drain cancelled").into()),
    }
}
