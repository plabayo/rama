//! HTTP/3 dispatch uses the same body limits, tracing and application services as H1/H2.

use super::HttpServeResult;
use crate::h3::{clean_close, completed, drain, drained_within};
use rama_core::{
    Service,
    extensions::{ExtensionsRef, Ingress},
    futures::{StreamExt, stream::FuturesUnordered},
    graceful::ShutdownGuard,
    telemetry::tracing,
};
use rama_http::service::web::response::IntoResponse;
use rama_http_core::{
    h3::{connection::Config, qpack::ErrorScope, server, transport},
    service::RamaHttpService,
};
use rama_http_types::Request;
use std::convert::Infallible;

pub(super) async fn serve<C, S, R>(
    conn: C,
    config: Config,
    guard: Option<ShutdownGuard>,
    service: S,
) -> HttpServeResult
where
    C: transport::Connection,
    S: Service<Request, Output = R, Error = Infallible> + Clone,
    R: IntoResponse + Send + 'static,
{
    let extensions = conn.extensions().clone();
    let close_timeout = config.close_drain_timeout;
    let goaway_timeout = config.goaway_drain_timeout;
    let (mut connection, driver) = server::handshake(conn, config)?;
    let driver = driver.run();
    let mut driver = std::pin::pin!(driver);
    let cancelled = async {
        match guard.as_ref() {
            Some(guard) => guard.cancelled().await,
            None => std::future::pending().await,
        }
    };
    let mut cancelled = std::pin::pin!(cancelled);
    let mut requests = FuturesUnordered::new();
    let service = RamaHttpService::new(service);
    let mut draining = false;
    loop {
        tokio::select! {
            result = &mut driver => return drain(std::future::ready(result), &mut requests, close_timeout, (!draining).then_some(&mut cancelled)).await,
            _ = &mut cancelled, if !draining => {
                connection.shutdown()?;
                draining = true;
            }
            accepted = connection.accept(), if !draining => {
                let stream = match accepted {
                    Ok(stream) => stream,
                    // Keep accepted work alive while the driver files received input.
                    Err(error) if clean_close(error) => return drain(driver, &mut requests, close_timeout, (!draining).then_some(&mut cancelled)).await,
                    Err(error) => return Err(error.into()),
                };
                let service = service.clone();
                let ingress = extensions.clone();
                requests.push(async move {
                    let (request, response) = stream.resolve().await?;
                    request.extensions().insert(Ingress(ingress));
                    let result = service.serve(request).await;
                    let output = match result {
                        Ok(output) => output,
                        Err(never) => match never {},
                    };
                    response.send_response(output).await
                });
            }
            result = requests.next(), if !requests.is_empty() => {
                if let Some(Err(error)) = result {
                    if clean_close(error) {
                        return drain(driver, &mut requests, close_timeout, (!draining).then_some(&mut cancelled)).await;
                    }
                    if error.scope() == ErrorScope::Connection {
                        return completed(Err(error));
                    }
                    tracing::debug!(%error, "HTTP/3 request stream failed");
                }
            }
        }
        if draining && requests.is_empty() {
            return tokio::select! {
                result = &mut driver => drain(std::future::ready(result), &mut requests, close_timeout, None::<std::future::Pending<()>>).await,
                result = drained_within(connection.drained(), goaway_timeout) => match result {
                    Err(error) if clean_close(error) => drain(driver, &mut requests, close_timeout, None::<std::future::Pending<()>>).await,
                    result => completed(result),
                },
            };
        }
    }
}
