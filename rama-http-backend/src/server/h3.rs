//! HTTP/3 dispatch uses the same body limits, tracing and application services as H1/H2.

use super::HttpServeResult;
use rama_core::{
    Service,
    extensions::{ExtensionsRef, Ingress},
    futures::{StreamExt, stream::FuturesUnordered},
    graceful::ShutdownGuard,
};
use rama_http::service::web::response::IntoResponse;
use rama_http_core::{
    h3::{connection::Config, qpack::ErrorScope, server},
    service::RamaHttpService,
};
use rama_http_types::Request;
use std::convert::Infallible;

pub(super) async fn serve<S, R>(
    input: rama_quic::Connection,
    config: Config,
    guard: Option<ShutdownGuard>,
    service: S,
) -> HttpServeResult
where
    S: Service<Request, Output = R, Error = Infallible> + Clone,
    R: IntoResponse + Send + 'static,
{
    let extensions = input.extensions().clone();
    let (mut connection, driver) = server::handshake(input, config)?;
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
            result = &mut driver => return result.map_err(Into::into),
            _ = &mut cancelled, if !draining => {
                connection.shutdown()?;
                draining = true;
            }
            accepted = connection.accept(), if !draining => {
                let stream = match accepted {
                    Ok(stream) => stream,
                    Err(error) if error.code() == rama_http_types::proto::h3::Code::H3_NO_ERROR => return Ok(()),
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
                if let Some(Err(error)) = result
                    && error.scope() == ErrorScope::Connection
                {
                    return Err(error.into());
                }
            }
        }
        if draining && requests.is_empty() {
            return tokio::select! {
                result = &mut driver => result.map_err(Into::into),
                result = connection.drained() => result.map_err(Into::into),
            };
        }
    }
}
