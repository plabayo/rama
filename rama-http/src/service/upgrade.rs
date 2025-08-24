//! Service that redirects all HTTP requests to HTTPS

use crate::Request;
use crate::{Response, header};
use crate::service::web::response::IntoResponse;
use crate::StatusCode;
use rama_core::{Context, Service, telemetry::tracing};
use rama_net::http::RequestContext; 
use std::{convert::Infallible, fmt};

/// Service that redirects all HTTP requests to HTTPS
pub struct Upgrade;

impl<State, Body> Service<State, Request<Body>> for Upgrade
where
    State: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let req_ctx: &mut RequestContext =
            match ctx.get_or_try_insert_with_ctx(|ctx| (ctx, &req).try_into()) {
                Ok(req_ctx) => req_ctx,
                Err(err) => {
                    tracing::error!(
                        "failed to get RequestContext for insecure incoming req: {err}"
                    );
                    return Ok(StatusCode::BAD_GATEWAY.into_response());
                }
            };
        let host = &req_ctx.authority.host();
        let paq = req
            .uri()
            .path_and_query()
            .map(|paq| paq.as_str())
            .unwrap_or("/");
        let loc = format!("https://{host}{paq}");

        Ok(([(header::LOCATION, loc)], StatusCode::PERMANENT_REDIRECT).into_response())
    }
}

impl fmt::Debug for Upgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upgrade")
            .finish()
    }
}

impl Clone for Upgrade {
    fn clone(&self) -> Self {
        Self
    }
}