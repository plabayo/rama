//! Service that redirects all HTTP requests to HTTPS

use crate::Request;
use crate::StatusCode;
use crate::service::web::response::IntoResponse;
use crate::{Response, header};
use rama_core::{Service, telemetry::tracing};
use rama_net::{Protocol, http::RequestContext};
use rama_utils::macros::generate_set_and_with;
use std::convert::Infallible;

/// Service that redirects all HTTP requests to HTTPS
#[derive(Debug, Clone)]
pub struct Upgrade {
    status_code: StatusCode,
}

impl Upgrade {
    generate_set_and_with! {
        /// Set status_code in the Upgrade struct
        pub fn status_code(mut self, status_code: StatusCode) -> Self {
            self.status_code = status_code;
            self
        }
    }
}

impl<Body> Service<Request<Body>> for Upgrade
where
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Response, Self::Error> {
        let req_ctx = match RequestContext::try_from(&req) {
            Ok(req_ctx) => req_ctx,
            Err(err) => {
                tracing::error!("failed to get RequestContext for insecure incoming req: {err}");
                return Ok(StatusCode::BAD_GATEWAY.into_response());
            }
        };
        let host = &req_ctx.authority.host();
        let upgraded_protocol = match req_ctx.protocol {
            Protocol::HTTP => Protocol::HTTPS.as_str(),
            Protocol::WS => Protocol::WSS.as_str(),
            _ => {
                tracing::error!("unexpected protocol: {}", req_ctx.protocol);
                return Ok(StatusCode::BAD_GATEWAY.into_response());
            }
        };
        let paq = req
            .uri()
            .path_and_query()
            .map(|paq| paq.as_str())
            .unwrap_or("/");
        let loc = format!("{upgraded_protocol}://{host}{paq}");

        Ok(([(header::LOCATION, loc)], self.status_code).into_response())
    }
}

impl Default for Upgrade {
    fn default() -> Self {
        Self {
            status_code: StatusCode::PERMANENT_REDIRECT,
        }
    }
}
