use std::convert::Infallible;

use radix_trie::Trie;

use rama_core::{Service, error::ErrorContext, service::BoxService};
use rama_http::{Body, Request, Response, service::web::response::IntoResponse};
use rama_utils::str::arcstr::arcstr;

use crate::{Status, server::NamedService};

/// A gRPC [`Service`] router.
#[derive(Debug, Default, Clone)]
pub struct GrpcRouter {
    services: Trie<&'static str, BoxService<Request, Response, Infallible>>,
}

impl GrpcRouter {
    /// Create a new [`GrpcRouter`]
    #[inline(always)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a gRPC [`NamedService`] this this [`GrpcRouter`].
    #[inline(always)]
    #[must_use]
    pub fn with_service<S>(mut self, svc: S) -> Self
    where
        S: Service<Request, Output = Response, Error = Infallible> + NamedService,
    {
        self.services.insert(S::NAME, svc.boxed());
        self
    }

    /// Add a gRPC [`NamedService`] this this [`GrpcRouter`].
    #[inline(always)]
    pub fn set_service<S>(&mut self, svc: S) -> &mut Self
    where
        S: Service<Request, Output = Response, Error = Infallible> + NamedService,
    {
        self.services.insert(S::NAME, svc.boxed());
        self
    }
}

impl Service<Request> for GrpcRouter {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let Some(svc_name) = req.uri().path().split('/').nth(1) else {
            return Ok(
                Status::unimplemented(arcstr!("service name not found in uri path"))
                    .try_into_http::<Body>()
                    .into_box_error()
                    .into_response(),
            );
        };

        let Some(svc) = self.services.get(svc_name) else {
            return Ok(Status::unimplemented(format!(
                "no gRPC service found for name '{svc_name}'"
            ))
            .try_into_http::<Body>()
            .into_box_error()
            .into_response());
        };

        svc.serve(req).await
    }
}
