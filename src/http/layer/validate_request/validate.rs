use crate::{
    http::{Request, Response},
    service::Context,
};
use std::future::Future;

/// Trait for validating requests.
pub trait ValidateRequest<S, B>: Send + Sync + 'static {
    /// The body type used for responses to unvalidated requests.
    type ResponseBody;

    /// Validate the request.
    ///
    /// If `Ok(())` is returned then the request is allowed through, otherwise not.
    fn validate(
        &self,
        ctx: Context<S>,
        request: Request<B>,
    ) -> impl Future<Output = Result<(Context<S>, Request<B>), Response<Self::ResponseBody>>> + Send + '_;
}
