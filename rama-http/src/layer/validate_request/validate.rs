use crate::{Request, Response};

/// Trait for validating requests.
pub trait ValidateRequest<B>: Send + Sync + 'static {
    /// The body type used for responses to unvalidated requests.
    type ResponseBody;

    /// Validate the request.
    ///
    /// If `Ok(())` is returned then the request is allowed through, otherwise not.
    fn validate(
        &self,
        request: Request<B>,
    ) -> impl Future<Output = Result<Request<B>, Response<Self::ResponseBody>>> + Send + '_;
}
