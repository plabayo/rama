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

impl<B, V> ValidateRequest<B> for Option<V>
where
    B: Send + 'static,
    V: ValidateRequest<B>,
{
    type ResponseBody = V::ResponseBody;

    async fn validate(
        &self,
        request: Request<B>,
    ) -> Result<Request<B>, Response<Self::ResponseBody>> {
        match self {
            Some(validator) => validator.validate(request).await,
            None => Ok(request),
        }
    }
}
