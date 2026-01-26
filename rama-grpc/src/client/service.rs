use rama_core::{Service, error::BoxError};
use rama_http_types::StreamingBody;

/// Definition of the gRPC trait alias for [`Service`].
///
/// This trait enforces that all rama services provided to [`Grpc`] implements
/// the correct traits.
///
/// [`Grpc`]: ../client/struct.Grpc.html
pub trait GrpcService<ReqBody>: Send + Sync + 'static {
    /// Responses body given by the service.
    type ResponseBody: StreamingBody;
    /// Errors produced by the service.
    type Error: Into<BoxError>;

    /// Process the request and return the response asynchronously.
    ///
    /// Reference [`Service::serve`].
    fn serve(
        &self,
        request: rama_http_types::Request<ReqBody>,
    ) -> impl Future<Output = Result<rama_http_types::Response<Self::ResponseBody>, Self::Error>>;
}

impl<T, ReqBody, ResBody> GrpcService<ReqBody> for T
where
    T: Service<
            rama_http_types::Request<ReqBody>,
            Output = rama_http_types::Response<ResBody>,
            Error: Into<BoxError>,
        >,
    ResBody: StreamingBody<Error: Into<BoxError>>,
{
    type ResponseBody = ResBody;
    type Error = T::Error;

    #[inline(always)]
    fn serve(
        &self,
        request: rama_http_types::Request<ReqBody>,
    ) -> impl Future<Output = Result<rama_http_types::Response<Self::ResponseBody>, Self::Error>>
    {
        Service::serve(self, request)
    }
}
