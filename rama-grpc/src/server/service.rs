use rama_core::{Service, futures::Stream};

use crate::{Request, Response, Status, Streaming};

/// A specialization of [`Service`].
///
/// Existing [`Service`] implementations with the correct form will
/// automatically implement `UnaryService`.
pub trait UnaryService<R>: Send + Sync + 'static {
    /// Protobuf response message type
    type Response;

    /// Serve a the grpc request and return
    /// a response, or otherwise an error.
    fn serve(
        &self,
        request: Request<R>,
    ) -> impl Future<Output = Result<Response<Self::Response>, Status>>;
}

impl<T, M1, M2> UnaryService<M1> for T
where
    T: Service<Request<M1>, Output = Response<M2>, Error = crate::Status>,
{
    type Response = M2;

    #[inline(always)]
    fn serve(
        &self,
        request: Request<M1>,
    ) -> impl Future<Output = Result<Response<Self::Response>, Status>> {
        Service::serve(self, request)
    }
}

/// A specialization of [`Service`].
///
/// Existing [`Service`] implementations with the correct form will
/// automatically implement `ServerStreamingService`.
pub trait ServerStreamingService<R>: Send + Sync + 'static {
    /// Protobuf response message type
    type Response;

    /// Stream of outbound response messages
    type ResponseStream: Stream<Item = Result<Self::Response, Status>>;

    /// Serve a the grpc request and return
    /// a response stream, or otherwise an error.
    fn serve(
        &self,
        request: Request<R>,
    ) -> impl Future<Output = Result<Response<Self::ResponseStream>, Status>>;
}

impl<T, S, M1, M2> ServerStreamingService<M1> for T
where
    T: Service<Request<M1>, Output = Response<S>, Error = crate::Status>,
    S: Stream<Item = Result<M2, crate::Status>>,
{
    type Response = M2;
    type ResponseStream = S;

    #[inline(always)]
    fn serve(
        &self,
        request: Request<M1>,
    ) -> impl Future<Output = Result<Response<Self::ResponseStream>, Status>> {
        Service::serve(self, request)
    }
}

/// A specialization of [`Service`].
///
/// Existing [`Service`] implementations with the correct form will
/// automatically implement `ClientStreamingService`.
pub trait ClientStreamingService<R>: Send + Sync + 'static {
    /// Protobuf response message type
    type Response;

    /// Serve a the grpc streaming request and return
    /// a response, or otherwise an error.
    fn serve(
        &self,
        request: Request<Streaming<R>>,
    ) -> impl Future<Output = Result<Response<Self::Response>, Status>>;
}

impl<T, M1, M2> ClientStreamingService<M1> for T
where
    T: Service<Request<Streaming<M1>>, Output = Response<M2>, Error = crate::Status>,
{
    type Response = M2;

    #[inline(always)]
    fn serve(
        &self,
        request: Request<Streaming<M1>>,
    ) -> impl Future<Output = Result<Response<Self::Response>, Status>> {
        Service::serve(self, request)
    }
}

/// A specialization of [`Service`].
///
/// Existing [`Service`] implementations with the correct form will
/// automatically implement `StreamingService`.
pub trait StreamingService<R>: Send + Sync + 'static {
    /// Protobuf response message type
    type Response;

    /// Stream of outbound response messages
    type ResponseStream: Stream<Item = Result<Self::Response, Status>>;

    /// Serve a the grpc streaming request and return
    /// a streaming response, or otherwise an error.
    fn serve(
        &self,
        request: Request<Streaming<R>>,
    ) -> impl Future<Output = Result<Response<Self::ResponseStream>, Status>>;
}

impl<T, S, M1, M2> StreamingService<M1> for T
where
    T: Service<Request<Streaming<M1>>, Output = Response<S>, Error = crate::Status>,
    S: Stream<Item = Result<M2, crate::Status>>,
{
    type Response = M2;
    type ResponseStream = S;

    #[inline(always)]
    fn serve(
        &self,
        request: Request<Streaming<M1>>,
    ) -> impl Future<Output = Result<Response<Self::ResponseStream>, Status>> {
        Service::serve(self, request)
    }
}
