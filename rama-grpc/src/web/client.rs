use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
};
use rama_http::{
    headers::{ContentType, HeaderMapExt as _},
    layer::version_adapter::adapt_request_version,
};
use rama_http_types::{Request, Response, Version};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use super::{GrpcWebCall, call::FrameLimits};
use crate::codec::MaxDecodingMessageSize;

/// Layer implementing the grpc-web protocol for clients.
///
/// A response message frame may carry at most the `max_decoding_message_size` of the
/// [`crate::client::Grpc`] client sending the request, or the
/// [`max_message_frame_size`](Self::with_max_message_frame_size) of this layer for a
/// request that does not come from one.
#[derive(Debug, Clone)]
pub struct GrpcWebClientLayer {
    frame_limits: FrameLimits,
}

impl Default for GrpcWebClientLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcWebClientLayer {
    /// Create a new grpc-web for clients layer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            frame_limits: FrameLimits::default(),
        }
    }

    generate_set_and_with! {
        /// Set the largest payload, in bytes, of a response message frame for a request
        /// that carries no maximum decoding message size of a [`crate::client::Grpc`] client.
        ///
        /// Defaults to 4 MiB.
        pub fn max_message_frame_size(mut self, max_message_frame_size: usize) -> Self {
            self.frame_limits.message = max_message_frame_size;
            self
        }
    }

    generate_set_and_with! {
        /// Set the largest payload, in bytes, of the response trailers frame.
        ///
        /// Defaults to 4 MiB.
        pub fn max_trailers_frame_size(mut self, max_trailers_frame_size: usize) -> Self {
            self.frame_limits.trailers = max_trailers_frame_size;
            self
        }
    }
}

impl<S> Layer<S> for GrpcWebClientLayer {
    type Service = GrpcWebClientService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcWebClientService {
            inner,
            frame_limits: self.frame_limits,
        }
    }
}

/// A [`Service`] that wraps some inner http service that will
/// coerce requests coming from `rama-grpc` clients into proper
/// `grpc-web` requests.
///
/// A response message frame may carry at most the `max_decoding_message_size` of the
/// [`crate::client::Grpc`] client sending the request, or the
/// [`max_message_frame_size`](Self::with_max_message_frame_size) of this service for a
/// request that does not come from one.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct GrpcWebClientService<S> {
    inner: S,
    frame_limits: FrameLimits,
}

impl<S> GrpcWebClientService<S> {
    define_inner_service_accessors!();

    /// Create a new grpc-web for clients service.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            frame_limits: FrameLimits::default(),
        }
    }

    generate_set_and_with! {
        /// Set the largest payload, in bytes, of a response message frame for a request
        /// that carries no maximum decoding message size of a [`crate::client::Grpc`] client.
        ///
        /// Defaults to 4 MiB.
        pub fn max_message_frame_size(mut self, max_message_frame_size: usize) -> Self {
            self.frame_limits.message = max_message_frame_size;
            self
        }
    }

    generate_set_and_with! {
        /// Set the largest payload, in bytes, of the response trailers frame.
        ///
        /// Defaults to 4 MiB.
        pub fn max_trailers_frame_size(mut self, max_trailers_frame_size: usize) -> Self {
            self.frame_limits.trailers = max_trailers_frame_size;
            self
        }
    }
}

impl<S, B1, B2> Service<Request<B1>> for GrpcWebClientService<S>
where
    S: Service<Request<GrpcWebCall<B1>>, Output = Response<B2>, Error: Into<BoxError>>,
    B1: Send + 'static,
    B2: Send + 'static,
{
    type Output = Response<GrpcWebCall<B2>>;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<B1>) -> Result<Self::Output, Self::Error> {
        adapt_request_version(&mut req, Version::HTTP_11)?;

        // Message frames follow the limit the client's codec applies once it decodes them.
        let mut frame_limits = self.frame_limits;
        if let Some(limit) = req.extensions().get_ref::<MaxDecodingMessageSize>() {
            frame_limits.message = limit.0;
        }

        req.headers_mut().typed_insert(ContentType::grpc_web());

        let req = req.map(GrpcWebCall::client_request);

        let resp = self.inner.serve(req).await.into_box_error()?;
        Ok(resp.map(|body| GrpcWebCall::client_response(body, frame_limits)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    use rama_core::{
        bytes::{Buf as _, BufMut as _, Bytes, BytesMut},
        extensions::{ExtensionsMut as _, NoExtensionsTransfer},
        service::service_fn,
        stream,
    };
    use rama_http_types::{Body, HeaderValue, body::util::BodyExt as _};
    use rama_net::uri::Uri;
    use rama_utils::octets::mib;

    use super::*;
    use crate::{
        Code, Status,
        client::Grpc,
        codec::{
            Codec, DEFAULT_MAX_RECV_MESSAGE_SIZE, DecodeBuf, Decoder, EncodeBuf, Encoder,
            MaxDecodingMessageSize,
        },
    };

    struct BytesCodec;

    impl Codec for BytesCodec {
        type Encode = Bytes;

        type Decode = Bytes;

        type Encoder = Self;

        type Decoder = Self;

        fn encoder(&mut self) -> Self {
            Self
        }

        fn decoder(&mut self) -> Self {
            Self
        }
    }

    impl Encoder for BytesCodec {
        type Item = Bytes;

        type Error = Status;

        fn encode(&mut self, item: Bytes, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
            dst.put_slice(&item);
            Ok(())
        }
    }

    impl Decoder for BytesCodec {
        type Item = Bytes;

        type Error = Status;

        fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
            Ok(Some(src.copy_to_bytes(src.remaining())))
        }
    }

    fn grpc_web_response(payload_len: usize, trailer_pad_len: usize) -> Bytes {
        let mut trailers = BytesMut::from(&b"grpc-status:0\r\n"[..]);
        if trailer_pad_len > 0 {
            trailers.put_slice(b"x-pad:");
            trailers.put_bytes(b'p', trailer_pad_len);
            trailers.put_slice(b"\r\n");
        }
        let mut wire = BytesMut::with_capacity(payload_len + trailers.len() + 10);
        wire.put_u8(0);
        wire.put_u32(u32::try_from(payload_len).unwrap());
        wire.put_bytes(b'm', payload_len);
        wire.put_u8(0x80);
        wire.put_u32(u32::try_from(trailers.len()).unwrap());
        wire.put_slice(&trailers);
        wire.freeze()
    }

    async fn unary(
        wire: Bytes,
        decoding_limit: Option<usize>,
        max_trailers_frame_size: Option<usize>,
    ) -> Result<Bytes, Status> {
        let mut transport =
            GrpcWebClientService::new(service_fn(move |_req: Request<GrpcWebCall<Body>>| {
                let wire = wire.clone();
                async move { Ok::<_, Infallible>(Response::new(Body::from(wire))) }
            }));
        if let Some(limit) = max_trailers_frame_size {
            transport.set_max_trailers_frame_size(limit);
        }
        let mut grpc = Grpc::new(transport, Uri::from_static("http://grpc.test"));
        if let Some(limit) = decoding_limit {
            grpc.set_max_decoding_message_size(limit);
        }
        grpc.unary(
            crate::Request::new(Bytes::new()),
            "/test.Svc/Call",
            BytesCodec,
        )
        .await
        .map(crate::Response::into_inner)
    }

    #[tokio::test]
    async fn raised_decoding_limit_admits_frames_above_the_default() {
        let payload_len = mib(5);
        let message = unary(grpc_web_response(payload_len, 0), Some(mib(8)), None)
            .await
            .unwrap();
        assert_eq!(message.len(), payload_len);
    }

    #[tokio::test]
    async fn message_frame_above_the_decoding_limit_is_out_of_range() {
        for (decoding_limit, payload_len) in [
            (Some(mib(1)), mib(1) + 1),
            (None, DEFAULT_MAX_RECV_MESSAGE_SIZE + 1),
        ] {
            let status = unary(grpc_web_response(payload_len, 0), decoding_limit, None)
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::OutOfRange, "limit={decoding_limit:?}");
        }
    }

    #[tokio::test]
    async fn oversized_trailers_frame_is_refused_despite_a_raised_decoding_limit() {
        let wire = grpc_web_response(16, 128);
        let status = unary(wire.clone(), Some(mib(8)), Some(64))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::OutOfRange);

        let message = unary(wire, Some(mib(8)), Some(256)).await.unwrap();
        assert_eq!(message.len(), 16);
    }

    #[tokio::test]
    async fn decoding_limit_resolves_through_a_connection_boundary() {
        let payload_len = mib(5);
        let wire = grpc_web_response(payload_len, 0);
        let transport =
            GrpcWebClientService::new(service_fn(move |_req: Request<GrpcWebCall<Body>>| {
                let wire = wire.clone();
                async move { Ok::<_, Infallible>(Response::new(Body::from(wire))) }
            }));
        let mut req = Request::new(Body::empty());
        req.extensions().insert(MaxDecodingMessageSize(mib(8)));
        let child = req
            .extensions()
            .fork_connection(&NoExtensionsTransfer::new());
        *req.extensions_mut() = child;

        let collected = transport
            .serve(req)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!(collected.to_bytes().len(), payload_len + 5);
    }

    #[tokio::test]
    async fn streaming_calls_end_after_an_oversized_message_frame() {
        let wire = grpc_web_response(mib(5), 0);
        let transport =
            GrpcWebClientService::new(service_fn(move |_req: Request<GrpcWebCall<Body>>| {
                let wire = wire.clone();
                async move { Ok::<_, Infallible>(Response::new(Body::from(wire))) }
            }));
        let grpc = Grpc::new(transport, Uri::from_static("http://grpc.test"));

        let mut server_streaming = grpc
            .server_streaming(
                crate::Request::new(Bytes::new()),
                "/test.Svc/Call",
                BytesCodec,
            )
            .await
            .unwrap()
            .into_inner();
        let mut bidi = grpc
            .streaming(
                crate::Request::new(stream::iter([Bytes::new()])),
                "/test.Svc/Call",
                BytesCodec,
            )
            .await
            .unwrap()
            .into_inner();
        for stream in [&mut server_streaming, &mut bidi] {
            assert_eq!(stream.message().await.unwrap_err().code(), Code::OutOfRange);
            assert!(stream.message().await.unwrap().is_none());
            assert!(stream.message().await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn the_client_limit_replaces_an_inherited_one() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let transport = service_fn({
            let seen = seen.clone();
            move |req: Request<Body>| {
                seen.lock().unwrap().push(
                    req.extensions()
                        .get_ref::<MaxDecodingMessageSize>()
                        .map(|limit| limit.0),
                );
                async move {
                    let mut response = Response::new(Body::empty());
                    response
                        .headers_mut()
                        .insert("grpc-status", HeaderValue::from_static("0"));
                    Ok::<_, Infallible>(response)
                }
            }
        });
        let default_client = Grpc::new(transport.clone(), Uri::from_static("http://grpc.test"));
        let mut raised_client = Grpc::new(transport, Uri::from_static("http://grpc.test"));
        raised_client.set_max_decoding_message_size(mib(8));

        for client in [&default_client, &raised_client] {
            let request = crate::Request::new(Bytes::new());
            request.extensions().insert(MaxDecodingMessageSize(mib(64)));
            drop(client.unary(request, "/test.Svc/Call", BytesCodec).await);
        }
        assert_eq!(
            *seen.lock().unwrap(),
            [Some(DEFAULT_MAX_RECV_MESSAGE_SIZE), Some(mib(8))]
        );
    }

    #[tokio::test]
    async fn message_frame_size_setter_bounds_requests_without_a_client_limit() {
        let payload_len = mib(5);
        let wire = grpc_web_response(payload_len, 0);
        let inner = service_fn(move |_req: Request<GrpcWebCall<Body>>| {
            let wire = wire.clone();
            async move { Ok::<_, Infallible>(Response::new(Body::from(wire))) }
        });

        let default = GrpcWebClientLayer::new().into_layer(inner.clone());
        let raised = GrpcWebClientLayer::new()
            .with_max_message_frame_size(mib(8))
            .into_layer(inner);

        let mut body = default
            .serve(Request::new(Body::empty()))
            .await
            .unwrap()
            .into_body();
        let error = body.frame().await.unwrap().unwrap_err();
        assert_eq!(error.code(), Code::OutOfRange);

        let collected = raised
            .serve(Request::new(Body::empty()))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!(collected.to_bytes().len(), payload_len + 5);

        // A request of a client that set a limit is bounded by that limit instead.
        let request = Request::new(Body::empty());
        request.extensions().insert(MaxDecodingMessageSize(mib(1)));
        let mut body = raised.serve(request).await.unwrap().into_body();
        let error = body.frame().await.unwrap().unwrap_err();
        assert_eq!(error.code(), Code::OutOfRange);
    }
}
