use std::{fmt, pin::pin};

use rama_core::{
    error::BoxError,
    extensions::ExtensionsRef as _,
    futures::Stream,
    stream::{self, StreamExt},
};
use rama_http_types::{Body, StreamingBody};

use crate::codec::EncodeBody;
use crate::codec::compression::{
    CompressionEncoding, EnabledCompressionEncodings, SingleMessageCompressionOverride,
};
use crate::metadata::GRPC_CONTENT_TYPE;
use crate::{
    Request, Status,
    codec::{Codec, Streaming},
    server::{ClientStreamingService, ServerStreamingService, StreamingService, UnaryService},
};

/// A gRPC Server handler.
///
/// This will wrap some inner [`Codec`] and provide utilities to handle
/// inbound unary, client side streaming, server side streaming, and
/// bi-directional streaming.
///
/// Each request handler method accepts some service that implements the
/// corresponding service trait and a http request that contains some body that
/// implements some [`Body`].
pub struct Grpc<T> {
    codec: T,
    /// Which compression encodings does the server accept for requests?
    accept_compression_encodings: EnabledCompressionEncodings,
    /// Which compression encodings might the server use for responses.
    send_compression_encodings: EnabledCompressionEncodings,
    /// Limits the maximum size of a decoded message.
    max_decoding_message_size: Option<usize>,
    /// Limits the maximum size of an encoded message.
    max_encoding_message_size: Option<usize>,
}

impl<T> Grpc<T>
where
    T: Codec,
{
    /// Creates a new gRPC server with the provided [`Codec`].
    pub fn new(codec: T) -> Self {
        Self {
            codec,
            accept_compression_encodings: EnabledCompressionEncodings::default(),
            send_compression_encodings: EnabledCompressionEncodings::default(),
            max_decoding_message_size: None,
            max_encoding_message_size: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable accepting compressed requests.
        ///
        /// If a request with an unsupported encoding is received the server will respond with
        /// [`Code::UnUnimplemented`](crate::Code).
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable sending compressed responses.
        ///
        /// Requires the client to also support receiving compressed responses.
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Limits the maximum size of a decoded message.
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Limits the maximum size of a encoded message.
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn compression_config(
            mut self,
            accept_encodings: EnabledCompressionEncodings,
            send_encodings: EnabledCompressionEncodings,
        ) -> Self {
            for &encoding in CompressionEncoding::ENCODINGS {
                if accept_encodings.is_enabled(encoding) {
                    self.set_accept_compressed(encoding);
                }
                if send_encodings.is_enabled(encoding) {
                    self.set_send_compressed(encoding);
                }
            }

            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn max_message_size_config(
            mut self,
            max_decoding_message_size: Option<usize>,
            max_encoding_message_size: Option<usize>,
        ) -> Self {
            if let Some(limit) = max_decoding_message_size {
                self.set_max_decoding_message_size(limit);
            }
            if let Some(limit) = max_encoding_message_size {
                self.set_max_encoding_message_size(limit);
            }

            self
        }
    }

    /// Handle a single unary gRPC request.
    pub async fn unary<S, B>(
        &mut self,
        service: S,
        req: rama_http_types::Request<B>,
    ) -> Result<rama_http_types::Response<Body>, BoxError>
    where
        S: UnaryService<T::Decode, Response = T::Encode>,
        B: StreamingBody<Error: Into<BoxError> + Send + 'static> + Send + Sync + 'static,
    {
        let accept_encoding = CompressionEncoding::from_accept_encoding_header(
            req.headers(),
            self.send_compression_encodings,
        );

        let request = match self.map_request_unary(req).await {
            Ok(r) => r,
            Err(status) => {
                return self.map_response::<stream::Once<Result<T::Encode, Status>>>(
                    Err(status),
                    accept_encoding,
                    SingleMessageCompressionOverride::default(),
                    self.max_encoding_message_size,
                );
            }
        };

        let response = service
            .serve(request)
            .await
            .map(|r| r.map(|m| stream::once(Ok(m))));

        let compression_override = compression_override_from_response(&response);

        self.map_response(
            response,
            accept_encoding,
            compression_override,
            self.max_encoding_message_size,
        )
    }

    /// Handle a server side streaming request.
    pub async fn server_streaming<S, B>(
        &mut self,
        service: S,
        req: rama_http_types::Request<B>,
    ) -> Result<rama_http_types::Response<Body>, BoxError>
    where
        S: ServerStreamingService<T::Decode, Response = T::Encode>,
        S::ResponseStream: Send + Sync + 'static,
        B: StreamingBody<Error: Into<BoxError> + Send + 'static> + Send + Sync + 'static,
    {
        let accept_encoding = CompressionEncoding::from_accept_encoding_header(
            req.headers(),
            self.send_compression_encodings,
        );

        let request = match self.map_request_unary(req).await {
            Ok(r) => r,
            Err(status) => {
                return self.map_response::<S::ResponseStream>(
                    Err(status),
                    accept_encoding,
                    SingleMessageCompressionOverride::default(),
                    self.max_encoding_message_size,
                );
            }
        };

        let response = service.serve(request).await;

        self.map_response(
            response,
            accept_encoding,
            // disabling compression of individual stream items must be done on
            // the items themselves
            SingleMessageCompressionOverride::default(),
            self.max_encoding_message_size,
        )
    }

    /// Handle a client side streaming gRPC request.
    pub async fn client_streaming<S, B>(
        &mut self,
        service: S,
        req: rama_http_types::Request<B>,
    ) -> Result<rama_http_types::Response<Body>, BoxError>
    where
        S: ClientStreamingService<T::Decode, Response = T::Encode>,
        B: StreamingBody<Error: Into<BoxError> + Send + 'static> + Send + Sync + 'static,
    {
        let accept_encoding = CompressionEncoding::from_accept_encoding_header(
            req.headers(),
            self.send_compression_encodings,
        );

        let request = match self.map_request_streaming(req) {
            Ok(req) => req,
            Err(status) => return Ok(status.try_into_http()?),
        };

        let response = service
            .serve(request)
            .await
            .map(|r| r.map(|m| stream::once(Ok(m))));

        let compression_override = compression_override_from_response(&response);

        self.map_response(
            response,
            accept_encoding,
            compression_override,
            self.max_encoding_message_size,
        )
    }

    /// Handle a bi-directional streaming gRPC request.
    pub async fn streaming<S, B>(
        &mut self,
        service: S,
        req: rama_http_types::Request<B>,
    ) -> Result<rama_http_types::Response<Body>, BoxError>
    where
        S: StreamingService<T::Decode, Response = T::Encode> + Send,
        S::ResponseStream: Send + Sync + 'static,
        B: StreamingBody<Error: Into<BoxError> + Send + 'static> + Send + Sync + 'static,
    {
        let accept_encoding = CompressionEncoding::from_accept_encoding_header(
            req.headers(),
            self.send_compression_encodings,
        );

        let request = match self.map_request_streaming(req) {
            Ok(req) => req,
            Err(status) => return Ok(status.try_into_http()?),
        };

        let response = service.serve(request).await;

        self.map_response(
            response,
            accept_encoding,
            SingleMessageCompressionOverride::default(),
            self.max_encoding_message_size,
        )
    }

    async fn map_request_unary<B>(
        &mut self,
        request: rama_http_types::Request<B>,
    ) -> Result<Request<T::Decode>, Status>
    where
        B: StreamingBody<Error: Into<BoxError> + Send + 'static> + Send + Sync + 'static,
    {
        let request_compression_encoding = self.request_encoding_if_supported(&request)?;

        let (parts, body) = request.into_parts();

        let mut stream = pin!(Streaming::new_request(
            self.codec.decoder(),
            body,
            request_compression_encoding,
            self.max_decoding_message_size,
        ));

        let message = stream
            .try_next()
            .await?
            .ok_or_else(|| Status::internal("Missing request message."))?;

        let mut req = Request::from_http_parts(parts, message);

        if let Some(trailers) = stream.trailers().await? {
            req.metadata_mut().merge(trailers);
        }

        Ok(req)
    }

    fn map_request_streaming<B>(
        &mut self,
        request: rama_http_types::Request<B>,
    ) -> Result<Request<Streaming<T::Decode>>, Status>
    where
        B: StreamingBody<Error: Into<BoxError> + Send + 'static> + Send + Sync + 'static,
    {
        let encoding = self.request_encoding_if_supported(&request)?;

        let request = request.map(|body| {
            Streaming::new_request(
                self.codec.decoder(),
                body,
                encoding,
                self.max_decoding_message_size,
            )
        });

        Ok(Request::from_http(request))
    }

    fn map_response<B>(
        &mut self,
        response: Result<crate::Response<B>, Status>,
        accept_encoding: Option<CompressionEncoding>,
        compression_override: SingleMessageCompressionOverride,
        max_message_size: Option<usize>,
    ) -> Result<rama_http_types::Response<Body>, BoxError>
    where
        B: Stream<Item = Result<T::Encode, Status>> + Send + Sync + 'static,
    {
        let response = match response {
            Ok(res) => res,
            Err(status) => return Ok(status.try_into_http()?),
        };

        let (mut parts, body) = response.into_http().into_parts();

        // Set the content type
        parts
            .headers
            .insert(rama_http_types::header::CONTENT_TYPE, GRPC_CONTENT_TYPE);

        #[cfg(feature = "compression")]
        if let Some(encoding) = accept_encoding {
            // Set the content encoding
            parts.headers.insert(
                crate::codec::compression::ENCODING_HEADER,
                encoding.into_header_value(),
            );
        }

        let body = EncodeBody::new_server(
            self.codec.encoder(),
            body,
            accept_encoding,
            compression_override,
            max_message_size,
        );

        Ok(rama_http_types::Response::from_parts(
            parts,
            Body::new(body),
        ))
    }

    fn request_encoding_if_supported<B>(
        &self,
        request: &rama_http_types::Request<B>,
    ) -> Result<Option<CompressionEncoding>, Status> {
        CompressionEncoding::from_encoding_header(
            request.headers(),
            self.accept_compression_encodings,
        )
    }
}

impl<T: fmt::Debug> fmt::Debug for Grpc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grpc")
            .field("codec", &self.codec)
            .field(
                "accept_compression_encodings",
                &self.accept_compression_encodings,
            )
            .field(
                "send_compression_encodings",
                &self.send_compression_encodings,
            )
            .finish()
    }
}

fn compression_override_from_response<B, E>(
    res: &Result<crate::Response<B>, E>,
) -> SingleMessageCompressionOverride {
    res.as_ref()
        .ok()
        .and_then(|response| {
            response
                .extensions()
                .get::<SingleMessageCompressionOverride>()
                .copied()
        })
        .unwrap_or_default()
}
