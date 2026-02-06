use std::{fmt, pin::pin};

use rama_core::{
    error::BoxError,
    futures::Stream,
    stream::{self, StreamExt},
};
use rama_http::{
    Body, StreamingBody,
    header::CONTENT_TYPE,
    headers::{HeaderMapExt, Te},
    uri::{PathAndQuery, Uri},
};

use crate::{
    Code, Request, Response, Status,
    client::GrpcService,
    codec::{
        Codec, CompressionEncoding, Decoder, EnabledCompressionEncodings, EncodeBody, Streaming,
    },
    metadata::GRPC_CONTENT_TYPE,
    request::SanitizeHeaders,
};

/// A gRPC client dispatcher.
///
/// This will wrap some inner [`GrpcService`] and will encode/decode
/// messages via the provided codec.
///
/// Each request method takes a [`Request`], a [`PathAndQuery`], and a
/// [`Codec`]. The request contains the message to send via the
/// [`Codec::encoder`]. The path determines the fully qualified path
/// that will be append to the outgoing uri. The path must follow
/// the conventions explained in the [gRPC protocol definition] under `Path →`. An
/// example of this path could look like `/greeter.Greeter/SayHello`.
///
/// [gRPC protocol definition]: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#requests
pub struct Grpc<T> {
    inner: T,
    config: GrpcConfig,
}

struct GrpcConfig {
    origin: Uri,
    /// Which compression encodings does the client accept?
    accept_compression_encodings: EnabledCompressionEncodings,
    /// The compression encoding that will be applied to requests.
    send_compression_encodings: Option<CompressionEncoding>,
    /// Limits the maximum size of a decoded message.
    max_decoding_message_size: Option<usize>,
    /// Limits the maximum size of an encoded message.
    max_encoding_message_size: Option<usize>,
}

impl<T> Grpc<T> {
    /// Creates a new gRPC client with the provided [`GrpcService`] and `Uri`.
    ///
    /// The provided Uri will use only the scheme and authority parts as the
    /// path_and_query portion will be set for each method.
    #[must_use]
    pub fn new(inner: T, origin: Uri) -> Self {
        Self {
            inner,
            config: GrpcConfig {
                origin,
                send_compression_encodings: None,
                accept_compression_encodings: EnabledCompressionEncodings::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            },
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    rama_utils::macros::generate_set_and_with! {
        /// Compress requests with the provided encoding.
        ///
        /// Requires the server to accept the specified encoding, otherwise it might return an error.
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.config.send_compression_encodings = Some(encoding);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable accepting compressed responses.
        ///
        /// Requires the server to also support sending compressed responses.
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.config.accept_compression_encodings.enable(encoding);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Limits the maximum size of a decoded message.
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.config.max_decoding_message_size = Some(limit);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Limits the maximum size of an encoded message.
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.config.max_encoding_message_size = Some(limit);
            self
        }
    }

    /// Send a single unary gRPC request.
    pub async fn unary<M1, M2, C>(
        &self,
        request: Request<M1>,
        path: PathAndQuery,
        codec: C,
    ) -> Result<Response<M2>, Status>
    where
        T: GrpcService<Body>,
        T::ResponseBody: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        C: Codec<Encode = M1, Decode = M2> + Send + Sync + 'static,
        M1: Send + Sync + 'static,
        M2: Send + Sync + 'static,
    {
        let request = request.map(|m| stream::once(m));
        self.client_streaming(request, path, codec).await
    }

    /// Send a client side streaming gRPC request.
    pub async fn client_streaming<S, M1, M2, C>(
        &self,
        request: Request<S>,
        path: PathAndQuery,
        codec: C,
    ) -> Result<Response<M2>, Status>
    where
        T: GrpcService<Body>,
        T::ResponseBody: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        S: Stream<Item = M1> + Send + Sync + 'static,
        C: Codec<Encode = M1, Decode = M2> + Send + Sync + 'static,
        M1: Send + Sync + 'static,
        M2: Send + Sync + 'static,
    {
        let (mut parts, body, extensions) =
            self.streaming(request, path, codec).await?.into_parts();

        let mut body = pin!(body);

        let message = body
            .try_next()
            .await
            .map_err(|mut status| {
                status.metadata_mut().merge(parts.clone());
                status
            })?
            .ok_or_else(|| Status::internal("Missing response message."))?;

        if let Some(trailers) = body.trailers().await? {
            parts.merge(trailers);
        }

        Ok(Response::from_parts(parts, message, extensions))
    }

    /// Send a server side streaming gRPC request.
    pub async fn server_streaming<M1, M2, C>(
        &self,
        request: Request<M1>,
        path: PathAndQuery,
        codec: C,
    ) -> Result<Response<Streaming<M2>>, Status>
    where
        T: GrpcService<Body>,
        T::ResponseBody: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        C: Codec<Encode = M1, Decode = M2> + Send + Sync + 'static,
        M1: Send + Sync + 'static,
        M2: Send + Sync + 'static,
    {
        let request = request.map(|m| stream::once(m));
        self.streaming(request, path, codec).await
    }

    /// Send a bi-directional streaming gRPC request.
    pub async fn streaming<S, M1, M2, C>(
        &self,
        request: Request<S>,
        path: PathAndQuery,
        mut codec: C,
    ) -> Result<Response<Streaming<M2>>, Status>
    where
        T: GrpcService<Body>,
        T::ResponseBody: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
        S: Stream<Item = M1> + Send + Sync + 'static,
        C: Codec<Encode = M1, Decode = M2> + Send + Sync + 'static,
        M1: Send + Sync + 'static,
        M2: Send + Sync + 'static,
    {
        let request = request
            .map(|s| {
                EncodeBody::new_client(
                    codec.encoder(),
                    s.map(Ok),
                    self.config.send_compression_encodings,
                    self.config.max_encoding_message_size,
                )
            })
            .map(Body::new);

        let request = self.config.prepare_request(request, path)?;

        let response = self
            .inner
            .serve(request)
            .await
            .map_err(Status::from_error_generic)?;

        let decoder = codec.decoder();

        self.create_response(decoder, response)
    }

    // Keeping this code in a separate function from Self::streaming lets functions that return the
    // same output share the generated binary code
    fn create_response<M2>(
        &self,
        decoder: impl Decoder<Item = M2, Error = Status> + Send + 'static,
        response: rama_http_types::Response<T::ResponseBody>,
    ) -> Result<Response<Streaming<M2>>, Status>
    where
        T: GrpcService<Body>,
        T::ResponseBody: StreamingBody + Send + Sync + 'static,
        <T::ResponseBody as StreamingBody>::Error: Into<BoxError>,
    {
        let encoding = CompressionEncoding::from_encoding_header(
            response.headers(),
            self.config.accept_compression_encodings,
        )?;

        let status_code = response.status();
        let trailers_only_status = Status::from_header_map(response.headers());

        // We do not need to check for trailers if the `grpc-status` header is present
        // with a valid code.
        let expect_additional_trailers = if let Some(status) = trailers_only_status {
            if status.code() != Code::Ok {
                return Err(status);
            }

            false
        } else {
            true
        };

        let response = response.map(|body| {
            if expect_additional_trailers {
                Streaming::new_response(
                    decoder,
                    body,
                    status_code,
                    encoding,
                    self.config.max_decoding_message_size,
                )
            } else {
                Streaming::new_empty(decoder, body)
            }
        });

        Ok(Response::from_http(response))
    }
}

impl GrpcConfig {
    fn prepare_request(
        &self,
        request: Request<Body>,
        path: PathAndQuery,
    ) -> Result<rama_http_types::Request<Body>, Status> {
        let mut parts = self.origin.clone().into_parts();

        match &parts.path_and_query {
            Some(pnq) if pnq != "/" => {
                let Ok(paq) = format!("{}{}", pnq.path(), path).parse() else {
                    return Err(Status::internal("new Path/Query combo is invalid"));
                };
                parts.path_and_query = Some(paq);
            }
            _ => {
                parts.path_and_query = Some(path);
            }
        }

        let Ok(uri) = Uri::from_parts(parts) else {
            return Err(Status::internal("uri with Path/Query combo is invalid"));
        };

        let mut request = request.into_http(
            uri,
            rama_http_types::Method::POST,
            rama_http_types::Version::HTTP_2,
            SanitizeHeaders::Yes,
        );

        // Add the gRPC related HTTP headers
        request.headers_mut().typed_insert(Te::trailers());

        // Set the content type
        request
            .headers_mut()
            .insert(CONTENT_TYPE, GRPC_CONTENT_TYPE);
        // TODO: replace with typed header (below) once
        // grpc mime creation is just a static value as well...
        // request.headers_mut().typed_insert(ContentType::grpc());

        #[cfg(feature = "compression")]
        if let Some(encoding) = self.send_compression_encodings {
            request.headers_mut().insert(
                crate::codec::compression::ENCODING_HEADER,
                encoding.into_header_value(),
            );
        }

        if let Some(header_value) = self
            .accept_compression_encodings
            .try_into_accept_encoding_header_value()
            .map_err(Status::from_error)?
        {
            request.headers_mut().insert(
                crate::codec::compression::ACCEPT_ENCODING_HEADER,
                header_value,
            );
        }

        Ok(request)
    }
}

impl<T: Clone> Clone for Grpc<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: GrpcConfig {
                origin: self.config.origin.clone(),
                send_compression_encodings: self.config.send_compression_encodings,
                accept_compression_encodings: self.config.accept_compression_encodings,
                max_encoding_message_size: self.config.max_encoding_message_size,
                max_decoding_message_size: self.config.max_decoding_message_size,
            },
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Grpc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grpc")
            .field("inner", &self.inner)
            .field("origin", &self.config.origin)
            .field(
                "compression_encoding",
                &self.config.send_compression_encodings,
            )
            .field(
                "accept_compression_encodings",
                &self.config.accept_compression_encodings,
            )
            .field(
                "max_decoding_message_size",
                &self.config.max_decoding_message_size,
            )
            .field(
                "max_encoding_message_size",
                &self.config.max_encoding_message_size,
            )
            .finish()
    }
}
