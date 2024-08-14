//! Middleware that decompresses request and response bodies.
//!
//! # Examples
//!
//! #### Request
//! ```rust
//! use std::{error::Error, io::Write};
//!
//! use bytes::{Bytes, BytesMut};
//! use flate2::{write::GzEncoder, Compression};
//!
//! use rama::http::{Body, header, HeaderValue, Request, Response};
//! use rama::service::{Context, Service, Layer, service_fn};
//! use rama::http::layer::decompression::{DecompressionBody, RequestDecompressionLayer};
//! use rama::http::dep::http_body_util::BodyExt;
//! use rama::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! // A request encoded with gzip coming from some HTTP client.
//! let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
//! encoder.write_all(b"Hello?")?;
//! let request = Request::builder()
//!     .header(header::CONTENT_ENCODING, "gzip")
//!     .body(Body::from(encoder.finish()?))?;
//!
//! // Our HTTP server
//! let mut server = (
//!     // Automatically decompress request bodies.
//!     RequestDecompressionLayer::new(),
//! ).layer(service_fn(handler));
//!
//! // Send the request, with the gzip encoded body, to our server.
//! let _response = server.serve(Context::default(), request).await?;
//!
//! // Handler receives request whose body is decoded when read
//! async fn handler(mut req: Request<DecompressionBody<Body>>) -> Result<Response, BoxError>{
//!     let data = req.into_body().collect().await?.to_bytes();
//!     assert_eq!(&data[..], b"Hello?");
//!     Ok(Response::new(Body::from("Hello, World!")))
//! }
//! # Ok(())
//! # }
//! ```
//!
//! #### Response
//!
//! ```rust
//! use std::convert::Infallible;
//!
//! use bytes::{Bytes, BytesMut};
//!
//! use rama::http::{Body, Request, Response};
//! use rama::service::{Context, Service, Layer, service_fn};
//! use rama::http::layer::{compression::Compression, decompression::DecompressionLayer};
//! use rama::http::dep::http_body_util::BodyExt;
//! use rama::error::BoxError;
//!
//! #
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # async fn handle(req: Request) -> Result<Response, Infallible> {
//! #     let body = Body::from("Hello, World!");
//! #     Ok(Response::new(body))
//! # }
//!
//! // Some opaque service that applies compression.
//! let service = Compression::new(service_fn(handle));
//!
//! // Our HTTP client.
//! let mut client = (
//!     // Automatically decompress response bodies.
//!     DecompressionLayer::new(),
//! ).layer(service);
//!
//! // Call the service.
//! //
//! // `DecompressionLayer` takes care of setting `Accept-Encoding`.
//! let request = Request::new(Body::default());
//!
//! let response = client
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! // Read the body
//! let body = response.into_body();
//! let bytes = body.collect().await?.to_bytes().to_vec();
//! let body = String::from_utf8(bytes).map_err(Into::<BoxError>::into)?;
//!
//! assert_eq!(body, "Hello, World!");
//! #
//! # Ok(())
//! # }
//! ```

mod request;

mod body;
mod layer;
mod service;

#[doc(inline)]
pub use self::{body::DecompressionBody, layer::DecompressionLayer, service::Decompression};

#[doc(inline)]
pub use self::request::layer::RequestDecompressionLayer;
#[doc(inline)]
pub use self::request::service::RequestDecompression;

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::io::Write;

    use crate::http::dep::http_body_util::BodyExt;
    use crate::http::layer::compression::Compression;
    use crate::http::{Body, HeaderMap, HeaderName, Request, Response};
    use crate::service::{service_fn, Context, Service};

    use flate2::write::GzEncoder;

    #[tokio::test]
    async fn works() {
        let client = Decompression::new(Compression::new(service_fn(handle)));

        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(Context::default(), req).await.unwrap();

        // read the body, it will be decompressed automatically
        let body = res.into_body();
        let collected = body.collect().await.unwrap();
        let decompressed_data = String::from_utf8(collected.to_bytes().to_vec()).unwrap();

        assert_eq!(decompressed_data, "Hello, World!");
    }

    async fn handle(_req: Request) -> Result<Response, Infallible> {
        let mut trailers = HeaderMap::new();
        trailers.insert(HeaderName::from_static("foo"), "bar".parse().unwrap());
        let body = Body::from("Hello, World!");
        Ok(Response::builder().body(body).unwrap())
    }

    #[tokio::test]
    async fn decompress_multi_gz() {
        let client = Decompression::new(service_fn(handle_multi_gz));

        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(Context::default(), req).await.unwrap();

        // read the body, it will be decompressed automatically
        let body = res.into_body();
        let decompressed_data =
            String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();

        assert_eq!(decompressed_data, "Hello, World!");
    }

    async fn handle_multi_gz(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let mut buf = Vec::new();
        let mut enc1 = GzEncoder::new(&mut buf, Default::default());
        enc1.write_all(b"Hello, ").unwrap();
        enc1.finish().unwrap();

        let mut enc2 = GzEncoder::new(&mut buf, Default::default());
        enc2.write_all(b"World!").unwrap();
        enc2.finish().unwrap();

        let mut res = Response::new(Body::from(buf));
        res.headers_mut()
            .insert("content-encoding", "gzip".parse().unwrap());
        Ok(res)
    }
}
