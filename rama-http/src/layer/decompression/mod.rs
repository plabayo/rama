//! Middleware that decompresses request and response bodies.
//!
//! # Examples
//!
//! #### Request
//! ```rust
//! use std::{error::Error, io::Write};
//!
//! use rama_core::bytes::{Bytes, BytesMut};
//! use flate2::{write::GzEncoder, Compression};
//!
//! use rama_http::{Body, header, HeaderValue, Request, Response};
//! use rama_core::service::service_fn;
//! use rama_core::{Service, Layer};
//! use rama_http::layer::decompression::{DecompressionBody, RequestDecompressionLayer};
//! use rama_http::body::util::BodyExt;
//! use rama_core::error::BoxError;
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
//! ).into_layer(service_fn(handler));
//!
//! // Send the request, with the gzip encoded body, to our server.
//! let _response = server.serve(request).await?;
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
//! use rama_core::bytes::{Bytes, BytesMut};
//!
//! use rama_http::{Body, Request, Response};
//! use rama_core::service::service_fn;
//! use rama_core::{Service, Layer};
//! use rama_http::layer::{compression::Compression, decompression::DecompressionLayer};
//! use rama_http::body::util::BodyExt;
//! use rama_core::error::BoxError;
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
//! ).into_layer(service);
//!
//! // Call the service.
//! //
//! // `DecompressionLayer` takes care of setting `Accept-Encoding`.
//! let request = Request::new(Body::default());
//!
//! let response = client
//!     .serve(request)
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

pub(crate) mod body;
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

    use crate::layer::compression::Compression;
    use crate::{Body, HeaderMap, HeaderName, Request, Response, body::util::BodyExt};
    use rama_core::Service;
    use rama_core::service::service_fn;

    use flate2::write::GzEncoder;

    #[tokio::test]
    async fn works() {
        let client = Decompression::new(Compression::new(service_fn(handle)));

        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();

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
        let res = client.serve(req).await.unwrap();

        // read the body, it will be decompressed automatically
        let body = res.into_body();
        let decompressed_data =
            String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();

        assert_eq!(decompressed_data, "Hello, World!");
    }

    #[tokio::test]
    async fn decompress_multi_zstd() {
        let client = Decompression::new(service_fn(handle_multi_zstd));

        let req = Request::builder()
            .header("accept-encoding", "zstd")
            .body(Body::empty())
            .unwrap();
        let res = client.serve(req).await.unwrap();

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

    async fn handle_multi_zstd(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let mut buf = Vec::new();
        let mut enc1 = zstd::Encoder::new(&mut buf, Default::default()).unwrap();
        enc1.write_all(b"Hello, ").unwrap();
        enc1.finish().unwrap();

        let mut enc2 = zstd::Encoder::new(&mut buf, Default::default()).unwrap();
        enc2.write_all(b"World!").unwrap();
        enc2.finish().unwrap();

        let mut res = Response::new(Body::from(buf));
        res.headers_mut()
            .insert("content-encoding", "zstd".parse().unwrap());
        Ok(res)
    }
}
