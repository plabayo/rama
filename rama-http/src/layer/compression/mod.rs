//! Middleware that compresses response bodies.
//!
//! # Example
//!
//! Example showing how to respond with the compressed contents of a file.
//!
//! ```rust
//! use rama_core::bytes::Bytes;
//! use futures_lite::stream::StreamExt;
//! use rama_core::error::BoxError;
//! use rama_http::dep::http_body::Frame;
//! use rama_http::dep::http_body_util::{BodyExt , StreamBody};
//! use rama_http::dep::http_body_util::combinators::BoxBody as InnerBoxBody;
//! use rama_http::layer::compression::CompressionLayer;
//! use rama_http::{Body, Request, Response, header::ACCEPT_ENCODING};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use std::convert::Infallible;
//! use tokio::fs::{self, File};
//! use tokio_util::io::ReaderStream;
//!
//! type BoxBody = InnerBoxBody<Bytes, std::io::Error>;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! async fn handle(req: Request) -> Result<Response<BoxBody>, Infallible> {
//!     // Open the file.
//!     let file = File::open("Cargo.toml").await.expect("file missing");
//!     // Convert the file into a `Stream` of `Bytes`.
//!     let stream = ReaderStream::new(file);
//!     // Convert the stream into a stream of data `Frame`s.
//!     let stream = stream.map(|res| match res {
//!         Ok(v) => Ok(Frame::data(v)),
//!         Err(e) => Err(e),
//!     });
//!     // Convert the `Stream` into a `Body`.
//!     let body = StreamBody::new(stream);
//!     // Erase the type because its very hard to name in the function signature.
//!     let body = BodyExt::boxed(body);
//!     // Create response.
//!     Ok(Response::new(body))
//! }
//!
//! let mut service = (
//!     // Compress responses based on the `Accept-Encoding` header.
//!     CompressionLayer::new(),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let request = Request::builder()
//!     .header(ACCEPT_ENCODING, "gzip")
//!     .body(Body::default())?;
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! assert_eq!(response.headers()["content-encoding"], "gzip");
//!
//! // Read the body
//! let bytes = response
//!     .into_body()
//!     .collect()
//!     .await?
//!     .to_bytes();
//!
//! // The compressed body should be smaller 🤞
//! let uncompressed_len = fs::read_to_string("Cargo.toml").await?.len();
//! assert!(bytes.len() < uncompressed_len);
//! #
//! # Ok(())
//! # }
//! ```
//!

pub mod predicate;

pub(crate) mod body;
mod layer;
mod pin_project_cfg;
mod service;

#[doc(inline)]
pub use self::{
    body::CompressionBody,
    layer::CompressionLayer,
    predicate::{DefaultPredicate, Predicate},
    service::Compression,
};
#[doc(inline)]
pub use crate::layer::util::compression::CompressionLevel;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::layer::compression::predicate::SizeAbove;

    use crate::dep::http_body::Body as _;
    use crate::dep::http_body_util::BodyExt;
    use crate::header::{
        ACCEPT_ENCODING, ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_RANGE, CONTENT_TYPE, RANGE,
    };
    use crate::{Body, HeaderValue, Request, Response};
    use async_compression::tokio::write::{BrotliDecoder, BrotliEncoder};
    use flate2::read::GzDecoder;
    use rama_core::service::service_fn;
    use rama_core::{Context, Service};
    use std::convert::Infallible;
    use std::io::Read;
    use std::sync::{Arc, RwLock};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::io::StreamReader;

    // Compression filter allows every other request to be compressed
    #[derive(Clone)]
    struct Always;

    impl Predicate for Always {
        fn should_compress<B>(&self, _: &rama_http_types::Response<B>) -> bool
        where
            B: rama_http_types::dep::http_body::Body,
        {
            true
        }
    }

    #[tokio::test]
    async fn gzip_works() {
        let svc = service_fn(handle);
        let svc = Compression::new(svc).compress_when(Always);

        // call the service
        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();

        // read the compressed body
        let collected = res.into_body().collect().await.unwrap();
        let compressed_data = collected.to_bytes();

        // decompress the body
        // doing this with flate2 as that is much easier than async-compression and blocking during
        // tests is fine
        let mut decoder = GzDecoder::new(&compressed_data[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();

        assert_eq!(decompressed, "Hello, World!");
    }

    #[tokio::test]
    async fn x_gzip_works() {
        let svc = service_fn(handle);
        let svc = Compression::new(svc).compress_when(Always);

        // call the service
        let req = Request::builder()
            .header("accept-encoding", "x-gzip")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();

        // we treat x-gzip as equivalent to gzip and don't have to return x-gzip
        // taking extra caution by checking all headers with this name
        assert_eq!(
            res.headers()
                .get_all("content-encoding")
                .iter()
                .collect::<Vec<&HeaderValue>>(),
            vec!(HeaderValue::from_static("gzip"))
        );

        // read the compressed body
        let collected = res.into_body().collect().await.unwrap();
        let compressed_data = collected.to_bytes();

        // decompress the body
        // doing this with flate2 as that is much easier than async-compression and blocking during
        // tests is fine
        let mut decoder = GzDecoder::new(&compressed_data[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();

        assert_eq!(decompressed, "Hello, World!");
    }

    #[tokio::test]
    async fn zstd_works() {
        let svc = service_fn(handle);
        let svc = Compression::new(svc).compress_when(Always);

        // call the service
        let req = Request::builder()
            .header("accept-encoding", "zstd")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();

        // read the compressed body
        let body = res.into_body();
        let compressed_data = body.collect().await.unwrap().to_bytes();

        // decompress the body
        let decompressed = zstd::stream::decode_all(std::io::Cursor::new(compressed_data)).unwrap();
        let decompressed = String::from_utf8(decompressed).unwrap();

        assert_eq!(decompressed, "Hello, World!");
    }

    #[tokio::test]
    async fn no_recompress() {
        const DATA: &str = "Hello, World! I'm already compressed with br!";

        let svc = service_fn(async |_| {
            let buf = {
                let mut buf = Vec::new();

                let mut enc = BrotliEncoder::new(&mut buf);
                enc.write_all(DATA.as_bytes()).await?;
                enc.flush().await?;
                buf
            };

            let resp = Response::builder()
                .header("content-encoding", "br")
                .body(Body::from(buf))
                .unwrap();
            Ok::<_, std::io::Error>(resp)
        });
        let svc = Compression::new(svc);

        // call the service
        //
        // note: the accept-encoding doesn't match the content-encoding above, so that
        // we're able to see if the compression layer triggered or not
        let req = Request::builder()
            .header("accept-encoding", "gzip")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();

        // check we didn't recompress
        assert_eq!(
            res.headers()
                .get("content-encoding")
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default(),
            "br",
        );

        // read the compressed body
        let body = res.into_body();
        let data = body.collect().await.unwrap().to_bytes();

        // decompress the body
        let data = {
            let mut output_buf = Vec::new();
            let mut decoder = BrotliDecoder::new(&mut output_buf);
            decoder
                .write_all(&data)
                .await
                .expect("couldn't brotli-decode");
            decoder.flush().await.expect("couldn't flush");
            output_buf
        };

        assert_eq!(data, DATA.as_bytes());
    }

    async fn handle(_req: Request) -> Result<Response, Infallible> {
        let body = Body::from("Hello, World!");
        Ok(Response::builder().body(body).unwrap())
    }

    #[tokio::test]
    async fn will_not_compress_if_filtered_out() {
        use predicate::Predicate;

        const DATA: &str = "Hello world uncompressed";

        let svc_fn = service_fn(async |_| {
            let resp = Response::builder()
                // .header("content-encoding", "br")
                .body(Body::from(DATA.as_bytes()))
                .unwrap();
            Ok::<_, std::io::Error>(resp)
        });

        // Compression filter allows every other request to be compressed
        #[derive(Default, Clone)]
        struct EveryOtherResponse(Arc<RwLock<u64>>);

        #[allow(clippy::dbg_macro)]
        impl Predicate for EveryOtherResponse {
            fn should_compress<B>(&self, _: &rama_http_types::Response<B>) -> bool
            where
                B: rama_http_types::dep::http_body::Body,
            {
                let mut guard = self.0.write().unwrap();
                let should_compress = *guard % 2 != 0;
                *guard += 1;
                should_compress
            }
        }

        let svc = Compression::new(svc_fn).compress_when(EveryOtherResponse::default());
        let req = Request::builder()
            .header("accept-encoding", "br")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();

        // read the uncompressed body
        let body = res.into_body();
        let data = body.collect().await.unwrap().to_bytes();
        let still_uncompressed = String::from_utf8(data.to_vec()).unwrap();
        assert_eq!(DATA, &still_uncompressed);

        // Compression filter will compress the next body
        let req = Request::builder()
            .header("accept-encoding", "br")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();

        // read the compressed body
        let body = res.into_body();
        let data = body.collect().await.unwrap().to_bytes();
        assert!(String::from_utf8(data.to_vec()).is_err());
    }

    #[tokio::test]
    async fn doesnt_compress_images() {
        async fn handle(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
            let mut res = Response::new(Body::from(
                "a".repeat((SizeAbove::DEFAULT_MIN_SIZE * 2) as usize),
            ));
            res.headers_mut()
                .insert(CONTENT_TYPE, "image/png".parse().unwrap());
            Ok(res)
        }

        let svc = Compression::new(service_fn(handle));

        let res = svc
            .serve(
                Context::default(),
                Request::builder()
                    .header(ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(res.headers().get(CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn does_compress_svg() {
        async fn handle(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
            let mut res = Response::new(Body::from(
                "a".repeat((SizeAbove::DEFAULT_MIN_SIZE * 2) as usize),
            ));
            res.headers_mut()
                .insert(CONTENT_TYPE, "image/svg+xml".parse().unwrap());
            Ok(res)
        }

        let svc = Compression::new(service_fn(handle));

        let res = svc
            .serve(
                Context::default(),
                Request::builder()
                    .header(ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.headers()[CONTENT_ENCODING], "gzip");
    }

    #[tokio::test]
    async fn compress_with_quality() {
        const DATA: &str = "Check compression quality level! Check compression quality level! Check compression quality level!";
        let level = CompressionLevel::Best;

        let svc = service_fn(async |_| {
            let resp = Response::builder()
                .body(Body::from(DATA.as_bytes()))
                .unwrap();
            Ok::<_, std::io::Error>(resp)
        });

        let svc = Compression::new(svc).quality(level);

        // call the service
        let req = Request::builder()
            .header("accept-encoding", "br")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();

        // read the compressed body
        let body = res.into_body();
        let compressed_data = body.collect().await.unwrap().to_bytes();

        // build the compressed body with the same quality level
        let compressed_with_level = {
            use async_compression::tokio::bufread::BrotliEncoder;

            let stream = Box::pin(futures_lite::stream::once({
                Ok::<_, std::io::Error>(DATA.as_bytes())
            }));
            let reader = StreamReader::new(stream);
            let mut enc = BrotliEncoder::with_quality(reader, level.into_async_compression());

            let mut buf = Vec::new();
            enc.read_to_end(&mut buf).await.unwrap();
            buf
        };

        assert_eq!(
            compressed_data,
            compressed_with_level.as_slice(),
            "Compression level is not respected"
        );
    }

    #[tokio::test]
    async fn should_not_compress_ranges() {
        let svc = service_fn(async |_| {
            let mut res = Response::new(Body::from("Hello"));
            let headers = res.headers_mut();
            headers.insert(ACCEPT_RANGES, "bytes".parse().unwrap());
            headers.insert(CONTENT_RANGE, "bytes 0-4/*".parse().unwrap());
            Ok::<_, std::io::Error>(res)
        });
        let svc = Compression::new(svc).compress_when(Always);

        // call the service
        let req = Request::builder()
            .header(ACCEPT_ENCODING, "gzip")
            .header(RANGE, "bytes=0-4")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        let headers = res.headers().clone();

        // read the uncompressed body
        let collected = res.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(headers[ACCEPT_RANGES], "bytes");
        assert!(!headers.contains_key(CONTENT_ENCODING));
        assert_eq!(collected, "Hello");
    }

    #[tokio::test]
    async fn should_strip_accept_ranges_header_when_compressing() {
        let svc = service_fn(async |_| {
            let mut res = Response::new(Body::from("Hello, World!"));
            res.headers_mut()
                .insert(ACCEPT_RANGES, "bytes".parse().unwrap());
            Ok::<_, std::io::Error>(res)
        });
        let svc = Compression::new(svc).compress_when(Always);

        // call the service
        let req = Request::builder()
            .header(ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        let headers = res.headers().clone();

        // read the compressed body
        let collected = res.into_body().collect().await.unwrap();
        let compressed_data = collected.to_bytes();

        // decompress the body
        // doing this with flate2 as that is much easier than async-compression and blocking during
        // tests is fine
        let mut decoder = GzDecoder::new(&compressed_data[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();

        assert!(!headers.contains_key(ACCEPT_RANGES));
        assert_eq!(headers[CONTENT_ENCODING], "gzip");
        assert_eq!(decompressed, "Hello, World!");
    }

    #[tokio::test]
    async fn size_hint_identity() {
        const MSG: &str = "Hello, world!";
        let svc = service_fn(async |_| Ok::<_, std::io::Error>(Response::new(Body::from(MSG))));
        let svc = Compression::new(svc);

        let req = Request::new(Body::empty());
        let res = svc.serve(Context::default(), req).await.unwrap();
        let body = res.into_body();
        assert_eq!(body.size_hint().exact().unwrap(), MSG.len() as u64);
    }
}
