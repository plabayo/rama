use crate::Body;
use crate::dep::http_body::Body as HttpBody;
use crate::dep::http_body_util::BodyExt;
use crate::header::ALLOW;
use crate::service::fs::{DirectoryServeMode, ServeDir, ServeFile};
use crate::{Method, Response, header};
use crate::{Request, StatusCode};
use brotli::BrotliDecompress;
use flate2::bufread::{DeflateDecoder, GzDecoder};
use rama_core::bytes::Bytes;
use rama_core::service::service_fn;
use rama_core::{Context, Service};
use rama_http_types::BodyExtractExt;
use std::convert::Infallible;
use std::io::Read;

#[tokio::test]
async fn basic() {
    let svc = ServeDir::new("..");

    let req = Request::builder()
        .uri("/README.md")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/markdown");

    let body = body_into_text(res.into_body()).await;

    let contents = std::fs::read_to_string("../README.md").unwrap();
    assert_eq!(body, contents);
}

#[tokio::test]
async fn basic_with_index() {
    let svc = ServeDir::new("../test-files");

    let req = Request::new(Body::empty());
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/html");

    let body = body_into_text(res.into_body()).await;

    #[cfg(target_os = "windows")]
    assert_eq!(body, "<b>HTML!</b>\r\n");
    #[cfg(not(target_os = "windows"))]
    assert_eq!(body, "<b>HTML!</b>\n");
}

#[tokio::test]
async fn head_request() {
    let svc = ServeDir::new("../test-files");

    let req = Request::builder()
        .uri("/precompressed.txt")
        .method(Method::HEAD)
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    #[cfg(target_os = "windows")]
    assert_eq!(res.headers()["content-length"], "24");
    #[cfg(not(target_os = "windows"))]
    assert_eq!(res.headers()["content-length"], "23");

    assert!(res.into_body().frame().await.is_none());
}

#[tokio::test]
async fn precompresed_head_request() {
    let svc = ServeDir::new("../test-files").precompressed_gzip();

    let req = Request::builder()
        .uri("/precompressed.txt")
        .header("Accept-Encoding", "gzip")
        .method(Method::HEAD)
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.headers()["content-encoding"], "gzip");
    assert_eq!(res.headers()["content-length"], "59");

    assert!(res.into_body().frame().await.is_none());
}

#[tokio::test]
async fn with_custom_chunk_size() {
    let svc = ServeDir::new("..").with_buf_chunk_size(1024 * 32);

    let req = Request::builder()
        .uri("/README.md")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/markdown");

    let body = body_into_text(res.into_body()).await;

    let contents = std::fs::read_to_string("../README.md").unwrap();
    assert_eq!(body, contents);
}

#[tokio::test]
async fn precompressed_gzip() {
    let svc = ServeDir::new("../test-files").precompressed_gzip();

    let req = Request::builder()
        .uri("/precompressed.txt")
        .header("Accept-Encoding", "gzip")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.headers()["content-encoding"], "gzip");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let mut decoder = GzDecoder::new(&body[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();
    assert!(decompressed.starts_with("\"This is a test file!\""));
}

#[tokio::test]
async fn precompressed_br() {
    let svc = ServeDir::new("../test-files").precompressed_br();

    let req = Request::builder()
        .uri("/precompressed.txt")
        .header("Accept-Encoding", "br")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.headers()["content-encoding"], "br");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let mut decompressed = Vec::new();
    BrotliDecompress(&mut &body[..], &mut decompressed).unwrap();
    let decompressed = String::from_utf8(decompressed.clone()).unwrap();
    assert!(decompressed.starts_with("\"This is a test file!\""));
}

#[tokio::test]
async fn precompressed_deflate() {
    let svc = ServeDir::new("../test-files").precompressed_deflate();
    let request = Request::builder()
        .uri("/precompressed.txt")
        .header("Accept-Encoding", "deflate,br")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), request).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.headers()["content-encoding"], "deflate");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let mut decoder = DeflateDecoder::new(&body[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();
    assert!(decompressed.starts_with("\"This is a test file!\""));
}

#[tokio::test]
async fn unsupported_precompression_algorithm_fallbacks_to_uncompressed() {
    let svc = ServeDir::new("../test-files").precompressed_gzip();

    let request = Request::builder()
        .uri("/precompressed.txt")
        .header("Accept-Encoding", "br")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), request).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert!(res.headers().get("content-encoding").is_none());

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.starts_with("\"This is a test file!\""));
}

#[tokio::test]
async fn only_precompressed_variant_existing() {
    let svc = ServeDir::new("../test-files").precompressed_gzip();

    let request = Request::builder()
        .uri("/only_gzipped.txt")
        .body(Body::empty())
        .unwrap();
    let res = svc
        .clone()
        .serve(Context::default(), request)
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Should reply with gzipped file if client supports it
    let request = Request::builder()
        .uri("/only_gzipped.txt")
        .header("Accept-Encoding", "gzip")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), request).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.headers()["content-encoding"], "gzip");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let mut decoder = GzDecoder::new(&body[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();
    assert!(decompressed.starts_with("\"This is a test file\""));
}

#[tokio::test]
async fn missing_precompressed_variant_fallbacks_to_uncompressed() {
    let svc = ServeDir::new("../test-files").precompressed_gzip();

    let request = Request::builder()
        .uri("/missing_precompressed.txt")
        .header("Accept-Encoding", "gzip")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), request).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    // Uncompressed file is served because compressed version is missing
    assert!(res.headers().get("content-encoding").is_none());

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.starts_with("Test file!"));
}

#[tokio::test]
async fn missing_precompressed_variant_fallbacks_to_uncompressed_for_head_request() {
    let svc = ServeDir::new("../test-files").precompressed_gzip();

    let request = Request::builder()
        .uri("/missing_precompressed.txt")
        .header("Accept-Encoding", "gzip")
        .method(Method::HEAD)
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), request).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    #[cfg(target_os = "windows")]
    assert_eq!(res.headers()["content-length"], "12");
    #[cfg(not(target_os = "windows"))]
    assert_eq!(res.headers()["content-length"], "11");
    // Uncompressed file is served because compressed version is missing
    assert!(res.headers().get("content-encoding").is_none());

    assert!(res.into_body().frame().await.is_none());
}

#[tokio::test]
async fn access_to_sub_dirs() {
    let svc = ServeDir::new("..");

    let req = Request::builder()
        .uri("/Cargo.toml")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/x-toml");

    let body = body_into_text(res.into_body()).await;

    let contents = std::fs::read_to_string("../Cargo.toml").unwrap();
    assert_eq!(body, contents);
}

#[tokio::test]
async fn not_found() {
    let svc = ServeDir::new("..");

    let req = Request::builder()
        .uri("/not-found")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::CONTENT_TYPE).is_none());

    let body = body_into_text(res.into_body()).await;
    assert!(body.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn not_found_when_not_a_directory() {
    let svc = ServeDir::new("../test-files");

    // `index.html` is a file, and we are trying to request
    // it as a directory.
    let req = Request::builder()
        .uri("/index.html/some_file")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    // This should lead to a 404
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::CONTENT_TYPE).is_none());

    let body = body_into_text(res.into_body()).await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn not_found_precompressed() {
    let svc = ServeDir::new("../test-files").precompressed_gzip();

    let req = Request::builder()
        .uri("/not-found")
        .header("Accept-Encoding", "gzip")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::CONTENT_TYPE).is_none());

    let body = body_into_text(res.into_body()).await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn fallbacks_to_different_precompressed_variant_if_not_found_for_head_request() {
    let svc = ServeDir::new("../test-files")
        .precompressed_gzip()
        .precompressed_br();

    let req = Request::builder()
        .uri("/precompressed_br.txt")
        .header("Accept-Encoding", "gzip,br,deflate")
        .method(Method::HEAD)
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.headers()["content-encoding"], "br");
    assert_eq!(res.headers()["content-length"], "15");

    assert!(res.into_body().frame().await.is_none());
}

#[tokio::test]
async fn fallbacks_to_different_precompressed_variant_if_not_found() {
    let svc = ServeDir::new("../test-files")
        .precompressed_gzip()
        .precompressed_br();

    let req = Request::builder()
        .uri("/precompressed_br.txt")
        .header("Accept-Encoding", "gzip,br,deflate")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["content-type"], "text/plain");
    assert_eq!(res.headers()["content-encoding"], "br");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let mut decompressed = Vec::new();
    BrotliDecompress(&mut &body[..], &mut decompressed).unwrap();
    let decompressed = String::from_utf8(decompressed.clone()).unwrap();
    assert!(decompressed.starts_with("Test file"));
}

#[tokio::test]
async fn redirect_to_trailing_slash_on_dir() {
    let svc = ServeDir::new("..");

    let req = Request::builder().uri("/src").body(Body::empty()).unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = &res.headers()[rama_http_types::header::LOCATION];
    assert_eq!(location, "/src/");
}

#[tokio::test]
async fn empty_directory_without_index() {
    let svc = ServeDir::new("..").with_directory_serve_mode(DirectoryServeMode::NotFound);

    let req = Request::new(Body::empty());
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::CONTENT_TYPE).is_none());

    let body = body_into_text(res.into_body()).await;
    assert!(body.is_empty());
}

#[tokio::test]
async fn serve_directory_as_file_tree() {
    let svc =
        ServeDir::new("../test-files").with_directory_serve_mode(DirectoryServeMode::HtmlFileList);

    let req = Request::new(Body::empty());
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/html; charset=utf-8");

    let payload = res.into_body().try_into_string().await.unwrap();
    assert!(payload.contains("Directory listing for"));
    assert!(payload.contains("hello.txt"));
    assert!(payload.contains("index.html"));
}

#[tokio::test]
async fn empty_directory_without_index_no_information_leak() {
    let svc = ServeDir::new("..").with_directory_serve_mode(DirectoryServeMode::NotFound);

    let req = Request::builder()
        .uri("/test-files")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::CONTENT_TYPE).is_none());

    let body = body_into_text(res.into_body()).await;
    assert!(body.is_empty());
}

async fn body_into_text<B>(body: B) -> String
where
    B: HttpBody<Data = rama_core::bytes::Bytes, Error: std::fmt::Debug> + Unpin,
{
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn access_cjk_percent_encoded_uri_path() {
    // percent encoding present of 你好世界.txt
    let cjk_filename_encoded = "%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C.txt";

    let svc = ServeDir::new("../test-files");

    let req = Request::builder()
        .uri(format!("/{cjk_filename_encoded}"))
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/plain");
}

#[tokio::test]
async fn access_space_percent_encoded_uri_path() {
    let encoded_filename = "filename%20with%20space.txt";

    let svc = ServeDir::new("../test-files");

    let req = Request::builder()
        .uri(format!("/{encoded_filename}"))
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/plain");
}

#[tokio::test]
async fn read_partial_empty() {
    let svc = ServeDir::new("../test-files");

    let req = Request::builder()
        .uri("/empty.txt")
        .header("Range", "bytes=0-")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(res.headers()["content-length"], "0");
    assert_eq!(res.headers()["content-range"], "bytes 0-0/0");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
}

#[tokio::test]
async fn read_partial_in_bounds() {
    let svc = ServeDir::new("..");
    let bytes_start_incl = 9;
    let bytes_end_incl = 1023;

    let req = Request::builder()
        .uri("/README.md")
        .header(
            "Range",
            format!("bytes={bytes_start_incl}-{bytes_end_incl}"),
        )
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    let file_contents = std::fs::read("../README.md").unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        res.headers()["content-length"],
        (bytes_end_incl - bytes_start_incl + 1).to_string()
    );
    assert!(
        res.headers()["content-range"]
            .to_str()
            .unwrap()
            .starts_with(&format!(
                "bytes {}-{}/{}",
                bytes_start_incl,
                bytes_end_incl,
                file_contents.len()
            ))
    );
    assert_eq!(res.headers()["content-type"], "text/markdown");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let source = Bytes::from(file_contents[bytes_start_incl..=bytes_end_incl].to_vec());
    assert_eq!(body, source);
}

#[tokio::test]
async fn read_partial_accepts_out_of_bounds_range() {
    let svc = ServeDir::new("..");
    let bytes_start_incl = 0;
    let bytes_end_excl = 9999999;
    let requested_len = bytes_end_excl - bytes_start_incl;

    let req = Request::builder()
        .uri("/README.md")
        .header(
            "Range",
            format!("bytes={}-{}", bytes_start_incl, requested_len - 1),
        )
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    let file_contents = std::fs::read("../README.md").unwrap();
    assert_eq!(
        res.headers()["content-range"],
        &format!(
            "bytes 0-{}/{}",
            file_contents.len() - 1,
            file_contents.len()
        )
    )
}

#[tokio::test]
async fn read_partial_errs_on_garbage_header() {
    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .header("Range", "bad_format")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    let file_contents = std::fs::read("../README.md").unwrap();
    assert_eq!(
        res.headers()["content-range"],
        &format!("bytes */{}", file_contents.len())
    )
}

#[tokio::test]
async fn read_partial_errs_on_bad_range() {
    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .header("Range", "bytes=-1-15")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    let file_contents = std::fs::read("../README.md").unwrap();
    assert_eq!(
        res.headers()["content-range"],
        &format!("bytes */{}", file_contents.len())
    )
}

#[tokio::test]
async fn accept_encoding_identity() {
    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .header("Accept-Encoding", "identity")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // Identity encoding should not be included in the response headers
    assert!(res.headers().get("content-encoding").is_none());
}

#[tokio::test]
async fn last_modified() {
    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let last_modified = res
        .headers()
        .get(header::LAST_MODIFIED)
        .expect("Missing last modified header!");

    // -- If-Modified-Since

    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .header(header::IF_MODIFIED_SINCE, last_modified)
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert!(res.into_body().frame().await.is_none());

    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .header(header::IF_MODIFIED_SINCE, "Fri, 09 Aug 1996 14:21:40 GMT")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let readme_bytes = include_bytes!("../../../../../README.md");
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), readme_bytes);

    // -- If-Unmodified-Since

    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .header(header::IF_UNMODIFIED_SINCE, last_modified)
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), readme_bytes);

    let svc = ServeDir::new("..");
    let req = Request::builder()
        .uri("/README.md")
        .header(header::IF_UNMODIFIED_SINCE, "Fri, 09 Aug 1996 14:21:40 GMT")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
    assert!(res.into_body().frame().await.is_none());
}

#[tokio::test]
async fn with_fallback_svc() {
    async fn fallback(req: Request) -> Result<Response, Infallible> {
        Ok(Response::new(Body::from(format!(
            "from fallback {}",
            req.uri().path()
        ))))
    }

    let svc = ServeDir::new("..").fallback(service_fn(fallback));

    let req = Request::builder()
        .uri("/doesnt-exist")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let body = body_into_text(res.into_body()).await;
    assert_eq!(body, "from fallback /doesnt-exist");
}

#[tokio::test]
async fn with_fallback_serve_file() {
    let svc = ServeDir::new("..").fallback(ServeFile::new("../README.md"));

    let req = Request::builder()
        .uri("/doesnt-exist")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/markdown");

    let body = body_into_text(res.into_body()).await;

    let contents = std::fs::read_to_string("../README.md").unwrap();
    assert_eq!(body, contents);
}

#[tokio::test]
async fn method_not_allowed() {
    let svc = ServeDir::new("..");

    let req = Request::builder()
        .method(Method::POST)
        .uri("/README.md")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(res.headers()[ALLOW], "GET,HEAD");
}

#[tokio::test]
async fn calling_fallback_on_not_allowed() {
    async fn fallback(req: Request) -> Result<Response, Infallible> {
        Ok(Response::new(Body::from(format!(
            "from fallback {}",
            req.uri().path()
        ))))
    }

    let svc = ServeDir::new("..")
        .call_fallback_on_method_not_allowed(true)
        .fallback(service_fn(fallback));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/doesnt-exist")
        .body(Body::empty())
        .unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let body = body_into_text(res.into_body()).await;
    assert_eq!(body, "from fallback /doesnt-exist");
}

#[tokio::test]
async fn with_fallback_svc_and_not_append_index_html_on_directories() {
    async fn fallback(req: Request) -> Result<Response, Infallible> {
        Ok(Response::new(Body::from(format!(
            "from fallback {}",
            req.uri().path()
        ))))
    }

    let svc = ServeDir::new("..")
        .with_directory_serve_mode(DirectoryServeMode::NotFound)
        .fallback(service_fn(fallback));

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let body = body_into_text(res.into_body()).await;
    assert_eq!(body, "from fallback /");
}

#[tokio::test]
async fn calls_fallback_on_invalid_paths() {
    async fn fallback<T>(_: T) -> Result<Response, Infallible> {
        let mut res = Response::new(Body::empty());
        res.headers_mut()
            .insert("from-fallback", "1".parse().unwrap());
        Ok(res)
    }

    let svc = ServeDir::new("..").fallback(service_fn(fallback));

    let req = Request::builder()
        .uri("/weird_%c3%28_path")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["from-fallback"], "1");
}
// https://github.com/tower-rs/tower-http/issues/573
#[tokio::test]
async fn calls_fallback_on_invalid_filenames() {
    async fn fallback<T>(_: T) -> Result<Response<Body>, Infallible> {
        let mut res = Response::new(Body::empty());
        res.headers_mut()
            .insert("from-fallback", "1".parse().unwrap());
        Ok(res)
    }

    let svc = ServeDir::new("..").fallback(service_fn(fallback));

    let req = Request::builder()
        .uri("/invalid|path")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["from-fallback"], "1");
}

#[tokio::test]
async fn calls_fallback_on_null() {
    async fn fallback<T>(_: T) -> Result<Response<Body>, Infallible> {
        let mut res = Response::new(Body::empty());
        res.headers_mut()
            .insert("from-fallback", "1".parse().unwrap());
        Ok(res)
    }

    let svc = ServeDir::new("..").fallback(service_fn(fallback));

    let req = Request::builder()
        .uri("/invalid-path%00")
        .body(Body::empty())
        .unwrap();

    let res = svc.serve(Context::default(), req).await.unwrap();

    assert_eq!(res.headers()["from-fallback"], "1");
}
