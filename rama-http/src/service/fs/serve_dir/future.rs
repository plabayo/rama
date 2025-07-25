use super::open_file::{FileOpened, FileRequestExtent, OpenFileOutput};
use crate::headers::encoding::Encoding;
use crate::{
    Body, HeaderValue, Request, Response, StatusCode,
    dep::http_body_util::BodyExt,
    header::{self, ALLOW},
    service::fs::AsyncReadBody,
    service::web::response::{Html, IntoResponse},
};
use rama_core::bytes::Bytes;
use rama_core::{Context, Service, error::BoxError};
use rama_http_types::dep::http_body;
use std::{convert::Infallible, io};

pub(super) async fn consume_open_file_result<State, ReqBody, ResBody, F>(
    open_file_result: Result<OpenFileOutput, std::io::Error>,
    fallback_and_request: Option<(&F, Context<State>, Request<ReqBody>)>,
) -> Result<Response, std::io::Error>
where
    State: Clone + Send + Sync + 'static,
    F: Service<State, Request<ReqBody>, Response = Response<ResBody>, Error = Infallible> + Clone,
    ResBody: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    ResBody::Error: Into<BoxError>,
{
    match open_file_result {
        Ok(OpenFileOutput::FileOpened(file_output)) => Ok(build_response(*file_output)),

        Ok(OpenFileOutput::Redirect { location }) => {
            let mut res = response_with_status(StatusCode::TEMPORARY_REDIRECT);
            res.headers_mut()
                .insert(rama_http_types::header::LOCATION, location);
            Ok(res)
        }

        Ok(OpenFileOutput::Html(payload)) => Ok(Html(payload).into_response()),

        Ok(OpenFileOutput::FileNotFound | OpenFileOutput::InvalidFilename) => {
            if let Some((fallback, ctx, request)) = fallback_and_request {
                serve_fallback(fallback, ctx, request).await
            } else {
                Ok(not_found())
            }
        }

        Ok(OpenFileOutput::PreconditionFailed) => {
            Ok(response_with_status(StatusCode::PRECONDITION_FAILED))
        }

        Ok(OpenFileOutput::NotModified) => Ok(response_with_status(StatusCode::NOT_MODIFIED)),

        Ok(OpenFileOutput::InvalidRedirectUri) => {
            Ok(response_with_status(StatusCode::INTERNAL_SERVER_ERROR))
        }

        Err(err) => {
            #[cfg(unix)]
            // 20 = libc::ENOTDIR => "not a directory
            // when `io_error_more` landed, this can be changed
            // to checking for `io::ErrorKind::NotADirectory`.
            // https://github.com/rust-lang/rust/issues/86442
            let error_is_not_a_directory = err.raw_os_error() == Some(20);
            #[cfg(not(unix))]
            let error_is_not_a_directory = false;

            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) || error_is_not_a_directory
            {
                if let Some((fallback, ctx, request)) = fallback_and_request {
                    serve_fallback(fallback, ctx, request).await
                } else {
                    Ok(not_found())
                }
            } else {
                Err(err)
            }
        }
    }
}

pub(super) fn method_not_allowed() -> Response {
    let mut res = response_with_status(StatusCode::METHOD_NOT_ALLOWED);
    res.headers_mut()
        .insert(ALLOW, HeaderValue::from_static("GET,HEAD"));
    res
}

fn response_with_status(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(empty_body())
        .unwrap()
}

pub(super) fn not_found() -> Response {
    response_with_status(StatusCode::NOT_FOUND)
}

pub(super) async fn serve_fallback<F, State, B, FResBody>(
    fallback: &F,
    ctx: Context<State>,
    req: Request<B>,
) -> Result<Response, std::io::Error>
where
    F: Service<State, Request<B>, Response = Response<FResBody>, Error = Infallible>,
    FResBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    let response = fallback.serve(ctx, req).await.unwrap();
    Ok(response
        .map(|body| {
            body.map_err(|err| match err.into().downcast::<io::Error>() {
                Ok(err) => *err,
                Err(err) => io::Error::other(err),
            })
            .boxed()
        })
        .map(Body::new))
}

fn build_response(output: FileOpened) -> Response {
    let (maybe_file, size) = match output.extent {
        FileRequestExtent::Full(file, meta) => (Some(file), meta.len()),
        FileRequestExtent::Head(meta) => (None, meta.len()),
    };

    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, output.mime_header_value)
        .header(header::ACCEPT_RANGES, "bytes");

    if let Some(encoding) = output
        .maybe_encoding
        .filter(|encoding| *encoding != Encoding::Identity)
    {
        builder = builder.header(header::CONTENT_ENCODING, HeaderValue::from(encoding));
    }

    if let Some(last_modified) = output.last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified.0.to_string());
    }

    match output.maybe_range {
        Some(Ok(ranges)) => {
            if let Some(range) = ranges.first() {
                if ranges.len() > 1 {
                    builder
                        .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .body(body_from_bytes(Bytes::from(
                            "Cannot serve multipart range requests",
                        )))
                        .unwrap()
                } else {
                    let body = if let Some(file) = maybe_file {
                        let range_size = range.end() - range.start() + 1;
                        Body::new(
                            AsyncReadBody::with_capacity_limited(
                                file,
                                output.chunk_size,
                                range_size,
                            )
                            .boxed(),
                        )
                    } else {
                        empty_body()
                    };

                    let content_length = if size == 0 {
                        0
                    } else {
                        range.end() - range.start() + 1
                    };

                    builder
                        .header(
                            header::CONTENT_RANGE,
                            format!("bytes {}-{}/{}", range.start(), range.end(), size),
                        )
                        .header(header::CONTENT_LENGTH, content_length)
                        .status(StatusCode::PARTIAL_CONTENT)
                        .body(body)
                        .unwrap()
                }
            } else {
                builder
                    .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .body(body_from_bytes(Bytes::from(
                        "No range found after parsing range header, please file an issue",
                    )))
                    .unwrap()
            }
        }

        Some(Err(_)) => builder
            .header(header::CONTENT_RANGE, format!("bytes */{size}"))
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .body(empty_body())
            .unwrap(),

        // Not a range request
        None => {
            let body = if let Some(file) = maybe_file {
                Body::new(AsyncReadBody::with_capacity(file, output.chunk_size).boxed())
            } else {
                empty_body()
            };

            builder
                .header(header::CONTENT_LENGTH, size)
                .body(body)
                .unwrap()
        }
    }
}

fn body_from_bytes(bytes: Bytes) -> Body {
    Body::from(bytes)
}

fn empty_body() -> Body {
    Body::empty()
}
