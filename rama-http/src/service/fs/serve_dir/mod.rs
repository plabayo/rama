use crate::dep::http_body::{self, Body as HttpBody};
use crate::headers::encoding::{SupportedEncodings, parse_accept_encoding_headers};
use crate::layer::set_status::SetStatus;
use crate::{Body, HeaderValue, Method, Request, Response, StatusCode, header};
use percent_encoding::percent_decode;
use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, OpaqueError};
use rama_core::telemetry::tracing;
use rama_core::{Context, Service};
use std::fmt;
use std::str::FromStr;
use std::{
    convert::Infallible,
    path::{Component, Path, PathBuf},
};

pub(crate) mod future;
mod headers;
mod open_file;

#[cfg(test)]
mod tests;

// default capacity 64KiB
const DEFAULT_CAPACITY: usize = 65536;

/// Service that serves files from a given directory and all its sub directories.
///
/// The `Content-Type` will be guessed from the file extension.
///
/// An empty response with status `404 Not Found` will be returned if:
///
/// - The file doesn't exist
/// - Any segment of the path contains `..`
/// - Any segment of the path contains a backslash
/// - On unix, any segment of the path referenced as directory is actually an
///   existing file (`/file.html/something`)
/// - We don't have necessary permissions to read the file
#[derive(Clone, Debug)]
pub struct ServeDir<F = DefaultServeDirFallback> {
    base: PathBuf,
    buf_chunk_size: usize,
    precompressed_variants: Option<PrecompressedVariants>,
    // This is used to specialise implementation for
    // single files
    variant: ServeVariant,
    fallback: Option<F>,
    call_fallback_on_method_not_allowed: bool,
}

impl ServeDir<DefaultServeDirFallback> {
    /// Create a new [`ServeDir`].
    pub fn new<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let mut base = PathBuf::from(".");
        base.push(path.as_ref());

        Self {
            base,
            buf_chunk_size: DEFAULT_CAPACITY,
            precompressed_variants: None,
            variant: ServeVariant::Directory {
                serve_mode: Default::default(),
            },
            fallback: None,
            call_fallback_on_method_not_allowed: false,
        }
    }

    pub(crate) fn new_single_file<P>(path: P, mime: HeaderValue) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            base: path.as_ref().to_owned(),
            buf_chunk_size: DEFAULT_CAPACITY,
            precompressed_variants: None,
            variant: ServeVariant::SingleFile { mime },
            fallback: None,
            call_fallback_on_method_not_allowed: false,
        }
    }
}

impl<F> ServeDir<F> {
    /// Set the [`DirectoryServeMode`].
    pub fn with_directory_serve_mode(mut self, mode: DirectoryServeMode) -> Self {
        match &mut self.variant {
            ServeVariant::Directory { serve_mode } => {
                *serve_mode = mode;
                self
            }
            ServeVariant::SingleFile { mime: _ } => self,
        }
    }

    /// Set the [`DirectoryServeMode`].
    pub fn set_directory_serve_mode(&mut self, mode: DirectoryServeMode) -> &mut Self {
        match &mut self.variant {
            ServeVariant::Directory { serve_mode } => {
                *serve_mode = mode;
                self
            }
            ServeVariant::SingleFile { mime: _ } => self,
        }
    }

    /// Set a specific read buffer chunk size.
    ///
    /// The default capacity is 64kb.
    pub fn with_buf_chunk_size(mut self, chunk_size: usize) -> Self {
        self.buf_chunk_size = chunk_size;
        self
    }

    /// Set a specific read buffer chunk size.
    ///
    /// The default capacity is 64kb.
    pub fn set_buf_chunk_size(&mut self, chunk_size: usize) -> &mut Self {
        self.buf_chunk_size = chunk_size;
        self
    }

    /// Informs the service that it should also look for a precompressed gzip
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the gzip encoding
    /// will receive the file `dir/foo.txt.gz` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn precompressed_gzip(mut self) -> Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .gzip = true;
        self
    }

    /// Informs the service that it should also look for a precompressed gzip
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the gzip encoding
    /// will receive the file `dir/foo.txt.gz` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn set_precompressed_gzip(&mut self) -> &mut Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .gzip = true;
        self
    }

    /// Informs the service that it should also look for a precompressed brotli
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the brotli encoding
    /// will receive the file `dir/foo.txt.br` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn precompressed_br(mut self) -> Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .br = true;
        self
    }

    /// Informs the service that it should also look for a precompressed brotli
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the brotli encoding
    /// will receive the file `dir/foo.txt.br` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn set_precompressed_br(&mut self) -> &mut Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .br = true;
        self
    }

    /// Informs the service that it should also look for a precompressed deflate
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the deflate encoding
    /// will receive the file `dir/foo.txt.zz` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn precompressed_deflate(mut self) -> Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .deflate = true;
        self
    }

    /// Informs the service that it should also look for a precompressed deflate
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the deflate encoding
    /// will receive the file `dir/foo.txt.zz` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn set_precompressed_deflate(&mut self) -> &mut Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .deflate = true;
        self
    }

    /// Informs the service that it should also look for a precompressed zstd
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the zstd encoding
    /// will receive the file `dir/foo.txt.zst` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn precompressed_zstd(mut self) -> Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .zstd = true;
        self
    }

    /// Informs the service that it should also look for a precompressed zstd
    /// version of _any_ file in the directory.
    ///
    /// Assuming the `dir` directory is being served and `dir/foo.txt` is requested,
    /// a client with an `Accept-Encoding` header that allows the zstd encoding
    /// will receive the file `dir/foo.txt.zst` instead of `dir/foo.txt`.
    /// If the precompressed file is not available, or the client doesn't support it,
    /// the uncompressed version will be served instead.
    /// Both the precompressed version and the uncompressed version are expected
    /// to be present in the directory. Different precompressed variants can be combined.
    pub fn set_precompressed_zstd(&mut self) -> &mut Self {
        self.precompressed_variants
            .get_or_insert(Default::default())
            .zstd = true;
        self
    }

    /// Set the fallback service.
    ///
    /// This service will be called if there is no file at the path of the request.
    ///
    /// The status code returned by the fallback will not be altered. Use
    /// [`ServeDir::not_found_service`] to set a fallback and always respond with `404 Not Found`.
    pub fn fallback<F2>(self, new_fallback: F2) -> ServeDir<F2> {
        ServeDir {
            base: self.base,
            buf_chunk_size: self.buf_chunk_size,
            precompressed_variants: self.precompressed_variants,
            variant: self.variant,
            fallback: Some(new_fallback),
            call_fallback_on_method_not_allowed: self.call_fallback_on_method_not_allowed,
        }
    }

    /// Set the fallback service and override the fallback's status code to `404 Not Found`.
    ///
    /// This service will be called if there is no file at the path of the request.
    pub fn not_found_service<F2>(self, new_fallback: F2) -> ServeDir<SetStatus<F2>> {
        self.fallback(SetStatus::new(new_fallback, StatusCode::NOT_FOUND))
    }

    /// Customize whether or not to call the fallback for requests that aren't `GET` or `HEAD`.
    ///
    /// Defaults to not calling the fallback and instead returning `405 Method Not Allowed`.
    pub fn call_fallback_on_method_not_allowed(mut self, call_fallback: bool) -> Self {
        self.call_fallback_on_method_not_allowed = call_fallback;
        self
    }

    /// Customize whether or not to call the fallback for requests that aren't `GET` or `HEAD`.
    ///
    /// Defaults to not calling the fallback and instead returning `405 Method Not Allowed`.
    pub fn set_call_fallback_on_method_not_allowed(&mut self, call_fallback: bool) -> &mut Self {
        self.call_fallback_on_method_not_allowed = call_fallback;
        self
    }

    /// Call the service and get a future that contains any `std::io::Error` that might have
    /// happened.
    ///
    /// By default `<ServeDir as Service<_>>::call` will handle IO errors and convert them into
    /// responses. It does that by converting [`std::io::ErrorKind::NotFound`] and
    /// [`std::io::ErrorKind::PermissionDenied`] to `404 Not Found` and any other error to `500
    /// Internal Server Error`. The error will also be logged with `tracing`.
    ///
    /// If you want to manually control how the error response is generated you can make a new
    /// service that wraps a `ServeDir` and calls `try_call` instead of `call`.
    pub async fn try_call<State, ReqBody, FResBody>(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Response, std::io::Error>
    where
        State: Clone + Send + Sync + 'static,
        F: Service<State, Request<ReqBody>, Response = Response<FResBody>, Error = Infallible>
            + Clone,
        FResBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        if req.method() != Method::GET && req.method() != Method::HEAD {
            if self.call_fallback_on_method_not_allowed {
                if let Some(fallback) = self.fallback.as_ref() {
                    return future::serve_fallback(fallback, ctx, req).await;
                }
            } else {
                return Ok(future::method_not_allowed());
            }
        }

        // `ServeDir` doesn't care about the request body but the fallback might. So move out the
        // body and pass it to the fallback, leaving an empty body in its place
        //
        // this is necessary because we cannot clone bodies
        let (mut parts, body) = req.into_parts();
        // same goes for extensions
        let extensions = std::mem::take(&mut parts.extensions);
        let req = Request::from_parts(parts, Body::empty());

        let fallback_and_request = self.fallback.as_ref().map(|fallback| {
            let mut fallback_req = Request::new(body);
            *fallback_req.method_mut() = req.method().clone();
            *fallback_req.uri_mut() = req.uri().clone();
            *fallback_req.headers_mut() = req.headers().clone();
            *fallback_req.extensions_mut() = extensions;

            (fallback, ctx, fallback_req)
        });

        let path_to_file = match self
            .variant
            .build_and_validate_path(&self.base, req.uri().path())
        {
            Some(path_to_file) => path_to_file,
            None => {
                return if let Some((fallback, ctx, request)) = fallback_and_request {
                    future::serve_fallback(fallback, ctx, request).await
                } else {
                    Ok(future::not_found())
                };
            }
        };

        let buf_chunk_size = self.buf_chunk_size;
        let range_header = req
            .headers()
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_owned());

        let negotiated_encodings: Vec<_> = parse_accept_encoding_headers(
            req.headers(),
            self.precompressed_variants.unwrap_or_default(),
        )
        .collect();

        let variant = self.variant.clone();

        let open_file_result = open_file::open_file(
            variant,
            path_to_file,
            req,
            negotiated_encodings,
            range_header,
            buf_chunk_size,
        )
        .await;

        future::consume_open_file_result(open_file_result, fallback_and_request).await
    }
}

impl<State, ReqBody, F, FResBody> Service<State, Request<ReqBody>> for ServeDir<F>
where
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    F: Service<State, Request<ReqBody>, Response = Response<FResBody>, Error = Infallible> + Clone,
    FResBody: HttpBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let result = self.try_call(ctx, req).await;
        Ok(result.unwrap_or_else(|err| {
            tracing::error!("Failed to read file: {err:?}");

            let body = Body::empty();
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body)
                .unwrap()
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectoryServeMode {
    #[default]
    /// If the requested path is a directory append `index.html`.
    ///
    /// This is useful for static sites
    AppendIndexHtml,
    /// If the requested path is a directory
    /// handle it as resource "not found" (404).
    NotFound,
    /// Show the file tree of the directory as file tree
    /// which can be navigated.
    HtmlFileList,
}

impl fmt::Display for DirectoryServeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DirectoryServeMode::AppendIndexHtml => "append-index",
                DirectoryServeMode::NotFound => "not-found",
                DirectoryServeMode::HtmlFileList => "html-file-list",
            }
        )
    }
}

impl FromStr for DirectoryServeMode {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        rama_utils::macros::match_ignore_ascii_case_str! {
            match(s) {
                "append-index" | "append_index" => Ok(Self::AppendIndexHtml),
                "not-found" | "not_found" => Ok(Self::NotFound),
                "html-file-list" | "html_file_list" => Ok(Self::HtmlFileList),
                _ => Err(OpaqueError::from_display("invalid DirectoryServeMode str")),
            }
        }
    }
}

impl TryFrom<&str> for DirectoryServeMode {
    type Error = OpaqueError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

// Allow the ServeDir service to be used in the ServeFile service
// with almost no overhead
#[derive(Clone, Debug)]
enum ServeVariant {
    Directory { serve_mode: DirectoryServeMode },
    SingleFile { mime: HeaderValue },
}

impl ServeVariant {
    fn build_and_validate_path(&self, base_path: &Path, requested_path: &str) -> Option<PathBuf> {
        match self {
            ServeVariant::Directory { serve_mode: _ } => {
                let path = requested_path.trim_start_matches('/');

                let path_decoded = percent_decode(path.as_ref()).decode_utf8().ok()?;
                let path_decoded = Path::new(&*path_decoded);

                let mut path_to_file = base_path.to_path_buf();
                for component in path_decoded.components() {
                    match component {
                        Component::Normal(comp) => {
                            // protect against paths like `/foo/c:/bar/baz` (#204)
                            if Path::new(&comp)
                                .components()
                                .all(|c| matches!(c, Component::Normal(_)))
                            {
                                path_to_file.push(comp)
                            } else {
                                return None;
                            }
                        }
                        Component::CurDir => {}
                        Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                            return None;
                        }
                    }
                }
                Some(path_to_file)
            }
            ServeVariant::SingleFile { mime: _ } => Some(base_path.to_path_buf()),
        }
    }
}

/// The default fallback service used with [`ServeDir`].
#[derive(Debug, Clone, Copy)]
pub struct DefaultServeDirFallback(Infallible);

impl<State, ReqBody> Service<State, Request<ReqBody>> for DefaultServeDirFallback
where
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        _ctx: Context<State>,
        _req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        match self.0 {}
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PrecompressedVariants {
    gzip: bool,
    deflate: bool,
    br: bool,
    zstd: bool,
}

impl SupportedEncodings for PrecompressedVariants {
    fn gzip(&self) -> bool {
        self.gzip
    }

    fn deflate(&self) -> bool {
        self.deflate
    }

    fn br(&self) -> bool {
        self.br
    }

    fn zstd(&self) -> bool {
        self.zstd
    }
}
