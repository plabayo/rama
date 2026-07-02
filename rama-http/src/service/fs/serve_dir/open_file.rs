use super::{
    DirSource, DirectoryServeMode, ServeDirSymlinkPolicy, ServeVariant,
    headers::{IfModifiedSince, IfUnmodifiedSince, LastModified, etag_from_metadata},
};
use crate::headers::{ETag, HeaderMapExt as _, IfMatch, IfNoneMatch};
use crate::headers::{encoding::Encoding, specifier::QualityValue};
use crate::{HeaderValue, Method, Request, header};
use http_range_header::RangeUnsatisfiableError;
use rama_core::combinators::Either;
use rama_core::telemetry::tracing;
use rama_http_types::mime::Mime;
use rama_net::uri::Uri;
use rama_utils::include_dir::{Dir, Metadata as EmbeddedMetadata};
use std::io::Cursor;
use std::{
    ffi::OsStr,
    fs::Metadata,
    io::{self, ErrorKind, SeekFrom},
    ops::RangeInclusive,
    path::{Path, PathBuf},
};
use tokio::io::AsyncRead;
use tokio::{fs::File, io::AsyncSeekExt};

// All html-only state (DirEntry, HumanSize, generate_directory_html, the
// emoji/size helpers, the per-helper unit tests) lives in a sibling
// file pulled in via `#[path]` so the gating is paid for exactly once.
#[cfg(feature = "html")]
#[path = "open_file_html.rs"]
mod html;

/// Represents the outcome of attempting to open a file for serving.
pub(super) enum OpenFileOutput {
    FileOpened(Box<FileOpened>),
    Redirect {
        location: HeaderValue,
    },
    #[cfg(feature = "html")]
    Html(String),
    FileNotFound,
    PreconditionFailed,
    NotModified {
        etag: Option<ETag>,
        last_modified: Option<LastModified>,
    },
    InvalidFilename,
}

impl OpenFileOutput {
    /// Create a new FileOpened variant with the given parameters.
    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper aggregating the opened-file response data"
    )]
    pub(super) fn new_file_opened(
        extent: FileRequestExtent,
        chunk_size: usize,
        mime: Mime,
        maybe_encoding: Option<Encoding>,
        maybe_range: Option<Result<Vec<RangeInclusive<u64>>, RangeUnsatisfiableError>>,
        last_modified: Option<LastModified>,
        precompression_configured: bool,
        etag: Option<ETag>,
    ) -> Self {
        Self::FileOpened(Box::new(FileOpened {
            extent,
            chunk_size,
            mime_value: mime,
            maybe_encoding,
            maybe_range,
            last_modified,
            precompression_configured,
            etag,
        }))
    }
}

/// Contains the data for a successfully opened file ready for serving.
pub(super) struct FileOpened {
    pub(super) extent: FileRequestExtent,
    pub(super) chunk_size: usize,
    pub(super) mime_value: Mime,
    pub(super) maybe_encoding: Option<Encoding>,
    pub(super) maybe_range: Option<Result<Vec<RangeInclusive<u64>>, RangeUnsatisfiableError>>,
    pub(super) last_modified: Option<LastModified>,
    /// Whether `ServeDir` was configured with any precompressed variants.
    /// When true, the response advertises `Vary: Accept-Encoding` even if
    /// this particular response was served uncompressed, per RFC 9110
    /// §12.5.3 — a different request could yield a different encoding.
    pub(super) precompression_configured: bool,
    /// Strong [`ETag`] derived from the file metadata, when available.
    pub(super) etag: Option<ETag>,
}

/// Represents different ways a file can be accessed for serving.
pub(super) enum FileRequestExtent {
    Full(File, Metadata),
    Head(Metadata),
    Embedded(Vec<u8>, u64), // Content, original file size
    EmbeddedHead(u64),      // Content length for HEAD requests on embedded files
}

impl FileRequestExtent {
    /// Convert the file extent into an async reader if possible.
    pub(super) fn into_reader(self) -> Option<impl AsyncRead + Send + Sync + Unpin> {
        match self {
            Self::Head(_) | Self::EmbeddedHead(_) => None,
            Self::Full(file, _) => Some(Either::A(file)),
            Self::Embedded(content, _) => Some(Either::B(Cursor::new(content))),
        }
    }

    pub(super) fn file_size(&self) -> u64 {
        match self {
            Self::Head(meta) | Self::Full(_, meta) => meta.len(),
            Self::Embedded(_, original_size) => *original_size,
            Self::EmbeddedHead(size) => *size,
        }
    }
}

/// Open a file for serving, handling both filesystem and embedded sources.
/// Supports precompressed variants, range requests, and conditional headers.
#[expect(
    clippy::too_many_arguments,
    reason = "internal helper; each arg has a distinct role and grouping them into a struct adds more noise than it removes"
)]
pub(super) async fn open_file(
    variant: ServeVariant,
    mut path_to_file: PathBuf,
    req: Request,
    negotiated_encodings: Vec<QualityValue<Encoding>>,
    range_header: Option<&str>,
    buf_chunk_size: usize,
    source: &DirSource,
    precompression_configured: bool,
    symlink_policy: ServeDirSymlinkPolicy,
) -> io::Result<OpenFileOutput> {
    let mime = match variant {
        ServeVariant::Directory {
            serve_mode,
            html_as_default_extension,
        } => {
            // Might already at this point know a redirect or not found result should be
            // returned which corresponds to a Some(output). Otherwise the path might be
            // modified and proceed to the open file/metadata future.
            if let Some(output) = maybe_serve_directory(
                &mut path_to_file,
                req.uri(),
                serve_mode,
                html_as_default_extension,
                source,
                symlink_policy,
            )
            .await?
            {
                return Ok(output);
            }

            guess_mime_type(&path_to_file)
        }

        ServeVariant::SingleFile { mime } => mime,
    };

    let preconditions = Preconditions::from_request(&req);

    if req.method() == Method::HEAD {
        match source {
            DirSource::Filesystem(_) => {
                let (meta, maybe_encoding) = file_metadata_with_fallback(
                    source,
                    path_to_file,
                    negotiated_encodings,
                    symlink_policy,
                )
                .await?;

                let last_modified = meta.modified().ok().map(LastModified::from);
                let etag = meta
                    .modified()
                    .ok()
                    .and_then(|mtime| etag_from_metadata(meta.len(), mtime));
                if let Some(output) = preconditions.check(etag.as_ref(), last_modified.as_ref()) {
                    return Ok(output);
                }

                let maybe_range = try_parse_range(range_header, meta.len());

                Ok(OpenFileOutput::new_file_opened(
                    FileRequestExtent::Head(meta),
                    buf_chunk_size,
                    mime,
                    maybe_encoding,
                    maybe_range,
                    last_modified,
                    precompression_configured,
                    etag,
                ))
            }
            DirSource::Embedded(base) => {
                let (contents, metadata, maybe_encoding) = match open_embedded_file_with_fallback(
                    base,
                    path_to_file,
                    negotiated_encodings,
                ) {
                    Ok(result) => result,
                    Err(err) => return Err(err),
                };

                let content_length = contents.len() as u64;
                let last_modified =
                    metadata.map(|metadata| LastModified::from(metadata.modified()));
                let etag = metadata
                    .and_then(|metadata| etag_from_metadata(content_length, metadata.modified()));

                if let Some(output) = preconditions.check(etag.as_ref(), last_modified.as_ref()) {
                    return Ok(output);
                }

                let maybe_range = try_parse_range(range_header, content_length);

                Ok(OpenFileOutput::new_file_opened(
                    FileRequestExtent::EmbeddedHead(content_length),
                    buf_chunk_size,
                    mime,
                    maybe_encoding,
                    maybe_range,
                    last_modified,
                    precompression_configured,
                    etag,
                ))
            }
        }
    } else {
        match source {
            DirSource::Filesystem(_) => {
                let (mut file, maybe_encoding) = match open_file_with_fallback(
                    source,
                    path_to_file,
                    negotiated_encodings,
                    symlink_policy,
                )
                .await
                {
                    Ok(result) => result,
                    Err(err) if is_invalid_filename_error(&err) => {
                        return Ok(OpenFileOutput::InvalidFilename);
                    }
                    Err(err) => return Err(err),
                };
                let meta = file.metadata().await?;
                let last_modified = meta.modified().ok().map(LastModified::from);
                let etag = meta
                    .modified()
                    .ok()
                    .and_then(|mtime| etag_from_metadata(meta.len(), mtime));
                if let Some(output) = preconditions.check(etag.as_ref(), last_modified.as_ref()) {
                    return Ok(output);
                }

                let maybe_range = try_parse_range(range_header, meta.len());
                if let Some(Ok(ranges)) = maybe_range.as_ref()
                    && ranges.len() == 1
                {
                    file.seek(SeekFrom::Start(*ranges[0].start())).await?;
                }

                Ok(OpenFileOutput::new_file_opened(
                    FileRequestExtent::Full(file, meta),
                    buf_chunk_size,
                    mime,
                    maybe_encoding,
                    maybe_range,
                    last_modified,
                    precompression_configured,
                    etag,
                ))
            }
            DirSource::Embedded(base) => {
                let (contents, metadata, maybe_encoding) = match open_embedded_file_with_fallback(
                    base,
                    path_to_file,
                    negotiated_encodings,
                ) {
                    Ok(result) => result,
                    Err(err) => return Err(err),
                };

                let content_length = contents.len() as u64;
                let last_modified = metadata
                    .as_ref()
                    .map(|meta| LastModified::from(meta.modified()));
                let etag =
                    metadata.and_then(|meta| etag_from_metadata(content_length, meta.modified()));

                if let Some(output) = preconditions.check(etag.as_ref(), last_modified.as_ref()) {
                    return Ok(output);
                }

                let maybe_range = try_parse_range(range_header, content_length);

                let mut content = contents;
                if let Some(Ok(ranges)) = maybe_range.as_ref()
                    && ranges.len() == 1
                {
                    let start = *ranges[0].start() as usize;
                    content.drain(0..start.min(content.len()));
                }

                Ok(OpenFileOutput::new_file_opened(
                    FileRequestExtent::Embedded(content, content_length),
                    buf_chunk_size,
                    mime,
                    maybe_encoding,
                    maybe_range,
                    last_modified,
                    precompression_configured,
                    etag,
                ))
            }
        }
    }
}

/// Check if an IO error indicates an invalid filename.
fn is_invalid_filename_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::InvalidInput | ErrorKind::InvalidFilename
    )
}

// Common MIME type guessing logic
/// Guess the MIME type from a file path extension.
fn guess_mime_type(path: &Path) -> Mime {
    crate::mime::guess::from_path(path)
        .first()
        .unwrap_or(crate::mime::APPLICATION_OCTET_STREAM)
}

/// Conditional request precondition headers parsed from the request.
struct Preconditions {
    if_match: Option<IfMatch>,
    if_unmodified_since: Option<IfUnmodifiedSince>,
    if_none_match: Option<IfNoneMatch>,
    if_modified_since: Option<IfModifiedSince>,
}

impl Preconditions {
    fn from_request(req: &Request) -> Self {
        Self {
            if_match: req.headers().typed_get::<IfMatch>(),
            if_unmodified_since: req
                .headers()
                .get(header::IF_UNMODIFIED_SINCE)
                .and_then(IfUnmodifiedSince::from_header_value),
            if_none_match: req.headers().typed_get::<IfNoneMatch>(),
            if_modified_since: req
                .headers()
                .get(header::IF_MODIFIED_SINCE)
                .and_then(IfModifiedSince::from_header_value),
        }
    }

    /// Evaluate preconditions per [RFC 9110 §13.2.2](https://www.rfc-editor.org/rfc/rfc9110#section-13.2.2).
    ///
    /// Precedence order:
    /// 1. `If-Match` (strong comparison) → 412 on failure
    /// 2. `If-Unmodified-Since` (only if `If-Match` absent) → 412 on failure
    /// 3. `If-None-Match` (weak comparison) → 304 on failure (for GET/HEAD)
    /// 4. `If-Modified-Since` (only if `If-None-Match` absent) → 304 on failure
    fn check(
        self,
        etag: Option<&ETag>,
        last_modified: Option<&LastModified>,
    ) -> Option<OpenFileOutput> {
        // Step 1: If-Match. RFC 9110 §13.1.1: with no current representation (no ETag), the
        // condition is false, including for `*`.
        if let Some(if_match) = self.if_match {
            let passes = etag
                .map(|etag| if_match.precondition_passes(etag))
                .unwrap_or(false);
            if !passes {
                return Some(OpenFileOutput::PreconditionFailed);
            }
        } else if let Some(since) = self.if_unmodified_since {
            // Step 2: If-Unmodified-Since (only when If-Match is absent). RFC 9110 §13.1.4:
            // ignored when no modification date is available.
            let passes = last_modified
                .map(|lm| since.precondition_passes(lm))
                .unwrap_or(true);
            if !passes {
                return Some(OpenFileOutput::PreconditionFailed);
            }
        }

        // Step 3: If-None-Match (weak comparison). No ETag means the condition is vacuously
        // satisfied, so serve normally.
        if let Some(if_none_match) = self.if_none_match {
            let passes = etag
                .map(|etag| if_none_match.precondition_passes(etag))
                .unwrap_or(true);
            if !passes {
                return Some(OpenFileOutput::NotModified {
                    etag: etag.cloned(),
                    last_modified: last_modified.cloned(),
                });
            }
        } else if let Some(since) = self.if_modified_since {
            // Step 4: If-Modified-Since (only when If-None-Match is absent). No last-modified
            // date means it is treated as modified (serve normally).
            let unmodified = last_modified
                .map(|lm| !since.is_modified(lm))
                .unwrap_or(false);
            if unmodified {
                return Some(OpenFileOutput::NotModified {
                    etag: etag.cloned(),
                    last_modified: last_modified.cloned(),
                });
            }
        }

        None
    }
}

// Returns the preferred_encoding encoding and modifies the path extension
// to the corresponding file extension for the encoding.
/// Determine the preferred encoding from negotiated encodings and modify the path
/// to include the appropriate file extension for the encoding.
fn preferred_encoding(
    path: &mut PathBuf,
    negotiated_encoding: &[QualityValue<Encoding>],
) -> Option<Encoding> {
    let preferred_encoding =
        Encoding::maybe_preferred_encoding(negotiated_encoding.iter().copied());

    if let Some(file_extension) =
        preferred_encoding.and_then(|encoding| encoding.to_file_extension())
    {
        let new_extension = path
            .extension()
            .map(|extension| {
                let mut os_string = extension.to_os_string();
                os_string.push(file_extension);
                os_string
            })
            .unwrap_or_else(|| file_extension.to_os_string());

        path.set_extension(new_extension);
    }

    preferred_encoding
}

// Attempts to open the file with any of the possible negotiated_encodings in the
// preferred order. If none of the negotiated_encodings have a corresponding precompressed
// file the uncompressed file is used as a fallback.
/// Attempt to open a file with any of the negotiated encodings in preferred order.
/// Falls back to uncompressed file if no precompressed variants are found.
async fn open_file_with_fallback(
    source: &DirSource,
    mut path: PathBuf,
    mut negotiated_encoding: Vec<QualityValue<Encoding>>,
    symlink_policy: ServeDirSymlinkPolicy,
) -> io::Result<(File, Option<Encoding>)> {
    let (file, encoding) = loop {
        // Get the preferred encoding among the negotiated ones.
        let encoding = preferred_encoding(&mut path, &negotiated_encoding);
        match (
            filesystem_metadata(source, &path, symlink_policy).await,
            encoding,
        ) {
            (Ok(_), maybe_encoding) => break (File::open(&path).await?, maybe_encoding),
            // Identity has no file extension to strip, so falling through to
            // the strip-and-retry path would clobber the originally requested
            // extension (e.g. `/foo.foobar` would become `/foo`). Only strip
            // when the preferred encoding actually appended an extension.
            // Regression test: see `identity_encoding_does_not_strip_extension`.
            (Err(err), Some(encoding))
                if err.kind() == io::ErrorKind::NotFound && encoding != Encoding::Identity =>
            {
                // Remove the extension corresponding to a precompressed file (.gz, .br, .zz)
                // to reset the path before the next iteration.
                path.set_extension(OsStr::new(""));
                // Remove the encoding from the negotiated_encodings since the file doesn't exist
                negotiated_encoding.retain(|qv| qv.value != encoding);
            }
            (Err(err), _) => return Err(err),
        };
    };
    Ok((file, encoding))
}

/// Attempt to open an embedded file with any of the negotiated encodings.
/// Falls back to uncompressed file if no precompressed variants are found.
fn open_embedded_file_with_fallback(
    base: &Dir<'_>,
    mut path: PathBuf,
    mut negotiated_encoding: Vec<QualityValue<Encoding>>,
) -> io::Result<(Vec<u8>, Option<EmbeddedMetadata>, Option<Encoding>)> {
    let (file, encoding) = loop {
        // Get the preferred encoding among the negotiated ones.
        let encoding = preferred_encoding(&mut path, &negotiated_encoding);
        match (base.get_file(&path), encoding) {
            (Some(file), maybe_encoding) => break (file, maybe_encoding),
            (None, Some(encoding)) if encoding != Encoding::Identity => {
                // Remove the extension corresponding to a precompressed file (.gz, .br, .zz)
                // to reset the path before the next iteration.
                path.set_extension(OsStr::new(""));
                // Remove the encoding from the negotiated_encodings since the file doesn't exist
                negotiated_encoding.retain(|qv| qv.value != encoding);
            }
            (None, Some(_) | None) => {
                return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
            }
        };
    };

    let content = file.contents().to_vec();
    let metadata = file.metadata().copied();

    Ok((content, metadata, encoding))
}

// Attempts to get the file metadata with any of the possible negotiated_encodings in the
// preferred order. If none of the negotiated_encodings have a corresponding precompressed
// file the uncompressed file is used as a fallback.
/// Get file metadata with fallback for different encodings.
async fn file_metadata_with_fallback(
    source: &DirSource,
    mut path: PathBuf,
    mut negotiated_encoding: Vec<QualityValue<Encoding>>,
    symlink_policy: ServeDirSymlinkPolicy,
) -> io::Result<(Metadata, Option<Encoding>)> {
    let (file, encoding) = loop {
        // Get the preferred encoding among the negotiated ones.
        let encoding = preferred_encoding(&mut path, &negotiated_encoding);
        match (
            filesystem_metadata(source, &path, symlink_policy).await,
            encoding,
        ) {
            (Ok(file), maybe_encoding) => break (file, maybe_encoding),
            // See `open_file_with_fallback` for why Identity is skipped here.
            (Err(err), Some(encoding))
                if err.kind() == io::ErrorKind::NotFound && encoding != Encoding::Identity =>
            {
                // Remove the extension corresponding to a precompressed file (.gz, .br, .zz)
                // to reset the path before the next iteration.
                path.set_extension(OsStr::new(""));
                // Remove the encoding from the negotiated_encodings since the file doesn't exist
                negotiated_encoding.retain(|qv| qv.value != encoding);
            }
            (Err(err), _) => return Err(err),
        };
    };
    Ok((file, encoding))
}

async fn filesystem_metadata(
    source: &DirSource,
    path: &Path,
    symlink_policy: ServeDirSymlinkPolicy,
) -> io::Result<Metadata> {
    match source {
        DirSource::Filesystem(root) => {
            filesystem_metadata_from_root(root, path, symlink_policy).await
        }
        DirSource::Embedded(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "embedded sources do not use filesystem metadata",
        )),
    }
}

async fn filesystem_metadata_from_root(
    root: &Path,
    path: &Path,
    symlink_policy: ServeDirSymlinkPolicy,
) -> io::Result<Metadata> {
    if symlink_policy == ServeDirSymlinkPolicy::AllowAll {
        return tokio::fs::metadata(path).await;
    }

    let root = if path.strip_prefix(root).is_ok() {
        root
    } else {
        root.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    };

    // The configured root (or single-file target) is operator-trusted and may
    // legitimately be a symlink — e.g. a blue-green `current -> releases/N`
    // deploy, or `ServeFile` pointed at `latest.log -> 2026-06-19.log`. The
    // policy therefore governs only the *request-supplied* components below the
    // root, which are the path-traversal escape vector; the root itself is not
    // policed.
    if let Ok(relative_path) = path.strip_prefix(root) {
        let mut current_path = root.to_path_buf();
        let mut components = relative_path.components().peekable();
        while let Some(component) = components.next() {
            current_path.push(component);
            if symlink_policy == ServeDirSymlinkPolicy::AllowFinalComponent
                && components.peek().is_none()
            {
                break;
            }
            reject_symlink(&current_path).await?;
        }
    } else {
        // Path is not under the configured root (unexpected); police it
        // defensively rather than trusting it.
        reject_symlink(path).await?;
    }

    tokio::fs::metadata(path).await
}

async fn reject_symlink(path: &Path) -> io::Result<()> {
    let meta = tokio::fs::symlink_metadata(path).await?;
    if is_symlink_like(&meta) {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "symlink paths are not served",
        ))
    } else {
        Ok(())
    }
}

/// Whether `meta` describes a symlink-like entry that should be rejected.
///
/// Beyond POSIX symlinks this also catches Windows reparse points (directory
/// junctions, mount points, ...), which [`std::fs::FileType::is_symlink`] does
/// *not* report yet redirect outside the served tree just like a symlink.
fn is_symlink_like(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }

    false
}

/// Handle directory requests based on the configured directory serve mode.
/// Can append index.html, return 404, or generate HTML file listing.
async fn maybe_serve_directory(
    path_to_file: &mut PathBuf,
    uri: &Uri,
    mode: DirectoryServeMode,
    html_as_default_extension: bool,
    source: &DirSource,
    symlink_policy: ServeDirSymlinkPolicy,
) -> Result<Option<OpenFileOutput>, std::io::Error> {
    let uri_path = uri.path_or_root();

    // `Some(true)` => directory, `Some(false)` => file, `None` => does not exist.
    let is_directory: Option<bool> = match source {
        DirSource::Filesystem(_) => is_dir(source, path_to_file, symlink_policy).await,
        DirSource::Embedded(base) => is_dir_embedded(path_to_file, base).await,
    };

    // A trailing slash means the client is referring to a directory.
    // If the path resolves to something other than an existing directory
    // (a file, or nothing at all), we must NOT silently strip the slash
    // and serve a file. Root `/` is exempted: it always means "this dir".
    if uri_path.ends_with('/') && uri_path != "/" && is_directory != Some(true) {
        return Ok(Some(OpenFileOutput::FileNotFound));
    }

    // Bare-name requests (`/about`) — if nothing exists at that path AND
    // the path has no extension yet, try appending `.html`.
    if html_as_default_extension && is_directory.is_none() && path_to_file.extension().is_none() {
        path_to_file.set_extension("html");
        return Ok(None);
    }

    if is_directory != Some(true) {
        return Ok(None);
    }

    match mode {
        DirectoryServeMode::AppendIndexHtml => {
            if uri_path.ends_with('/') {
                path_to_file.push("index.html");
                Ok(None)
            } else {
                let uri = match append_slash_on_path(uri.clone()) {
                    Ok(uri) => uri,
                    Err(err) => return Ok(Some(err)),
                };
                let location = HeaderValue::from_str(&uri.to_string())
                    .inspect_err(|err| {
                        tracing::debug!("failed to parse uri as header value for loc: {err}");
                    })
                    .map_err(std::io::Error::other)?;
                Ok(Some(OpenFileOutput::Redirect { location }))
            }
        }
        DirectoryServeMode::NotFound => Ok(Some(OpenFileOutput::FileNotFound)),
        #[cfg(feature = "html")]
        DirectoryServeMode::HtmlFileList => {
            html::serve_html_listing(path_to_file, uri, source).await
        }
    }
}

/// Parse and validate HTTP Range header.
fn try_parse_range(
    maybe_range_ref: Option<&str>,
    file_size: u64,
) -> Option<Result<Vec<RangeInclusive<u64>>, RangeUnsatisfiableError>> {
    maybe_range_ref.map(|header_value| {
        http_range_header::parse_range_header(header_value)
            .and_then(|first_pass| first_pass.validate(file_size))
    })
}

/// `Some(true)` => exists and is a directory. `Some(false)` => exists and is
/// not a directory (i.e. file). `None` => does not exist. Distinguishing
/// "missing" from "is a file" is what lets us decide whether to apply
/// `html_as_default_extension` or reject a trailing slash as a 404.
async fn is_dir(
    source: &DirSource,
    path_to_file: &Path,
    symlink_policy: ServeDirSymlinkPolicy,
) -> Option<bool> {
    filesystem_metadata(source, path_to_file, symlink_policy)
        .await
        .ok()
        .map(|meta_data| meta_data.is_dir())
}

async fn is_dir_embedded(path_to_file: &Path, base: &Dir<'_>) -> Option<bool> {
    // Empty path corresponds to the root directory, which is always a directory
    if path_to_file.as_os_str().is_empty() {
        return Some(true);
    }
    if base.get_dir(path_to_file).is_some() {
        Some(true)
    } else if base.get_file(path_to_file).is_some() {
        Some(false)
    } else {
        None
    }
}

/// Append a trailing slash to a URI path for directory redirection.
fn append_slash_on_path(mut uri: Uri) -> Result<Uri, OpenFileOutput> {
    // Scheme, authority and query are preserved; only the path gains a `/`.
    uri.ensure_path_trailing_slash();
    Ok(uri)
}
