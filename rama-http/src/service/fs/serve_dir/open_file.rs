use super::{
    DirSource, DirectoryServeMode, HiddenPathFilter, ServeDirSymlinkPolicy, ServeVariant,
    headers::{IfModifiedSince, IfUnmodifiedSince, LastModified, etag_from_metadata},
};
use crate::headers::{ETag, HeaderMapExt as _, IfMatch, IfNoneMatch, IfRange};
use crate::headers::{encoding::Encoding, specifier::QualityValue};
use crate::service::fs::AsyncReadBody;
use crate::{Body, HeaderValue, Method, Request, body::util::BodyExt as _, header};
use http_range_header::{RangeInvalid, RangeUnsatisfiableError};
use rama_core::bytes::Bytes;
use rama_core::telemetry::tracing;
use rama_http_types::mime::Mime;
use rama_net::uri::Uri;
use rama_utils::include_dir::{Dir, Metadata as EmbeddedMetadata};
use rama_utils::octets::kib_u64;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;
#[cfg(windows)]
use std::path::Component;
use std::{
    ffi::OsStr,
    fs::{File, Metadata},
    io::{self, ErrorKind, Read as _, Seek as _, SeekFrom},
    ops::RangeInclusive,
    path::{Path, PathBuf},
};

// All html-only state (DirEntry, HumanSize, generate_directory_html, the
// emoji/size helpers, the per-helper unit tests) lives in a sibling
// file pulled in via `#[path]` so the gating is paid for exactly once.
#[cfg(feature = "html")]
#[path = "open_file_html.rs"]
mod html;

/// Files up to this size are read whole by the blocking call that opens them.
const READ_WHOLE_MAX_LEN: u64 = kib_u64(128);

/// Which request-supplied filesystem paths may be served.
#[derive(Debug, Clone, Copy)]
pub(super) struct PathAccess<'a> {
    pub(super) symlink_policy: ServeDirSymlinkPolicy,
    pub(super) hidden: &'a HiddenPathFilter,
}

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

pub(super) enum RangeError {
    Unsatisfiable,
    MultipleRangesNotSupported,
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
        maybe_range: Option<Result<RangeInclusive<u64>, RangeError>>,
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
    pub(super) maybe_range: Option<Result<RangeInclusive<u64>, RangeError>>,
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
    /// A file streamed from disk, positioned at the start of the served range.
    Stream(tokio::fs::File, u64),
    /// A file held in memory: read whole, or embedded.
    Loaded(Bytes),
    /// Only the selected range, with the full representation size for headers.
    LoadedRange { contents: Bytes, file_size: u64 },
    /// A HEAD request for a file of this size.
    Head(u64),
}

impl FileRequestExtent {
    pub(super) fn file_size(&self) -> u64 {
        match self {
            Self::Stream(_, size)
            | Self::Head(size)
            | Self::LoadedRange {
                file_size: size, ..
            } => *size,
            Self::Loaded(contents) => contents.len() as u64,
        }
    }

    /// The response body serving `range`, or the whole file.
    pub(super) fn into_body(self, range: Option<&RangeInclusive<u64>>, chunk_size: usize) -> Body {
        match (self, range) {
            (Self::Head(_), _) => Body::empty(),
            (Self::Loaded(contents), None) | (Self::LoadedRange { contents, .. }, _) => {
                Body::from(contents)
            }
            (Self::Loaded(contents), Some(range)) => {
                Body::from(contents.slice(*range.start() as usize..=*range.end() as usize))
            }
            (Self::Stream(file, size), None) => {
                Body::new(AsyncReadBody::with_capacity_limited(file, chunk_size, size).boxed())
            }
            (Self::Stream(file, _), Some(range)) => Body::new(
                AsyncReadBody::with_capacity_limited(
                    file,
                    chunk_size,
                    range.end() - range.start() + 1,
                )
                .boxed(),
            ),
        }
    }
}

/// What a request asks of the file it resolves to.
struct FileRequest {
    preconditions: Preconditions,
    range_header: Option<Box<str>>,
    is_head: bool,
    ignore_multi_range_requests: bool,
    buf_chunk_size: usize,
    precompression_configured: bool,
    negotiated_encodings: Vec<QualityValue<Encoding>>,
}

impl FileRequest {
    /// Evaluates preconditions and the range of a file with the given validators and size.
    fn decide(
        &self,
        size: u64,
        modified: Option<std::time::SystemTime>,
    ) -> Result<Decided, OpenFileOutput> {
        let last_modified = modified.and_then(LastModified::try_from_system_time);
        let etag = modified.and_then(|mtime| etag_from_metadata(size, mtime));
        if let Some(output) = self
            .preconditions
            .check(etag.as_ref(), last_modified.as_ref())
        {
            return Err(output);
        }
        let range_header = self
            .preconditions
            .applicable_range(self.range_header.as_deref(), etag.as_ref());
        let range = try_parse_range(range_header, size, self.ignore_multi_range_requests);
        Ok(Decided {
            last_modified,
            etag,
            range,
        })
    }

    fn opened(
        &self,
        extent: FileRequestExtent,
        mime: Mime,
        encoding: Option<Encoding>,
        decided: Decided,
    ) -> OpenFileOutput {
        OpenFileOutput::new_file_opened(
            extent,
            self.buf_chunk_size,
            mime,
            encoding,
            decided.range,
            decided.last_modified,
            self.precompression_configured,
            decided.etag,
        )
    }
}

/// Validators and range of a file that passed its preconditions.
struct Decided {
    last_modified: Option<LastModified>,
    etag: Option<ETag>,
    range: Option<Result<RangeInclusive<u64>, RangeError>>,
}

/// Open a file for serving, handling both filesystem and embedded sources.
/// Supports precompressed variants, range requests, and conditional headers.
#[expect(
    clippy::too_many_arguments,
    reason = "internal helper; each arg has a distinct role and grouping them into a struct adds more noise than it removes"
)]
pub(super) async fn open_file(
    variant: ServeVariant,
    path_to_file: PathBuf,
    req: Request,
    negotiated_encodings: Vec<QualityValue<Encoding>>,
    range_header: Option<&str>,
    ignore_multi_range_requests: bool,
    buf_chunk_size: usize,
    source: &DirSource,
    precompression_configured: bool,
    access: PathAccess<'_>,
) -> io::Result<OpenFileOutput> {
    let request = FileRequest {
        preconditions: Preconditions::from_request(&req),
        range_header: range_header.map(Into::into),
        is_head: req.method() == Method::HEAD,
        ignore_multi_range_requests,
        buf_chunk_size,
        precompression_configured,
        negotiated_encodings,
    };
    match source {
        DirSource::Filesystem(root) => {
            let lookup = FilesystemLookup {
                root: root.clone(),
                symlink_policy: access.symlink_policy,
                hidden: access.hidden.clone(),
            };
            let (parts, _) = req.into_parts();
            // One blocking call resolves, opens and, when small, reads the file.
            tokio::task::spawn_blocking(move || {
                lookup.open(variant, path_to_file, &parts.uri, &request)
            })
            .await
            .map_err(io::Error::other)?
        }
        DirSource::Embedded(base) => open_embedded(
            base,
            variant,
            path_to_file,
            req.uri(),
            &request,
            access.hidden,
        ),
    }
}

/// Read only a validated small-file range when possible. If it is short,
/// reread from the start so the caller can recompute suffix/open-ended ranges
/// against the observed size instead of returning truncated or misplaced data.
fn read_small_file(
    file: &mut (impl io::Read + io::Seek),
    size: u64,
    range: Option<&RangeInclusive<u64>>,
) -> io::Result<FileRequestExtent> {
    if let Some(range) = range {
        let len = range.end() - range.start() + 1;
        if *range.start() != 0 {
            file.seek(SeekFrom::Start(*range.start()))?;
        }
        let mut contents = Vec::with_capacity(len as usize);
        (&mut *file).take(len).read_to_end(&mut contents)?;
        if contents.len() as u64 == len {
            return Ok(FileRequestExtent::LoadedRange {
                contents: Bytes::from(contents),
                file_size: size,
            });
        }
        file.seek(SeekFrom::Start(0))?;
    }
    let mut contents = Vec::with_capacity(size as usize);
    file.take(size).read_to_end(&mut contents)?;
    Ok(FileRequestExtent::Loaded(Bytes::from(contents)))
}

/// The next step for a request path, once it is known whether it names a directory.
enum DirectoryStep {
    Serve,
    Respond(OpenFileOutput),
    #[cfg(feature = "html")]
    List,
}

/// Handle directory requests based on the configured directory serve mode.
/// Can append index.html, return 404, or ask for an HTML file listing.
///
/// `is_directory`: `Some(true)` => directory, `Some(false)` => file, `None` => does not exist.
fn directory_step(
    is_directory: Option<bool>,
    path_to_file: &mut PathBuf,
    uri: &Uri,
    mode: DirectoryServeMode,
    redirect_to_trailing_slash: bool,
    html_as_default_extension: bool,
) -> io::Result<DirectoryStep> {
    let uri_path = uri.path_or_root();

    // A trailing slash means the client is referring to a directory.
    // If the path resolves to something other than an existing directory
    // (a file, or nothing at all), we must NOT silently strip the slash
    // and serve a file. Root `/` is exempted: it always means "this dir".
    if uri_path.ends_with('/') && uri_path != "/" && is_directory != Some(true) {
        return Ok(DirectoryStep::Respond(OpenFileOutput::FileNotFound));
    }

    // Bare-name requests (`/about`) — if nothing exists at that path AND
    // the path has no extension yet, try appending `.html`.
    if html_as_default_extension && is_directory.is_none() && path_to_file.extension().is_none() {
        path_to_file.set_extension("html");
        return Ok(DirectoryStep::Serve);
    }

    if is_directory != Some(true) {
        return Ok(DirectoryStep::Serve);
    }

    match mode {
        DirectoryServeMode::AppendIndexHtml => {
            if uri_path.ends_with('/') || !redirect_to_trailing_slash {
                path_to_file.push("index.html");
                Ok(DirectoryStep::Serve)
            } else {
                let uri = match append_slash_on_path(uri.clone()) {
                    Ok(uri) => uri,
                    Err(err) => return Ok(DirectoryStep::Respond(err)),
                };
                let location = HeaderValue::try_from(uri.to_string())
                    .inspect_err(|err| {
                        tracing::debug!("failed to parse uri as header value for loc: {err}");
                    })
                    .map_err(io::Error::other)?;
                Ok(DirectoryStep::Respond(OpenFileOutput::Redirect {
                    location,
                }))
            }
        }
        DirectoryServeMode::NotFound => Ok(DirectoryStep::Respond(OpenFileOutput::FileNotFound)),
        #[cfg(feature = "html")]
        DirectoryServeMode::HtmlFileList => Ok(DirectoryStep::List),
    }
}

fn open_embedded(
    base: &Dir<'static>,
    variant: ServeVariant,
    mut path_to_file: PathBuf,
    uri: &Uri,
    request: &FileRequest,
    hidden: &HiddenPathFilter,
) -> io::Result<OpenFileOutput> {
    let mime = match variant {
        ServeVariant::Directory {
            serve_mode,
            redirect_to_trailing_slash,
            html_as_default_extension,
        } => {
            let is_directory = is_dir_embedded(&path_to_file, base);
            match directory_step(
                is_directory,
                &mut path_to_file,
                uri,
                serve_mode,
                redirect_to_trailing_slash,
                html_as_default_extension,
            )? {
                DirectoryStep::Serve => {}
                DirectoryStep::Respond(output) => return Ok(output),
                #[cfg(feature = "html")]
                DirectoryStep::List => {
                    return Ok(html::list_embedded_dir(base, &path_to_file, uri, hidden));
                }
            }
            guess_mime_type(&path_to_file)
        }
        ServeVariant::SingleFile { mime } => mime,
    };
    #[cfg(not(feature = "html"))]
    let _ = hidden;

    let (contents, metadata, maybe_encoding) =
        match open_embedded_file_with_fallback(base, path_to_file, &request.negotiated_encodings) {
            Ok(result) => result,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(OpenFileOutput::FileNotFound);
            }
            Err(err) => return Err(err),
        };

    let content_length = contents.len() as u64;
    let decided = match request.decide(content_length, metadata.map(|meta| meta.modified())) {
        Ok(decided) => decided,
        Err(output) => return Ok(output),
    };
    let extent = if request.is_head {
        FileRequestExtent::Head(content_length)
    } else {
        FileRequestExtent::Loaded(Bytes::from_static(contents))
    };
    Ok(request.opened(extent, mime, maybe_encoding, decided))
}

/// Attempt to open an embedded file with any of the negotiated encodings.
/// Falls back to uncompressed file if no precompressed variants are found.
fn open_embedded_file_with_fallback(
    base: &Dir<'static>,
    mut path: PathBuf,
    negotiated_encoding: &[QualityValue<Encoding>],
) -> io::Result<(&'static [u8], Option<EmbeddedMetadata>, Option<Encoding>)> {
    let mut negotiated_encoding = negotiated_encoding.to_vec();
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

    Ok((file.contents(), file.metadata().copied(), encoding))
}

fn is_dir_embedded(path_to_file: &Path, base: &Dir<'_>) -> Option<bool> {
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

/// Resolves request paths below a filesystem root; every method blocks.
struct FilesystemLookup {
    root: PathBuf,
    symlink_policy: ServeDirSymlinkPolicy,
    hidden: HiddenPathFilter,
}

impl FilesystemLookup {
    fn open(
        &self,
        variant: ServeVariant,
        mut path_to_file: PathBuf,
        uri: &Uri,
        request: &FileRequest,
    ) -> io::Result<OpenFileOutput> {
        let mime = match variant {
            ServeVariant::Directory {
                serve_mode,
                redirect_to_trailing_slash,
                html_as_default_extension,
            } => {
                let is_directory = match self.metadata(&path_to_file) {
                    Ok(metadata) => Some(metadata.is_dir()),
                    Err(err) if is_missing_file_error(&err) => None,
                    Err(err) => return Err(err),
                };
                match directory_step(
                    is_directory,
                    &mut path_to_file,
                    uri,
                    serve_mode,
                    redirect_to_trailing_slash,
                    html_as_default_extension,
                )? {
                    DirectoryStep::Serve => {}
                    DirectoryStep::Respond(output) => return Ok(output),
                    #[cfg(feature = "html")]
                    DirectoryStep::List => {
                        return html::list_filesystem_dir(&path_to_file, uri, &self.hidden);
                    }
                }
                guess_mime_type(&path_to_file)
            }
            ServeVariant::SingleFile { mime } => mime,
        };

        if request.is_head {
            let (meta, maybe_encoding) =
                match Self::with_fallback(path_to_file, request, |path| self.metadata(path)) {
                    Ok(result) => result,
                    Err(err) if is_invalid_filename_error(&err) => {
                        return Ok(OpenFileOutput::InvalidFilename);
                    }
                    Err(err) => return Err(err),
                };
            let decided = match request.decide(meta.len(), meta.modified().ok()) {
                Ok(decided) => decided,
                Err(output) => return Ok(output),
            };
            let extent = FileRequestExtent::Head(meta.len());
            return Ok(request.opened(extent, mime, maybe_encoding, decided));
        }

        let (mut file, maybe_encoding) =
            match Self::with_fallback(path_to_file, request, |path| self.open_file(path)) {
                Ok(result) => result,
                Err(err) if is_invalid_filename_error(&err) => {
                    return Ok(OpenFileOutput::InvalidFilename);
                }
                Err(err) => return Err(err),
            };
        let meta = file.metadata()?;
        if meta.len() > READ_WHOLE_MAX_LEN {
            let decided = match request.decide(meta.len(), meta.modified().ok()) {
                Ok(decided) => decided,
                Err(output) => return Ok(output),
            };
            if let Some(Ok(range)) = decided.range.as_ref() {
                file.seek(SeekFrom::Start(*range.start()))?;
            }
            let extent = FileRequestExtent::Stream(tokio::fs::File::from_std(file), meta.len());
            return Ok(request.opened(extent, mime, maybe_encoding, decided));
        }

        // Resolve validators before reading, including If-Range's whole-file fallback.
        let mut decided = match request.decide(meta.len(), meta.modified().ok()) {
            Ok(decided) => decided,
            Err(output) => return Ok(output),
        };
        let range = decided.range.as_ref().and_then(|range| range.as_ref().ok());
        let extent = read_small_file(&mut file, meta.len(), range)?;
        if let FileRequestExtent::Loaded(contents) = &extent {
            // Whole reads, including a short range's fallback, determine the
            // actual served size when a file shrank after its metadata lookup.
            decided = match request.decide(contents.len() as u64, meta.modified().ok()) {
                Ok(decided) => decided,
                Err(output) => return Ok(output),
            };
        }
        Ok(request.opened(extent, mime, maybe_encoding, decided))
    }

    /// Runs `lookup` on the preferred precompressed variant of `path`, falling back
    /// through the negotiated encodings to the uncompressed file.
    fn with_fallback<T>(
        mut path: PathBuf,
        request: &FileRequest,
        lookup: impl Fn(&Path) -> io::Result<T>,
    ) -> io::Result<(T, Option<Encoding>)> {
        let mut negotiated_encoding = request.negotiated_encodings.clone();
        loop {
            // Get the preferred encoding among the negotiated ones.
            let encoding = preferred_encoding(&mut path, &negotiated_encoding);
            match (lookup(&path), encoding) {
                (Ok(found), maybe_encoding) => return Ok((found, maybe_encoding)),
                // Identity has no file extension to strip, so falling through to
                // the strip-and-retry path would clobber the originally requested
                // extension (e.g. `/foo.foobar` would become `/foo`). Only strip
                // when the preferred encoding actually appended an extension.
                // Regression test: see `identity_encoding_does_not_strip_extension`.
                (Err(err), Some(encoding))
                    if is_missing_file_error(&err) && encoding != Encoding::Identity =>
                {
                    // Remove the extension corresponding to a precompressed file (.gz, .br, .zz)
                    // to reset the path before the next iteration.
                    path.set_extension(OsStr::new(""));
                    // Remove the encoding from the negotiated_encodings since the file doesn't exist
                    negotiated_encoding.retain(|qv| qv.value != encoding);
                }
                (Err(err), _) => return Err(err),
            }
        }
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.check_access(path)?;
        std::fs::metadata(path)
    }

    fn open_file(&self, path: &Path) -> io::Result<File> {
        self.check_access(path)?;
        File::open(path)
    }

    /// Enforces the symlink and hidden-entry policies on a request-supplied path.
    fn check_access(&self, path: &Path) -> io::Result<()> {
        let root = if path.strip_prefix(&self.root).is_ok() {
            self.root.as_path()
        } else {
            self.root
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
        };

        if self.symlink_policy != ServeDirSymlinkPolicy::AllowAll {
            reject_symlinks_below_root(root, path, self.symlink_policy)?;
        }
        reject_hidden_resolved(root, path, &self.hidden)
    }
}

fn reject_symlinks_below_root(
    root: &Path,
    path: &Path,
    symlink_policy: ServeDirSymlinkPolicy,
) -> io::Result<()> {
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
            reject_symlink(&current_path)?;
        }
    } else {
        // Path is not under the configured root (unexpected); police it
        // defensively rather than trusting it.
        reject_symlink(path)?;
    }

    Ok(())
}

/// Request names are checked before any lookup; only Windows can alias a
/// hidden entry under another name (8.3 short names such as `GIT~1`).
#[cfg(not(windows))]
fn reject_hidden_resolved(
    _root: &Path,
    _path: &Path,
    _hidden: &HiddenPathFilter,
) -> io::Result<()> {
    Ok(())
}

/// Check the resolved on-disk names, as a short name (`GIT~1`) can alias a hidden entry.
#[cfg(windows)]
fn reject_hidden_resolved(root: &Path, path: &Path, hidden: &HiddenPathFilter) -> io::Result<()> {
    if hidden.allows_all() {
        return Ok(());
    }

    let resolved_root = std::fs::canonicalize(root)?;
    let resolved = std::fs::canonicalize(path)?;

    let Ok(relative) = resolved.strip_prefix(&resolved_root) else {
        // a permitted symlink left the root: police every resolved name
        return if hidden.hides_path(&resolved) {
            Err(hidden_entry_error())
        } else {
            Ok(())
        };
    };

    let mut current = resolved_root.clone();
    for component in relative.components() {
        current.push(component);
        let Component::Normal(name) = component else {
            continue;
        };
        if hidden.hides_name(name) {
            return Err(hidden_entry_error());
        }
        if hidden.checks_attributes() {
            let meta = std::fs::symlink_metadata(&current)?;
            if hidden.hides_attributes(name, meta.file_attributes()) {
                return Err(hidden_entry_error());
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn hidden_entry_error() -> io::Error {
    // reported as missing so a hidden entry is indistinguishable from an absent one
    io::Error::new(io::ErrorKind::NotFound, "hidden entries are not served")
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if is_symlink_like(&meta) {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "symlink paths are not served",
        ))
    } else {
        Ok(())
    }
}

/// Check if an IO error indicates an invalid filename.
fn is_invalid_filename_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::InvalidInput | ErrorKind::InvalidFilename
    )
}

/// Check if an IO error shows that no file exists at the probed path.
fn is_missing_file_error(err: &io::Error) -> bool {
    err.kind() == ErrorKind::NotFound || is_invalid_filename_error(err)
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
    if_range: IfRangeCondition,
}

/// The `If-Range` header, kept even when it does not decode.
enum IfRangeCondition {
    Absent,
    Valid(IfRange),
    Invalid,
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
            if_range: match req.headers().typed_try_get::<IfRange>() {
                Ok(None) => IfRangeCondition::Absent,
                Ok(Some(if_range)) => IfRangeCondition::Valid(if_range),
                Err(_) => IfRangeCondition::Invalid,
            },
        }
    }

    /// RFC 9110 §13.1.5: `Range` only applies while `If-Range` strongly matches the representation.
    fn applicable_range<'a>(&self, range: Option<&'a str>, etag: Option<&ETag>) -> Option<&'a str> {
        match &self.if_range {
            IfRangeCondition::Absent => range,
            // a date cannot rule out a second change within its second (RFC 9110 §8.8.2.2)
            IfRangeCondition::Valid(if_range) if !if_range.is_modified(etag, None) => range,
            IfRangeCondition::Valid(_) | IfRangeCondition::Invalid => None,
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
        &self,
        etag: Option<&ETag>,
        last_modified: Option<&LastModified>,
    ) -> Option<OpenFileOutput> {
        // Step 1: If-Match. RFC 9110 §13.1.1: with no current representation (no ETag), the
        // condition is false, including for `*`.
        if let Some(if_match) = &self.if_match {
            let passes = etag
                .map(|etag| if_match.precondition_passes(etag))
                .unwrap_or(false);
            if !passes {
                return Some(OpenFileOutput::PreconditionFailed);
            }
        } else if let Some(since) = &self.if_unmodified_since {
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
        if let Some(if_none_match) = &self.if_none_match {
            let passes = etag
                .map(|etag| if_none_match.precondition_passes(etag))
                .unwrap_or(true);
            if !passes {
                return Some(OpenFileOutput::NotModified {
                    etag: etag.cloned(),
                    last_modified: last_modified.cloned(),
                });
            }
        } else if let Some(since) = &self.if_modified_since {
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

/// Whether `meta` describes a symlink that should be rejected.
#[cfg(not(windows))]
fn is_symlink_like(meta: &Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Reject all reparse points, including those that
/// [`std::fs::FileType::is_symlink`] does not classify as symlinks.
#[cfg(windows)]
fn is_symlink_like(meta: &Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Parse and validate HTTP Range header.
fn try_parse_range(
    maybe_range_ref: Option<&str>,
    file_size: u64,
    ignore_multi_range_requests: bool,
) -> Option<Result<RangeInclusive<u64>, RangeError>> {
    let header_value = maybe_range_ref?;
    // ServeDir and ServeFile do not support multipart responses. Optionally
    // ignore the Range header before semantic and overlap validation.
    let multiple = || {
        if ignore_multi_range_requests {
            None
        } else {
            Some(Err(RangeError::MultipleRangesNotSupported))
        }
    };
    let parsed = match http_range_header::parse_range_header(header_value) {
        Ok(parsed) => parsed,
        // A reversed spec fails the whole header while parsing, before its range count is known.
        Err(RangeUnsatisfiableError::Invalid(RangeInvalid::Reversed))
            if header_value.contains(',') =>
        {
            return multiple();
        }
        Err(_err) => return Some(Err(RangeError::Unsatisfiable)),
    };
    if parsed.len() > 1 {
        return multiple();
    }

    match parsed.validate(file_size) {
        // Empty only for a zero-length file whose non-empty suffix is the whole file (RFC 9110 §14.1.1).
        Ok(mut ranges) => ranges.pop().map(Ok),
        Err(_err) => Some(Err(RangeError::Unsatisfiable)),
    }
}

/// Append a trailing slash to a URI path for directory redirection.
fn append_slash_on_path(mut uri: Uri) -> Result<Uri, OpenFileOutput> {
    // Scheme, authority and query are preserved; only the path gains a `/`.
    uri.ensure_path_trailing_slash();
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    struct CountRead {
        bytes: std::io::Cursor<Vec<u8>>,
        read: usize,
    }

    impl io::Read for CountRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.bytes.read(buf)?;
            self.read += n;
            Ok(n)
        }
    }

    impl io::Seek for CountRead {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(position)
        }
    }

    #[tokio::test]
    async fn small_range_reads_and_retains_only_the_requested_bytes() {
        let contents: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        for range in [0..=1023, 65536..=66559, 130048..=131071] {
            let mut reader = CountRead {
                bytes: io::Cursor::new(contents.clone()),
                read: 0,
            };
            let extent = read_small_file(&mut reader, contents.len() as u64, Some(&range)).unwrap();
            assert_eq!(reader.read, 1024);
            assert_eq!(extent.file_size(), contents.len() as u64);
            let FileRequestExtent::LoadedRange {
                contents: selected, ..
            } = &extent
            else {
                panic!("a complete range is buffered separately");
            };
            assert_eq!(selected.len(), 1024);
            let body = extent
                .into_body(Some(&range), 4096)
                .collect()
                .await
                .unwrap()
                .to_bytes();
            assert_eq!(
                body,
                &contents[*range.start() as usize..=*range.end() as usize]
            );
        }
    }

    #[tokio::test]
    async fn a_short_range_reloads_the_actual_file_before_recomputing_ranges() {
        for actual in [0, 75, 95] {
            let contents: Vec<u8> = (0..actual).collect();
            // Metadata said 100 bytes; the selected suffix was 90..=99.
            let mut reader = io::Cursor::new(contents.clone());
            let extent = read_small_file(&mut reader, 100, Some(&(90..=99))).unwrap();
            assert_eq!(extent.file_size(), u64::from(actual));
            assert!(matches!(extent, FileRequestExtent::Loaded(_)));
            let selected = try_parse_range(Some("bytes=-10"), extent.file_size(), false);
            if actual == 0 {
                // Preserve the existing empty-representation behavior.
                assert!(selected.is_none());
            } else {
                let range = selected
                    .unwrap()
                    .unwrap_or_else(|_| panic!("suffix fits the smaller file"));
                let body = extent
                    .into_body(Some(&range), 4096)
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                assert_eq!(body, &contents[contents.len() - 10..]);
            }
        }
    }

    #[test]
    fn range_read_errors_are_propagated() {
        struct Fails(io::Cursor<Vec<u8>>);
        impl io::Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(ErrorKind::PermissionDenied, "read failed"))
            }
        }
        impl io::Seek for Fails {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                self.0.seek(position)
            }
        }
        let error = read_small_file(
            &mut Fails(io::Cursor::new(vec![0; 100])),
            100,
            Some(&(10..=19)),
        )
        .err()
        .expect("read failure is not a short successful read");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn if_range_date_never_applies_a_range() {
        let modified = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_700_000_000))
            .unwrap();
        let etag = etag_from_metadata(10, modified).unwrap();
        let preconditions = |if_range| Preconditions {
            if_match: None,
            if_unmodified_since: None,
            if_none_match: None,
            if_modified_since: None,
            if_range: IfRangeCondition::Valid(if_range),
        };
        let range = Some("bytes=0-1");
        assert_eq!(
            preconditions(IfRange::date(modified)).applicable_range(range, Some(&etag)),
            None
        );
        assert_eq!(
            preconditions(IfRange::etag(etag.clone())).applicable_range(range, Some(&etag)),
            range
        );
    }
}
