use super::{
    DirectoryServeMode, ServeVariant,
    headers::{IfModifiedSince, IfUnmodifiedSince, LastModified},
};
use crate::headers::{encoding::Encoding, specifier::QualityValue};
use crate::{HeaderValue, Method, Request, Uri, header};
use chrono::{DateTime, Local};
use http_range_header::RangeUnsatisfiableError;
use rama_core::telemetry::tracing;
use std::{
    ffi::OsStr,
    fmt,
    fs::Metadata,
    io::{self, ErrorKind, SeekFrom},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    time::SystemTime,
};
use tokio::{fs::File, io::AsyncSeekExt};

pub(super) enum OpenFileOutput {
    FileOpened(Box<FileOpened>),
    Redirect { location: HeaderValue },
    Html(String),
    FileNotFound,
    PreconditionFailed,
    NotModified,
    InvalidRedirectUri,
    InvalidFilename,
}

pub(super) struct FileOpened {
    pub(super) extent: FileRequestExtent,
    pub(super) chunk_size: usize,
    pub(super) mime_header_value: HeaderValue,
    pub(super) maybe_encoding: Option<Encoding>,
    pub(super) maybe_range: Option<Result<Vec<RangeInclusive<u64>>, RangeUnsatisfiableError>>,
    pub(super) last_modified: Option<LastModified>,
}

pub(super) enum FileRequestExtent {
    Full(File, Metadata),
    Head(Metadata),
}

pub(super) async fn open_file(
    variant: ServeVariant,
    mut path_to_file: PathBuf,
    req: Request,
    negotiated_encodings: Vec<QualityValue<Encoding>>,
    range_header: Option<String>,
    buf_chunk_size: usize,
) -> io::Result<OpenFileOutput> {
    let if_unmodified_since = req
        .headers()
        .get(header::IF_UNMODIFIED_SINCE)
        .and_then(IfUnmodifiedSince::from_header_value);

    let if_modified_since = req
        .headers()
        .get(header::IF_MODIFIED_SINCE)
        .and_then(IfModifiedSince::from_header_value);

    let mime = match variant {
        ServeVariant::Directory { serve_mode } => {
            // Might already at this point know a redirect or not found result should be
            // returned which corresponds to a Some(output). Otherwise the path might be
            // modified and proceed to the open file/metadata future.
            if let Some(output) =
                maybe_serve_directory(&mut path_to_file, req.uri(), serve_mode).await?
            {
                return Ok(output);
            }

            mime_guess::from_path(&path_to_file)
                .first_raw()
                .map(HeaderValue::from_static)
                .unwrap_or_else(|| {
                    HeaderValue::from_str(mime::APPLICATION_OCTET_STREAM.as_ref()).unwrap()
                })
        }

        ServeVariant::SingleFile { mime } => mime,
    };

    if req.method() == Method::HEAD {
        let (meta, maybe_encoding) =
            file_metadata_with_fallback(path_to_file, negotiated_encodings).await?;

        let last_modified = meta.modified().ok().map(LastModified::from);
        if let Some(output) = check_modified_headers(
            last_modified.as_ref(),
            if_unmodified_since,
            if_modified_since,
        ) {
            return Ok(output);
        }

        let maybe_range = try_parse_range(range_header.as_deref(), meta.len());

        Ok(OpenFileOutput::FileOpened(Box::new(FileOpened {
            extent: FileRequestExtent::Head(meta),
            chunk_size: buf_chunk_size,
            mime_header_value: mime,
            maybe_encoding,
            maybe_range,
            last_modified,
        })))
    } else {
        let (mut file, maybe_encoding) =
            match open_file_with_fallback(path_to_file, negotiated_encodings).await {
                Ok(result) => result,

                Err(err) if is_invalid_filename_error(&err) => {
                    return Ok(OpenFileOutput::InvalidFilename);
                }
                Err(err) => return Err(err),
            };
        let meta = file.metadata().await?;
        let last_modified = meta.modified().ok().map(LastModified::from);
        if let Some(output) = check_modified_headers(
            last_modified.as_ref(),
            if_unmodified_since,
            if_modified_since,
        ) {
            return Ok(output);
        }

        let maybe_range = try_parse_range(range_header.as_deref(), meta.len());
        if let Some(Ok(ranges)) = maybe_range.as_ref()
            && ranges.len() == 1
        {
            // if there is any other amount of ranges than 1 we'll return an
            // unsatisfiable later as there isn't yet support for multipart ranges
            file.seek(SeekFrom::Start(*ranges[0].start())).await?;
        }

        Ok(OpenFileOutput::FileOpened(Box::new(FileOpened {
            extent: FileRequestExtent::Full(file, meta),
            chunk_size: buf_chunk_size,
            mime_header_value: mime,
            maybe_encoding,
            maybe_range,
            last_modified,
        })))
    }
}

fn is_invalid_filename_error(err: &io::Error) -> bool {
    // Only applies to NULL bytes
    if err.kind() == ErrorKind::InvalidInput {
        return true;
    }

    // FIXME: Remove when MSRV >= 1.87.
    // `io::ErrorKind::InvalidFilename` is stabilized in v1.87
    #[cfg(target_os = "windows")]
    if let Some(raw_err) = err.raw_os_error()
        && (raw_err == 123 || raw_err == 161 || raw_err == 206)
    {
        // https://github.com/rust-lang/rust/blob/70e2b4a4d197f154bed0eb3dcb5cac6a948ff3a3/library/std/src/sys/pal/windows/mod.rs
        // Lines 81 and 115
        return true;
    }

    false
}

fn check_modified_headers(
    modified: Option<&LastModified>,
    if_unmodified_since: Option<IfUnmodifiedSince>,
    if_modified_since: Option<IfModifiedSince>,
) -> Option<OpenFileOutput> {
    if let Some(since) = if_unmodified_since {
        let precondition = modified
            .as_ref()
            .map(|time| since.precondition_passes(time))
            .unwrap_or(false);

        if !precondition {
            return Some(OpenFileOutput::PreconditionFailed);
        }
    }

    if let Some(since) = if_modified_since {
        let unmodified = modified
            .as_ref()
            .map(|time| !since.is_modified(time))
            // no last_modified means its always modified
            .unwrap_or(false);
        if unmodified {
            return Some(OpenFileOutput::NotModified);
        }
    }

    None
}

// Returns the preferred_encoding encoding and modifies the path extension
// to the corresponding file extension for the encoding.
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
async fn open_file_with_fallback(
    mut path: PathBuf,
    mut negotiated_encoding: Vec<QualityValue<Encoding>>,
) -> io::Result<(File, Option<Encoding>)> {
    let (file, encoding) = loop {
        // Get the preferred encoding among the negotiated ones.
        let encoding = preferred_encoding(&mut path, &negotiated_encoding);
        match (File::open(&path).await, encoding) {
            (Ok(file), maybe_encoding) => break (file, maybe_encoding),
            (Err(err), Some(encoding)) if err.kind() == io::ErrorKind::NotFound => {
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

// Attempts to get the file metadata with any of the possible negotiated_encodings in the
// preferred order. If none of the negotiated_encodings have a corresponding precompressed
// file the uncompressed file is used as a fallback.
async fn file_metadata_with_fallback(
    mut path: PathBuf,
    mut negotiated_encoding: Vec<QualityValue<Encoding>>,
) -> io::Result<(Metadata, Option<Encoding>)> {
    let (file, encoding) = loop {
        // Get the preferred encoding among the negotiated ones.
        let encoding = preferred_encoding(&mut path, &negotiated_encoding);
        match (tokio::fs::metadata(&path).await, encoding) {
            (Ok(file), maybe_encoding) => break (file, maybe_encoding),
            (Err(err), Some(encoding)) if err.kind() == io::ErrorKind::NotFound => {
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

async fn maybe_serve_directory(
    path_to_file: &mut PathBuf,
    uri: &Uri,
    mode: DirectoryServeMode,
) -> Result<Option<OpenFileOutput>, std::io::Error> {
    if !is_dir(path_to_file).await {
        return Ok(None);
    }

    match mode {
        DirectoryServeMode::AppendIndexHtml => {
            if uri.path().ends_with('/') {
                path_to_file.push("index.html");
                Ok(None)
            } else {
                let uri = match append_slash_on_path(uri.clone()) {
                    Ok(uri) => uri,
                    Err(err) => return Ok(Some(err)),
                };
                let location = HeaderValue::from_str(&uri.to_string()).unwrap();
                Ok(Some(OpenFileOutput::Redirect { location }))
            }
        }
        DirectoryServeMode::NotFound => Ok(Some(OpenFileOutput::FileNotFound)),
        DirectoryServeMode::HtmlFileList => {
            let mut rows = vec![];

            let mut dir = tokio::fs::read_dir(&path_to_file).await?;
            while let Some(entry) = dir.next_entry().await? {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                let metadata = entry.metadata().await?;
                let is_dir = metadata.is_dir();
                let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let datetime: DateTime<Local> = modified.into();
                let modified_str = datetime.format("%Y-%m-%d %H:%M:%S %:z").to_string();

                let mime = if is_dir {
                    None
                } else {
                    mime_guess::from_path(file_name_str.as_ref()).first()
                };
                let emoji = emoji_for_mime(mime.as_ref(), is_dir);

                let hs = if metadata.is_dir() {
                    HumanSize::None
                } else {
                    format_size(metadata.len())
                };

                rows.push(format!(
                    "<tr><td>{5} <a href=\"{1}{2}{0}\">{0}</a></td><td>{3}</td><td>{4}</td></tr>",
                    file_name_str,
                    uri.path().trim_end_matches('/'),
                    if uri.path().trim_start_matches('/').is_empty() {
                        ""
                    } else {
                        "/"
                    },
                    modified_str,
                    hs,
                    emoji,
                ));
            }

            let table = format!(
                r#"<table style="width:100%; border-collapse:collapse;">
            <thead>
            <tr><th align="left">Name</th><th align="left">Last Modified</th><th align="left">Size</th></tr>
            </thead>
            <tbody>
            {0}
            </tbody>
            </table>"#,
                rows.join("\n")
            );

            let mut nav_parts = vec![];
            let mut current_path = String::new();
            for part in uri.path().trim_start_matches('/').split('/') {
                if !part.is_empty() {
                    current_path.push('/');
                    current_path.push_str(part);
                    nav_parts.push(format!("<a href=\"{current_path}\">{part}</a>"));
                }
            }
            let breadcrumb = if nav_parts.is_empty() {
                "<a href=\"/\">/</a>".to_owned()
            } else {
                format!(
                    "<a href=\"/\">/</a> &raquo; {}",
                    nav_parts.join(" &raquo; ")
                )
            };

            let html = format!(
                r#"<!DOCTYPE HTML>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <title>Directory listing for .{0}</title>
            </head>
            <body>
            <h1>Directory listing for .{0}</h1>
            <div>{2}</div>
            <hr>
            <ul>
            {1}
            </ul>
            <hr>
            </body>
            </html>"#,
                uri.path(),
                table,
                breadcrumb,
            );

            Ok(Some(OpenFileOutput::Html(html)))
        }
    }
}

enum HumanSize {
    None,
    Bytes(u64),
    KiloBytes(f64),
    MegaBytes(f64),
    GigaBytes(f64),
    TeraBytes(f64),
}

impl fmt::Display for HumanSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "--"),
            Self::Bytes(n) => write!(f, "{n}B"),
            Self::KiloBytes(d) => write!(f, "{d:.1}KB"),
            Self::MegaBytes(d) => write!(f, "{d:.1}MB"),
            Self::GigaBytes(d) => write!(f, "{d:.1}GB"),
            Self::TeraBytes(d) => write!(f, "{d:.1}TB"),
        }
    }
}

fn format_size(bytes: u64) -> HumanSize {
    const MAX_UNITS: usize = 5;

    let mut size = bytes as f64;
    let mut unit = 0;

    while size >= 1024.0 && unit < MAX_UNITS - 1 {
        size /= 1024.0;
        unit += 1;
    }
    match unit {
        0 => HumanSize::Bytes(size as u64),
        1 => HumanSize::KiloBytes(size),
        2 => HumanSize::MegaBytes(size),
        3 => HumanSize::GigaBytes(size),
        _ => HumanSize::TeraBytes(size),
    }
}

fn emoji_for_mime(mime: Option<&mime::Mime>, is_dir: bool) -> &'static str {
    if is_dir {
        return "📁";
    }

    match mime.map(|m| (m.type_().as_str(), m.subtype().as_str())) {
        Some(("text", "css")) => "🎨",
        Some(("image", _)) => "🖼️",
        Some(("audio", _)) => "🎵",
        Some(("video", _)) => "🎬",
        Some(("application", "pdf")) => "📕",
        Some(("application", "zip" | "x-tar")) => "🗜️",
        Some(("application", "json" | "xml")) => "🔧",
        Some(("application", "msword")) => "📃",
        Some(("application", "vnd.ms-excel")) => "📊",
        Some(("application", "javascript")) => "🧩",
        _ => "📄",
    }
}

fn try_parse_range(
    maybe_range_ref: Option<&str>,
    file_size: u64,
) -> Option<Result<Vec<RangeInclusive<u64>>, RangeUnsatisfiableError>> {
    maybe_range_ref.map(|header_value| {
        http_range_header::parse_range_header(header_value)
            .and_then(|first_pass| first_pass.validate(file_size))
    })
}

async fn is_dir(path_to_file: &Path) -> bool {
    tokio::fs::metadata(path_to_file)
        .await
        .is_ok_and(|meta_data| meta_data.is_dir())
}

fn append_slash_on_path(uri: Uri) -> Result<Uri, OpenFileOutput> {
    let rama_http_types::dep::http::uri::Parts {
        scheme,
        authority,
        path_and_query,
        ..
    } = uri.into_parts();

    let mut uri_builder = Uri::builder();

    if let Some(scheme) = scheme {
        uri_builder = uri_builder.scheme(scheme);
    }

    if let Some(authority) = authority {
        uri_builder = uri_builder.authority(authority);
    }

    let uri_builder = if let Some(path_and_query) = path_and_query {
        if let Some(query) = path_and_query.query() {
            uri_builder.path_and_query(format!("{}/?{}", path_and_query.path(), query))
        } else {
            uri_builder.path_and_query(format!("{}/", path_and_query.path()))
        }
    } else {
        uri_builder.path_and_query("/")
    };

    uri_builder.build().map_err(|err| {
        tracing::error!("redirect uri failed to build: {err:?}");
        OpenFileOutput::InvalidRedirectUri
    })
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use mime::Mime;

    #[test]
    fn test_emoji_for_mime() {
        struct Case {
            mime: Option<Mime>,
            is_dir: bool,
            expected: &'static str,
        }

        let cases = [
            Case {
                mime: None,
                is_dir: true,
                expected: "📁",
            },
            Case {
                mime: Some(Mime::from_str("text/plain").unwrap()),
                is_dir: false,
                expected: "📄",
            },
            Case {
                mime: Some(Mime::from_str("image/png").unwrap()),
                is_dir: false,
                expected: "🖼️",
            },
            Case {
                mime: Some(Mime::from_str("audio/mpeg").unwrap()),
                is_dir: false,
                expected: "🎵",
            },
            Case {
                mime: Some(Mime::from_str("application/pdf").unwrap()),
                is_dir: false,
                expected: "📕",
            },
            Case {
                mime: Some(Mime::from_str("application/zip").unwrap()),
                is_dir: false,
                expected: "🗜️",
            },
            Case {
                mime: Some(Mime::from_str("application/json").unwrap()),
                is_dir: false,
                expected: "🔧",
            },
            Case {
                mime: Some(Mime::from_str("application/octet-stream").unwrap()),
                is_dir: false,
                expected: "📄",
            },
        ];

        for case in cases {
            let actual = emoji_for_mime(case.mime.as_ref(), case.is_dir);
            assert_eq!(actual, case.expected, "Failed on case: {:?}", case.mime);
        }
    }

    #[test]
    fn test_format_size() {
        struct Case {
            input: u64,
            expected: &'static str,
        }

        let cases = [
            Case {
                input: 0,
                expected: "0B",
            },
            Case {
                input: 512,
                expected: "512B",
            },
            Case {
                input: 1023,
                expected: "1023B",
            },
            Case {
                input: 1024,
                expected: "1.0KB",
            },
            Case {
                input: 1048576,
                expected: "1.0MB",
            },
            Case {
                input: 1073741824,
                expected: "1.0GB",
            },
            Case {
                input: 1099511627776,
                expected: "1.0TB",
            },
        ];

        for case in cases {
            let actual = format_size(case.input).to_string();
            assert_eq!(actual, case.expected, "Failed on input: {}", case.input);
        }
    }
}
