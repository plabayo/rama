use super::{
    DirectoryServeMode, ServeVariant,
    headers::{IfModifiedSince, IfUnmodifiedSince, LastModified},
};
use crate::{HeaderValue, Method, Request, Uri, header};
use http_range_header::RangeUnsatisfiableError;
use rama_http_types::headers::{encoding::Encoding, specifier::QualityValue};
use std::{
    ffi::OsStr,
    fs::Metadata,
    io::{self, SeekFrom},
    ops::RangeInclusive,
    path::{Path, PathBuf},
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
            open_file_with_fallback(path_to_file, negotiated_encodings).await?;
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
        if let Some(Ok(ranges)) = maybe_range.as_ref() {
            // if there is any other amount of ranges than 1 we'll return an
            // unsatisfiable later as there isn't yet support for multipart ranges
            if ranges.len() == 1 {
                file.seek(SeekFrom::Start(*ranges[0].start())).await?;
            }
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
            let mut entries = vec![];

            let mut dir = tokio::fs::read_dir(&path_to_file).await?;
            while let Some(entry) = dir.next_entry().await? {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();
                entries.push(format!(
                    "<li><a href=\"{1}{2}{0}\">{0}</a></li>",
                    file_name_str,
                    uri.path().trim_end_matches('/'),
                    if uri.path().trim_start_matches('/').is_empty() {
                        ""
                    } else {
                        "/"
                    }
                ));
            }
            let listing = entries.join("\n");

            let mut nav_parts = vec![];
            let mut current_path = String::new();
            for part in uri.path().trim_start_matches('/').split('/') {
                if !part.is_empty() {
                    current_path.push('/');
                    current_path.push_str(part);
                    nav_parts.push(format!("<a href=\"{0}\">{1}</a>", current_path, part));
                }
            }
            let breadcrumb = if nav_parts.is_empty() {
                "<a href=\"/\">/</a>".to_string()
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
                listing,
                breadcrumb,
            );

            Ok(Some(OpenFileOutput::Html(html)))
        }
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
        tracing::error!(?err, "redirect uri failed to build");
        OpenFileOutput::InvalidRedirectUri
    })
}
