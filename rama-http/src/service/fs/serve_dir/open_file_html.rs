//! HTML directory-listing renderer. Compiled in only via the `html`
//! feature; declared from [`super`] as a path-mod so the file name
//! parallels its sibling `open_file.rs` rather than living under
//! `open_file/html.rs`.
//!
//! Every untrusted value (file names, breadcrumb labels, the current
//! path) is routed through the `html!` macro family, which auto-escapes
//! via [`crate::protocols::html::IntoHtml::escape_and_write`]. Per-row `href`
//! values are constructed via [`rama_net::uri::Uri::path_mut`] so unsafe
//! bytes inside filenames are percent-encoded by the URI builder rather
//! than spliced into the attribute raw.

use super::super::{DirSource, open_file::OpenFileOutput};
use crate::Uri;
use jiff::Zoned;
use rama_utils::include_dir;
use std::{fmt, path::PathBuf, time::SystemTime};

/// Handle a directory request under
/// [`DirectoryServeMode::HtmlFileList`](super::super::DirectoryServeMode::HtmlFileList):
/// collect the directory's entries (filesystem or embedded), then render
/// them into an [`OpenFileOutput::Html`] response body.
pub(super) async fn serve_html_listing(
    path_to_file: &PathBuf,
    uri: &Uri,
    source: &DirSource,
) -> std::io::Result<Option<OpenFileOutput>> {
    let mut entries = vec![];

    match source {
        DirSource::Filesystem(_) => {
            let mut dir = tokio::fs::read_dir(path_to_file).await?;
            while let Some(entry) = dir.next_entry().await? {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy().to_string();

                let metadata = entry.metadata().await?;
                let is_dir = metadata.is_dir();
                let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let size = if is_dir { 0 } else { metadata.len() };

                entries.push(DirEntry::new(file_name_str, is_dir, modified, size));
            }
        }
        DirSource::Embedded(base) => {
            let Some(dir) = base.get_dir(path_to_file) else {
                return Ok(Some(OpenFileOutput::FileNotFound));
            };

            // Process all entries (directories and files)
            for entry in dir.entries() {
                let file_name_str = entry
                    .path()
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                match entry {
                    include_dir::DirEntry::Dir(_) => {
                        let modified = SystemTime::UNIX_EPOCH;
                        entries.push(DirEntry::new(file_name_str, true, modified, 0));
                    }
                    include_dir::DirEntry::File(file) => {
                        let modified = file
                            .metadata()
                            .map(|m| m.modified())
                            .unwrap_or(SystemTime::UNIX_EPOCH);

                        entries.push(DirEntry::new(
                            file_name_str,
                            false,
                            modified,
                            file.contents().len() as u64,
                        ));
                    }
                }
            }
        }
    }

    Ok(Some(OpenFileOutput::Html(generate_directory_html(
        entries, uri,
    ))))
}

/// Human-readable file size representation.
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

/// Format file size in human-readable units (B, KB, MB, GB, TB).
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

/// Get an appropriate emoji icon for a file based on its MIME type.
fn emoji_for_mime(mime: Option<&crate::mime::Mime>, is_dir: bool) -> &'static str {
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

/// Represents a directory entry for HTML file listing.
struct DirEntry {
    name: String,
    is_dir: bool,
    modified: SystemTime,
    size: u64,
}

impl DirEntry {
    fn new(name: String, is_dir: bool, modified: SystemTime, size: u64) -> Self {
        Self {
            name,
            is_dir,
            modified,
            size,
        }
    }
}

/// Generate HTML page for directory listing with file details and navigation.
fn generate_directory_html(entries: Vec<DirEntry>, uri: &Uri) -> String {
    use crate::protocols::html::{
        IntoHtml as _, a, body, div, h1, head, hr, html, meta, table, tbody, td, th, thead, title,
        tr,
    };

    let uri_path = uri.path().map(|p| p.as_raw_str()).unwrap_or("/");
    let title_text = format!("Directory listing for .{uri_path}");

    #[expect(
        clippy::expect_used,
        reason = "the request URI's path was already parsed upstream by the request parser; re-parsing it here as a URI-reference can't fail under the graceful parser"
    )]
    let base_link = rama_net::uri::Uri::parse_reference(uri_path)
        .expect("request uri path is a valid uri reference");

    let rows: Vec<_> = entries
        .into_iter()
        .map(|entry| {
            let modified = format_system_time_local(entry.modified);
            let mime = (!entry.is_dir)
                .then(|| crate::mime::guess::from_path(entry.name.as_str()).first())
                .flatten();
            let emoji = emoji_for_mime(mime.as_ref(), entry.is_dir);
            let size = if entry.is_dir {
                HumanSize::None
            } else {
                format_size(entry.size)
            }
            .to_string();

            let href = base_link
                .clone()
                .with_additional_path_segment(entry.name.as_str())
                .to_string();

            tr!(
                td!(emoji, " ", a!(href = href, entry.name)),
                td!(modified),
                td!(size),
            )
        })
        .collect();

    let mut crumbs: Vec<(String, String)> = Vec::new();
    let mut current = String::new();
    for part in uri_path.trim_start_matches('/').split('/') {
        if !part.is_empty() {
            current.push('/');
            current.push_str(part);
            crumbs.push((current.clone(), part.to_owned()));
        }
    }
    let crumb_links: Vec<_> = crumbs
        .into_iter()
        .map(|(path, label)| (" » ", a!(href = path, label)))
        .collect();

    html!(
        head!(meta!(charset = "utf-8"), title!(&title_text)),
        body!(
            h1!(&title_text),
            div!(a!(href = "/", "/"), crumb_links),
            hr!(),
            table!(
                style = "width:100%; border-collapse:collapse;",
                thead!(tr!(
                    th!(align = "left", "Name"),
                    th!(align = "left", "Last Modified"),
                    th!(align = "left", "Size"),
                )),
                tbody!(rows),
            ),
            hr!(),
        ),
    )
    .into_string()
}

fn format_system_time_local(system_time: SystemTime) -> String {
    Zoned::try_from(system_time)
        .map(|zdt| zdt.strftime("%Y-%m-%d %H:%M:%S %:z").to_string())
        .unwrap_or_else(|_| "-".to_owned())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::mime::Mime;

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

    /// Regression test for [GHSA-cwv4-h3j5-w3cf]: filenames containing
    /// HTML metacharacters must be HTML-escaped (and URI-unsafe bytes
    /// percent-encoded) before being spliced into the directory listing
    /// page. Driven straight against `generate_directory_html` rather
    /// than through a real `tempdir`, because every dangerous filename
    /// shape here (`<`, `>`, `"`) is unrepresentable on NTFS — the
    /// filesystem-driven version panics on Windows runners.
    ///
    /// [GHSA-cwv4-h3j5-w3cf]: https://github.com/plabayo/rama/security/advisories/GHSA-cwv4-h3j5-w3cf
    #[test]
    fn test_escape_xss_in_listing() {
        let entries = [
            "\"><img src=x onerror=alert(1)>.txt",
            "<script src=x>alert.txt",
            "a&b.txt",
            "quote\"test.txt",
            "single'test.txt",
        ]
        .into_iter()
        .map(|name| DirEntry::new(name.to_owned(), false, SystemTime::UNIX_EPOCH, 0))
        .collect();

        let uri: Uri = "/".parse().expect("static `/` is a valid uri");
        let payload = generate_directory_html(entries, &uri);

        // No raw HTML/JS injection survives — the dangerous shape is the
        // unescaped `<…>` tag, so it's enough to confirm those bytes
        // never reach the parser.
        assert!(
            !payload.contains("<script src=x>"),
            "raw <script> tag present in body: {payload}",
        );
        assert!(
            !payload.contains("<img src=x"),
            "raw <img> tag present in body: {payload}",
        );

        // Escaped forms are emitted instead — link *text* goes through
        // the `html!` macro's `IntoHtml::escape_and_write`.
        assert!(payload.contains("&lt;script src=x&gt;alert"));
        assert!(payload.contains("&lt;img src=x"));
        assert!(payload.contains("a&amp;b.txt"));
        assert!(payload.contains("&quot;test.txt"));
        assert!(payload.contains("&#x27;test.txt"));

        // Per-row href values are built through
        // `rama_net::uri::Uri::path_mut`, which percent-encodes the
        // URI-unsafe bytes (`"`, `<`, `>`, space, …) and leaves
        // URI-safe ones (`&`, `'`) alone — the latter then pass through
        // the html attribute writer, which HTML-escapes them. Both
        // properties together rule out a future regression that spliced
        // `entry.name` raw into the href again.
        assert!(payload.contains(r#"href="/quote%22test.txt""#));
        assert!(payload.contains(r#"href="/%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E.txt""#));
        assert!(payload.contains(r#"href="/%3Cscript%20src=x%3Ealert.txt""#));
        assert!(payload.contains(r#"href="/a&amp;b.txt""#));
        assert!(payload.contains(r#"href="/single&#x27;test.txt""#));
    }
}
