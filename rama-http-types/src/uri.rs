//! HTTP URI types — re-exported from the native [`rama_net::uri`] implementation.
//!
//! `rama_http_types::Uri` IS `rama_net::uri::Uri`: a single, RFC-3986-complete
//! URI type shared across the whole stack, replacing the previous `http` crate
//! re-export.

use rama_core::error::BoxError;
use rama_core::error::BoxErrorExt as _;

#[doc(inline)]
pub use rama_net::uri::*;

/// Scheme alias kept for source compatibility: a URI scheme is a
/// [`rama_net::Protocol`].
#[doc(inline)]
pub use rama_net::Protocol as Scheme;

/// Strip `prefix` from the path of `uri`, returning a new [`Uri`] with the
/// prefix removed (re-rooted at `/`). Matching is ASCII-case-insensitive on the
/// raw path bytes, mirroring nested-router prefix stripping.
///
/// Returns an error when the path does not start with `prefix`.
pub fn try_to_strip_path_prefix_from_uri(
    uri: &Uri,
    prefix: impl AsRef<str>,
) -> Result<Uri, BoxError> {
    let mut uri = uri.clone();
    let opts = PathMatchOptions {
        ignore_ascii_case: true,
        ..Default::default()
    };
    if uri.path_mut().strip_prefix_with_opts(prefix.as_ref(), opts) {
        Ok(uri)
    } else {
        Err(BoxError::from_static_str(
            "URI's path does NOT contain prefix",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_to_strip_path_prefix_from_uri() {
        for (input_uri_str, prefix, maybe_output_uri_str) in [
            ("https://example.com", "", Some("https://example.com/")),
            ("https://example.com", "/", Some("https://example.com/")),
            ("https://example.com/", "", Some("https://example.com/")),
            ("https://example.com/", "/", Some("https://example.com/")),
            ("https://example.com/", "/foo", None),
            (
                "https://example.com/foo",
                "/",
                Some("https://example.com/foo"),
            ),
            (
                "https://example.com/foo",
                "/foo",
                Some("https://example.com/"),
            ),
            (
                "https://example.com/foo",
                "foo",
                Some("https://example.com/"),
            ),
            (
                "https://example.com/foo/bar",
                "foo",
                Some("https://example.com/bar"),
            ),
            (
                "https://example.com/foo/bar",
                "FOO",
                Some("https://example.com/bar"),
            ),
            (
                "https://example.com/FOO/BAR",
                "foo",
                Some("https://example.com/BAR"),
            ),
            ("https://example.com/foo/bar", "bar", None),
            // mid-segment prefix is rejected: matching is segment-boundary by
            // default (`foo/b` is not a `/`-aligned prefix of `/foo/bar`).
            ("https://example.com/foo/bar", "foo/b", None),
        ] {
            let input_uri: Uri = input_uri_str.parse().unwrap();
            match (
                try_to_strip_path_prefix_from_uri(&input_uri, prefix),
                maybe_output_uri_str,
            ) {
                (Err(_), None) => (),
                (Ok(mod_uri), Some(expected_output_uri_str)) => {
                    assert_eq!(
                        mod_uri.to_string(),
                        expected_output_uri_str,
                        "input: {:?}",
                        (input_uri_str, prefix, maybe_output_uri_str)
                    );
                }
                (result, expected) => {
                    panic!(
                        "unexpected result '{result:?}', expected: '{expected:?}'; input: {:?}",
                        (input_uri_str, prefix, maybe_output_uri_str)
                    );
                }
            }
        }
    }
}
