use rama_core::error::{BoxError, ErrorContext as _};
use rama_utils::str::{smol_str::format_smolstr, starts_with_ignore_ascii_case};

pub use crate::dep::hyperium::http::uri::*;

pub fn try_to_strip_path_prefix_from_uri(
    uri: &Uri,
    prefix: impl AsRef<str>,
) -> Result<Uri, BoxError> {
    let prefix = prefix.as_ref().trim_matches('/');
    let og_path = uri.path().trim_start_matches('/');

    if !starts_with_ignore_ascii_case(og_path, prefix) {
        return Err(BoxError::from("URI's path does NOT contain prefix"));
    }

    // SAFETY: above 'starts_with_ignore_ascii_case'
    // ensures that we are within the length for this slice to work
    let stripped_path = std::str::from_utf8(&og_path.as_bytes()[prefix.len()..])
        .context("interpret stripped path as utf-8 slice")?
        .trim_start_matches('/');

    let mut uri_parts = uri.clone().into_parts();

    uri_parts.path_and_query = Some(
        if let Some(query) = uri_parts
            .path_and_query
            .as_ref()
            .and_then(|paq| paq.query())
        {
            format_smolstr!("/{stripped_path}?{query}")
        } else {
            format_smolstr!("/{stripped_path}")
        }
        .parse()
        .context("parse raw str as path and query (containing stripped path)")?,
    );

    Uri::from_parts(uri_parts).context("re-create uri with stripped path from mod parts")
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
            (
                "https://example.com/foo/bar",
                "foo/b",
                Some("https://example.com/ar"),
            ),
        ] {
            let input_uri: Uri = input_uri_str.parse().unwrap();
            match (
                try_to_strip_path_prefix_from_uri(&input_uri, prefix),
                maybe_output_uri_str,
            ) {
                (Err(_), None) => (),
                (Ok(mod_uri), Some(expected_output_uri_str)) => {
                    let mod_uri_str = mod_uri.to_string();
                    assert_eq!(
                        mod_uri_str,
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
