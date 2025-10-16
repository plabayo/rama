use rama_core::{error::OpaqueError, telemetry::tracing};
use rama_http_types::Uri;
use rama_utils::macros::generate_set_and_with;
use rama_utils::thirdparty::wildcard::Wildcard;
use smol_str::SmolStr;

use super::{Pattern, TryIntoPattern, TryIntoUriFmt, fmt::UriFormatter};

#[derive(Debug)]
/// A rule that matches a [`Uri`] against a simple wildcard pattern and, if it
/// matches, produces a new [`Uri`] using a capture-aware formatter.
///
/// # Pattern syntax
///
/// The **pattern** is a literal byte string with `*` wildcards:
///
/// - `*` matches any (possibly empty) sequence of bytes.
/// - Matching is **case-sensitive**.
/// - The pattern is matched against the **entire** textual `Uri`
///   (for example `"https://a/b\\?c"`), not just a path segment.
/// - Notice in the previous example that `?` is escaped
///   as the `?` character by itself means a match of any 'single'
///   character which is contract to `*` that matches any "multiple" characters
/// - Each `*` produces a **1-based capture** `$1`, `$2`, … that can be
///   referenced from the formatter.
///
/// Examples:
///
/// - `"http://*"` matches any `http` URI, capturing everything after the scheme
///   and `//` into `$1`.
/// - `"https://*/docs/*"` captures the host (and optional port) into `$1` and
///   the tail after `/docs/` into `$2`.
///
/// # Formatter syntax
///
/// The **formatter** is a byte template that may contain **captures** `$N` with
/// `N` in `1..=16`. Captures are 1-based: `$1` inserts the first pattern
/// wildcard, `$2` the second, and so on.
///
/// - `$0` is not accepted, and neither is anything beyond `$16`.
/// - Missing captures are inserted as an empty string. For example, if the
///   pattern has one `*` and the formatter uses `$2`, nothing is inserted for
///   `$2`.
/// - The formatter may contain at most one `?` character. If more than
///   one `?` is present, construction fails (see **Errors**).
///
/// # Examples
///
/// Upgrade `http` to `https`:
///
/// ```rust
/// # use std::str::FromStr;
/// # use rama_http_types::Uri;
/// # use rama_net::http::uri::UriMatchReplaceRule;
/// let rule = UriMatchReplaceRule::try_new("http://*", "https://$1").unwrap();
///
/// let input: Uri = "http://example.com/x?y=1".parse().unwrap();
/// let out = rule.try_match_replace_uri(&input).unwrap();
/// assert_eq!(out.to_string(), "https://example.com/x?y=1");
///
/// // Non-matching scheme
/// let https_in: Uri = "https://example.com".parse().unwrap();
/// assert!(rule.try_match_replace_uri(&https_in).is_none());
/// ```
///
/// Reorder two captures:
///
/// ```rust
/// # use std::str::FromStr;
/// # use rama_http_types::Uri;
/// # use rama_net::http::uri::UriMatchReplaceRule;
/// let rule = UriMatchReplaceRule::try_new(
///     "https://*/docs/*",
///     "https://$1/knowledge/$2"
/// ).unwrap();
///
/// let input: Uri = "https://a.example.com/docs/rust".parse().unwrap();
/// let out = rule.try_match_replace_uri(&input).unwrap();
/// assert_eq!(out.to_string(), "https://a.example.com/knowledge/rust");
/// ```
///
/// # Edge cases and behavior
///
/// - **Empty matches**: each `*` can match an empty span. This is often useful
///   at path boundaries like `"/*/end"`.
/// - **`$0`**: accepted in the formatter but never inserts anything.
/// - **Missing indices**: using `$N` where `N` exceeds the number of pattern
///   wildcards inserts nothing, the rest of the formatter is preserved.
/// - **Multiple `?` in formatter**: invalid. The formatter accepts at most one
///   `?`. See **Errors**.
/// - **Invalid formatter escapes**: the formatter does not interpret percent
///   escapes or special encodings. It is a raw byte template plus `$N` slots.
/// - **Query handling**: pattern and formatter treat `?` and everything after
///   it as regular bytes. If your formatter includes a `?`, ensure you include
///   the query part you want, for example `"…?$1"` if your pattern captured it.
///
/// # Errors
///
/// `try_new` can fail when:
///
/// - The formatter contains **more than one `?`**.
/// - A capture token in the formatter is malformed: not a `$` followed by
///   `1..=3` digits, or the total potential formatted length would exceed the
///   configured maximum (see `UriFormatter`).
///
/// `try_match_replace_uri` never panics; it returns:
///
/// - `Some(Uri)` when the input matches and the formatted bytes parse as a
///   valid `Uri`.
/// - `None` when the input does not match the pattern **or** the formatted
///   bytes cannot be parsed as a `Uri`.
pub struct UriMatchReplaceRule {
    ptn: Wildcard<'static>,
    fmt: UriFormatter,
    ptn_include_query: bool,
    include_query_overwrite: bool,
}

impl UriMatchReplaceRule {
    #[inline]
    #[must_use]
    /// A convenience constructor that creates a rule which upgrades
    /// any `http://…` URI to `https://…` while preserving everything
    /// after the scheme.
    ///
    /// Equivalent to:
    ///
    /// ```rust
    /// # use rama_net::http::uri::UriMatchReplaceRule;
    /// let rule = UriMatchReplaceRule::try_new("http://*", "https://$1").unwrap();
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use std::str::FromStr;
    /// # use rama_http_types::Uri;
    /// # use rama_net::http::uri::UriMatchReplaceRule;
    /// let rule = UriMatchReplaceRule::http_to_https();
    /// let out = rule.try_match_replace_uri(&"http://a/b?x=1".parse::<Uri>().unwrap()).unwrap();
    /// assert_eq!(out.to_string(), "https://a/b?x=1");
    /// ```
    pub fn http_to_https() -> Self {
        Self::try_new("http://*", "https://$1").expect("to be always valid")
    }

    /// try to create a new `UriMatchReplaceRule`
    pub fn try_new(ptn: impl TryIntoPattern, fmt: impl TryIntoUriFmt) -> Result<Self, OpaqueError> {
        let Pattern {
            wildcard: ptn,
            include_query: ptn_include_query,
        } = ptn.try_into_wildcard()?;
        let fmt = fmt.try_into_fmt()?;
        // assume by default that ending on `*` for a pattern without `?`
        // means we should include query, but you can overwrite this to
        // anyway not include it.
        let include_query_overwrite = !ptn_include_query && ptn.pattern().last() == Some(&b'*');
        Ok(Self {
            ptn,
            fmt,
            ptn_include_query,
            include_query_overwrite,
        })
    }

    generate_set_and_with! {
        /// Includes the query parameter in original Uri for this rule,
        /// even if pattern or formatter does not request it.
        pub fn include_query_overwrite(mut self, include_query: bool) -> Self {
            self.include_query_overwrite = include_query;
            self
        }
    }

    #[inline]
    /// Attempts to create a new [`UriMatchReplaceRule`].
    ///
    /// - `ptn` is converted to a wildcard pattern where `*` captures arbitrary
    ///   byte sequences. Each `*` becomes `$1`, `$2`, … in the formatter.
    /// - `fmt` is converted to a `UriFormatter` where `$N` inserts the `N`-th
    ///   pattern capture. `$0` inserts nothing.
    ///
    /// See the type-level docs ([`UriMatchReplaceRule`])
    /// for details on syntax, edge cases, and errors.
    ///
    /// # Errors
    ///
    ///  [`UriMatchReplaceRule::try_match_replace_uri`] never errors; it returns:
    ///
    /// - `Some(Uri)` when the input matches and the formatted bytes parse as a
    ///   valid `Uri`.
    /// - `None` when the input does not match the pattern **or** the formatted
    ///   bytes cannot be parsed as a `Uri`
    pub fn try_match_replace_uri(&self, uri: &Uri) -> Option<Uri> {
        let mut buffer = Vec::new();
        self.try_match_replace_uri_with_buffer(uri, &mut buffer)
    }

    pub(super) fn include_query(&self) -> bool {
        self.include_query_overwrite || self.ptn_include_query || self.fmt.include_query()
    }

    pub(super) fn try_match_replace_uri_with_buffer(
        &self,
        uri: &Uri,
        buffer: &mut Vec<u8>,
    ) -> Option<Uri> {
        let s = uri_to_smoll_str(uri, self.include_query());
        self.try_match_replace_uri_str_with_buffer(&s, buffer)
    }

    pub(super) fn try_match_replace_uri_str_with_buffer(
        &self,
        s: &str,
        buffer: &mut Vec<u8>,
    ) -> Option<Uri> {
        self.ptn
            .captures(s.as_bytes())
            .and_then(|captures| self.fmt.fmt_uri(captures.as_ref(), buffer).inspect_err(|err| {
                tracing::debug!("unexpected error while formatting matched uri '{s:?}: {err}; ignore as None (~ no match)");
            }).ok())
    }
}

pub(super) fn uri_to_smoll_str(uri: &Uri, include_query: bool) -> SmolStr {
    let query = include_query
        .then(|| uri.query())
        .flatten()
        .unwrap_or_default();

    let path = uri.path().trim_matches('/');

    if let Some(authority) = uri.authority() {
        smol_str::format_smolstr!(
            "{}://{authority}{}{path}{}{query}",
            uri.scheme_str().unwrap_or("http"),
            if path.is_empty() { "" } else { "/" },
            if query.is_empty() { "" } else { "?" },
        )
    } else {
        smol_str::format_smolstr!(
            "{}{path}{}{query}",
            if path.is_empty() { "" } else { "/" },
            if query.is_empty() { "" } else { "?" },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // ---------- helpers ----------

    fn rule(ptn: &'static str, fmt: &'static str) -> UriMatchReplaceRule {
        UriMatchReplaceRule::try_new(ptn, fmt)
            .unwrap_or_else(|_| panic!("valid rule expected for ptn={ptn:?}, fmt={fmt:?}"))
    }

    fn uri(s: &str) -> Uri {
        Uri::from_str(s).unwrap_or_else(|_| panic!("valid URI expected: {s:?}"))
    }

    fn apply(rule: &UriMatchReplaceRule, input: &str) -> Option<String> {
        rule.try_match_replace_uri(&uri(input)).map(|u| {
            u.to_string()
                .trim_end_matches('/')
                .to_owned()
                .replace("/?", "?")
        })
    }

    // ---------- main cases ----------

    #[test]
    fn scheme_upgrade_single_wildcard() {
        // Pattern captures everything after the literal prefix, one based index in formatter
        let r = rule("http://*", "https://$1");

        let cases = [
            ("http://example.com", Some("https://example.com")),
            (
                "http://example.com/x?y=1",
                Some("https://example.com/x?y=1"),
            ),
            ("https://example.com", None), // does not match, scheme is already https
            ("ftp://example.com", None),
        ];

        for (input, want) in cases {
            let got = apply(&r, input);
            let want = want.map(|s| s.to_owned());
            assert_eq!(got, want, "input: {input}");
        }
    }

    #[test]
    fn multiple_wildcards_and_reordering() {
        // Two wildcards. Reorder them in the formatter.
        let r = rule("https://*/docs/*", "https://$1/knowledge/$2");

        let cases = [
            (
                "https://a.example.com/docs/rust",
                Some("https://a.example.com/knowledge/rust"),
            ),
            (
                "https://host/docs/part/leaf",
                Some("https://host/knowledge/part/leaf"),
            ),
            ("https://host/other/part", None), // missing literal segment "docs"
            ("http://host/docs/x", None),      // scheme mismatch
        ];

        for (input, want) in cases {
            let got = apply(&r, input);
            let want = want.map(|s| s.to_owned());
            assert_eq!(got, want, "input: {input}");
        }
    }

    #[test]
    fn empty_capture_allowed() {
        // Star may capture empty
        let r = rule("https://example.com/*/end", "https://example.com/$1/end");

        let cases = [
            ("https://example.com//end", None), // empty middle
            (
                "https://example.com/x/end",
                Some("https://example.com/x/end"),
            ),
            (
                "https://example.com/xx/end",
                Some("https://example.com/xx/end"),
            ),
            ("https://example.com/x/end/extra", None),
        ];

        for (input, want) in cases {
            let got = apply(&r, input);
            let want = want.map(|s| s.to_owned());
            assert_eq!(got, want, "input: {input}");
        }
    }

    #[test]
    fn identity_with_star_only_and_missing_indices() {
        // Pattern with one capture, formatter uses $2 then $1
        // $2 is missing so it inserts empty, then $1 provides the content
        let r = rule("*", "$2$1");

        let cases = [
            ("https://x/y", Some("https://x/y")),
            ("http://a/b?c#frag", Some("http://a/b?c")), // fragments are dropped because of uri module restrictions
        ];
        for (input, want) in cases {
            let got = apply(&r, input);
            let want = want.map(|s| s.to_owned());
            assert_eq!(got, want, "input: {input}");
        }
    }

    #[test]
    fn query_capture_and_preservation() {
        // Capture everything after the literal query prefix and keep it as is
        let r = rule("https://example.com/search\\?*", "https://example.com/s?$1");

        let cases = [
            (
                "https://example.com/search?q=hi&x=1",
                Some("https://example.com/s?q=hi&x=1"),
            ),
            ("https://example.com/search?", None),
            (
                "https://example.com/SEARCH?q=hi",
                Some("https://example.com/s?q=hi"),
            ), // search is not case sensitive
        ];

        for (input, want) in cases {
            let got = apply(&r, input);
            let want = want.map(|s| s.to_owned());
            assert_eq!(got, want, "input: {input}");
        }
    }

    // ---------- tiny deterministic fuzz ----------

    #[test]
    fn tiny_fuzz_http_to_https_never_panics_and_preserves_tail() {
        // Rule upgrades http to https and keeps the rest as a single capture
        let r = UriMatchReplaceRule::http_to_https();

        let hosts = ["a.com", "b.org", "x.y"];
        let paths = ["", "/p", "/p/q"];
        let queries = ["", "?k=v", "?x=1&y=2"];

        for h in hosts {
            for p in paths {
                for q in queries {
                    let input = format!("http://{h}{p}{q}");
                    let got = apply(&r, &input).expect("match expected for http input");
                    // reference expectation: flip scheme and keep tail
                    let expected = format!("https://{h}{p}{q}");
                    assert_eq!(got, expected, "input: {input}");
                }
            }
        }

        // Confirm non matches remain None
        let https_inputs = ["https://a.com", "https://a.com/p?q=1", "https://x.y/p/q"];
        for input in https_inputs {
            assert_eq!(apply(&r, input), None, "should not match: {input}");
        }
    }
}
