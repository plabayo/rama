use super::{UriMatchError, UriMatchReplace, UriMatchReplaceRule};
use rama_http_types::Uri;
use rama_utils::macros::generate_set_and_with;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A Set of [`UriMatchReplaceRule`],
/// which is an optimised version of a generic [`UriMatchReplace`] slice impl.
pub struct UriMatchReplaceRuleset {
    rules: Vec<UriMatchReplaceRule>,
    fallthrough: bool,
}

impl UriMatchReplaceRuleset {
    /// Create a new [`UriMatchReplaceRuleset`] from the given set of [`UriMatchReplaceRule`]s.
    #[inline]
    #[must_use]
    pub fn new(rules: impl IntoIterator<Item = UriMatchReplaceRule>) -> Self {
        Self::from_iter(rules)
    }

    generate_set_and_with! {
        /// Turn this set into a fallthrough set,
        /// meaning that all rules will try to be match in order as specified,
        /// each time using the last matched uri (or the input uri if no match found yet).
        ///
        /// It will still return no match found in case none of the inner rules matched.
        pub fn fallthrough(mut self, fallthrough: bool) -> Self {
            self.fallthrough = fallthrough;
            self
        }
    }
}

impl FromIterator<UriMatchReplaceRule> for UriMatchReplaceRuleset {
    fn from_iter<T: IntoIterator<Item = UriMatchReplaceRule>>(iter: T) -> Self {
        Self {
            rules: iter.into_iter().collect(),
            fallthrough: false,
        }
    }
}

impl UriMatchReplace for UriMatchReplaceRuleset {
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        let include_query = self.rules.iter().any(|rule| rule.include_query());
        let mut uri_slice = super::rule::uri_to_small_vec(uri.as_ref(), include_query);

        if self.fallthrough {
            let mut last_output = None;
            for rule in self.rules.iter() {
                if rule.include_query() {
                    if let Some(uri) = rule.try_match_replace_uri_slice(&uri_slice) {
                        super::rule::uri_to_small_vec_with_buffer(
                            &uri,
                            include_query,
                            &mut uri_slice,
                        );
                        last_output = Some(Cow::Owned(uri));
                    }
                } else {
                    let s = uri_slice.as_slice();
                    let s = s.split(|b| *b == b'?').next().unwrap_or(s);
                    if let Some(uri) = rule.try_match_replace_uri_slice(s) {
                        super::rule::uri_to_small_vec_with_buffer(
                            &uri,
                            include_query,
                            &mut uri_slice,
                        );
                        last_output = Some(Cow::Owned(uri));
                    }
                }
            }
            match last_output {
                Some(output) => Ok(output),
                None => Err(UriMatchError::NoMatch(uri)),
            }
        } else {
            for rule in self.rules.iter() {
                let opt = if rule.include_query() {
                    rule.try_match_replace_uri_slice(&uri_slice)
                } else {
                    let s = uri_slice.as_slice();
                    let s = s.split(|b| *b == b'?').next().unwrap_or(s);
                    rule.try_match_replace_uri_slice(s)
                };
                if let Some(uri) = opt {
                    return Ok(Cow::Owned(uri));
                }
            }
            Err(UriMatchError::NoMatch(uri))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- helpers ----------

    fn rule(ptn: &'static str, fmt: &'static str) -> UriMatchReplaceRule {
        UriMatchReplaceRule::try_new(ptn, fmt).unwrap_or_else(|err| {
            panic!("valid rule expected for ptn={ptn:?}, fmt={fmt:?}; err = {err}")
        })
    }

    /// Assert that for every container view the output equals `want`.
    #[allow(clippy::needless_pass_by_value)]
    fn expect_eq(rules: UriMatchReplaceRuleset, input: &'static str, want: Option<&'static str>) {
        let uri = Uri::from_static(input);
        let got = match rules.match_replace_uri(Cow::Borrowed(&uri)) {
            Ok(uri) => Some(uri),
            Err(UriMatchError::NoMatch(_)) => None,
            Err(UriMatchError::Unexpected(err)) => {
                panic!("unexpected match replace uri error: {err}")
            }
        };
        assert_eq!(
            got,
            want.map(Uri::from_static).map(Cow::Owned),
            "wrong result for input: {uri}"
        );
    }

    // ---------- tests ----------

    #[test]
    fn picks_first_matching_rule_in_iteration_order() {
        let r1 = rule("https://example.com/*", "https://example.com/a");
        let r2 = rule("https://example.com/*", "https://example.com/b");

        expect_eq(
            UriMatchReplaceRuleset::new([r1, r2]),
            "https://example.com/x",
            Some("https://example.com/a"),
        );
    }

    #[test]
    fn aggregates_include_query_across_rules_for_uri_slice_but_not_match() {
        let r1 = rule("https://example.com/path", "https://example.com/untouched");
        let r2 = rule(
            "https://example.com/path\\?*", // ensure to escape!!
            "https://example.com/rewrite?$1",
        );

        expect_eq(
            UriMatchReplaceRuleset::new([r1, r2]),
            "https://example.com/path?x=1&y=2",
            Some("https://example.com/untouched"),
        );
    }

    #[test]
    fn fallthrough_simple() {
        let r1 = rule("http://*", "https://$1");
        let r2 = rule("*://www.*", "$1://$2");

        expect_eq(
            UriMatchReplaceRuleset::new([r1, r2]).with_fallthrough(true),
            "http://www.example.com/foo?q=v",
            Some("https://example.com/foo?q=v"),
        );
    }

    #[test]
    fn non_match_returns_none() {
        let r = rule("http://only*", "https://$1");
        expect_eq(
            UriMatchReplaceRuleset::new([r]),
            "https://example.com",
            None,
        );
    }
}
