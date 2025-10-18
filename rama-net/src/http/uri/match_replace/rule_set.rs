use super::{UriMatchReplace, UriMatchReplaceRule};
use rama_http_types::Uri;
use std::borrow::Cow;

macro_rules! impl_uri_match_replace_on_iter {
    () => {
        fn match_replace_uri(&self, uri: &Uri) -> Option<Cow<'_, Uri>> {
            let include_query = self.iter().any(|rule| rule.include_query());
            let uri_slice = super::rule::uri_to_small_vec(uri, include_query);
            self.iter()
                .find_map(|rule| {
                    if rule.include_query() {
                        rule.try_match_replace_uri_slice(&uri_slice)
                    } else {
                        let s = uri_slice.as_slice();
                        let s = s.split(|b| *b == b'?').next().unwrap_or(s);
                        rule.try_match_replace_uri_slice(s)
                    }
                })
                .map(Cow::Owned)
        }
    };
}

impl<const N: usize> UriMatchReplace for [UriMatchReplaceRule; N] {
    impl_uri_match_replace_on_iter!();
}

impl UriMatchReplace for &[UriMatchReplaceRule] {
    impl_uri_match_replace_on_iter!();
}

impl UriMatchReplace for Vec<UriMatchReplaceRule> {
    impl_uri_match_replace_on_iter!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // ---------- helpers ----------

    fn rule(ptn: &'static str, fmt: &'static str) -> UriMatchReplaceRule {
        UriMatchReplaceRule::try_new(ptn, fmt).unwrap_or_else(|err| {
            panic!("valid rule expected for ptn={ptn:?}, fmt={fmt:?}; err = {err}")
        })
    }

    fn uri(s: &str) -> Uri {
        Uri::from_str(s).unwrap_or_else(|err| panic!("valid URI expected: {s:?}; err = {err}"))
    }

    /// Apply the given rules as different container types to a single input URI string.
    /// Returns the produced strings (or None) in the order: array, slice, vec, arc.
    fn apply_multiple_views(slice: &[UriMatchReplaceRule], input: &str) -> [Option<String>; 2] {
        let u = uri(input);

        // vec view
        let vec_rules = slice.to_vec();

        let out_slice = UriMatchReplace::match_replace_uri(&slice, &u).map(|c| c.to_string());
        let out_vec = UriMatchReplace::match_replace_uri(&vec_rules, &u).map(|c| c.to_string());

        [out_slice, out_vec]
    }

    /// Assert that for every container view the output equals `want`.
    fn expect_all_views_eq(rules: &[UriMatchReplaceRule], input: &str, want: Option<&str>) {
        let got = apply_multiple_views(rules, input);
        let want = want.map(str::to_string);
        for (i, g) in got.into_iter().enumerate() {
            assert_eq!(g, want, "container idx {i} wrong result for input: {input}");
        }
    }

    // ---------- tests ----------

    #[test]
    fn picks_first_matching_rule_in_iteration_order() {
        // Both rules match, but we expect the FIRST to be used.
        // First: rewrite to /a
        // Second: rewrite to /b
        let r1 = rule("https://example.com/*", "https://example.com/a");
        let r2 = rule("https://example.com/*", "https://example.com/b");

        expect_all_views_eq(
            &[r1, r2],
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

        expect_all_views_eq(
            &[r1, r2],
            "https://example.com/path?x=1&y=2",
            Some("https://example.com/untouched"),
        );
    }

    #[test]
    fn non_match_returns_none_for_all_containers() {
        let r = rule("http://only*", "https://$1");
        expect_all_views_eq(&[r], "https://example.com", None);
    }

    #[test]
    fn returns_owned_uri_in_cow() {
        let rules = vec![rule("http://*", "https://$1")];
        let u = uri("http://a/b");
        let got = UriMatchReplace::match_replace_uri(&rules, &u);
        match got {
            Some(Cow::Owned(uri)) => assert_eq!(uri.to_string(), "https://a/b"),
            Some(Cow::Borrowed(_)) => panic!("expected Cow::Owned, got Borrowed"),
            None => panic!("expected Some, got None"),
        }
    }

    #[test]
    fn tiny_fuzz_consistent_with_single_rule_behavior() {
        // Reference single-rule behavior: http -> https
        let single = rule("http://*", "https://$1");

        // Build a set that includes a non-matching rule first, to exercise ordering,
        // and a query-sensitive rule to exercise include_query aggregation,
        // and finally our reference rule.
        let set = vec![
            rule("ftp://*", "https://$1"),
            rule("http://host\\?*", "https://host?$1"), // will only match host with explicit query
            single.clone(),
        ];

        let hosts = ["a.com", "host", "x.y"];
        let paths = ["", "/p", "/p/q"];
        let queries = ["", "?k=v", "?x=1&y=2"];

        for h in hosts {
            for p in paths {
                for q in queries {
                    let http_in = format!("http://{h}{p}{q}");

                    // Reference output using the single rule
                    let ref_out = single
                        .match_replace_uri(&uri(&http_in))
                        .map(|u| u.to_string())
                        .expect("single rule always matches http");

                    // Set output via trait on different containers must match reference
                    for (idx, got) in apply_multiple_views(&set[..], &http_in)
                        .into_iter()
                        .enumerate()
                    {
                        let got = got
                            .unwrap_or_else(|| panic!("set {set:?} should match http: {http_in}"));
                        assert_eq!(got, ref_out, "container idx {idx} for input {http_in}");
                    }
                }
            }
        }

        // And confirm that https inputs do not match the set (none of the rules target https)
        for input in ["https://a.com", "https://host/p?q=1"] {
            for (idx, got) in apply_multiple_views(&set[..], input)
                .into_iter()
                .enumerate()
            {
                assert!(
                    got.is_none(),
                    "container idx {idx} should not match: {input}"
                );
            }
        }
    }
}
