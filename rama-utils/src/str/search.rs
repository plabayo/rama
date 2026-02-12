/// Returns `true` if `sub` occurs within `s`,
/// using ASCII case insensitive comparison.
///
/// This is a convenience wrapper around [`contains_ignore_ascii_case`].
pub fn submatch_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> bool
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    contains_ignore_ascii_case(s, sub).is_some()
}

/// Returns `true` if any item produced by `sub_iter` occurs within `s`,
/// using ASCII case insensitive comparison.
///
/// This is a convenience wrapper around [`any_contains_ignore_ascii_case`].
pub fn any_submatch_ignore_ascii_case<T, I>(s: T, sub_iter: I) -> bool
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item: AsRef<[u8]>>,
{
    any_contains_ignore_ascii_case(s, sub_iter).is_some()
}

/// Finds the first occurrence of `sub` within `s`,
/// using ASCII case insensitive comparison.
///
/// The returned index is a byte offset into `s`.
/// If `sub` is empty, this returns `Some(0)`.
pub fn contains_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> Option<usize>
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    let s = s.as_ref();
    let sub = sub.as_ref();

    let n = sub.len();

    if n == 0 {
        return Some(0);
    }

    s.windows(n)
        .position(|window| window.eq_ignore_ascii_case(sub))
}

/// Finds the first match of any substring from `sub_iter` within `s`,
/// using ASCII case insensitive comparison.
///
/// The returned index is a byte offset into `s`.
/// Iteration order decides which candidate is considered first.
#[inline(always)]
pub fn any_contains_ignore_ascii_case<T, I>(s: T, sub_iter: I) -> Option<usize>
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item: AsRef<[u8]>>,
{
    let haystack = s.as_ref();
    sub_iter
        .into_iter()
        .find_map(|sub| contains_ignore_ascii_case(haystack, sub))
}

/// Returns `true` if `s` starts with `sub`, using ASCII case insensitive comparison.
///
/// If `sub` is empty, this returns `true`.
pub fn starts_with_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> bool
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    let s = s.as_ref();
    let sub = sub.as_ref();

    let n = sub.len();

    s.get(..n)
        .is_some_and(|start| start.eq_ignore_ascii_case(sub))
}

/// Returns `true` if `s` starts with any prefix from `sub_iter`,
/// using ASCII case insensitive comparison.
///
/// Iteration order does not matter for the result, only for the amount of work performed.
pub fn any_starts_with_ignore_ascii_case<T, I>(s: T, sub_iter: I) -> bool
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item: AsRef<[u8]>>,
{
    let search_space = s.as_ref();
    sub_iter
        .into_iter()
        .any(|prefix| starts_with_ignore_ascii_case(search_space, prefix))
}

/// Returns `true` if `s` ends with `sub`, using ASCII case insensitive comparison.
///
/// If `sub` is empty, this returns `true`.
pub fn ends_with_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> bool
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    let s = s.as_ref();
    let sub = sub.as_ref();
    let n = sub.len();

    let start_index = s.len().checked_sub(n);
    start_index
        .and_then(|i| s.get(i..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(sub))
}

/// Returns `true` if `s` ends with any suffix from `sub_iter`,
/// using ASCII case insensitive comparison.
///
/// If any suffix is empty, this returns `true`.
/// Iteration order does not matter for the result, only for the amount of work performed.
pub fn any_ends_with_ignore_ascii_case<T, I>(s: T, sub_iter: I) -> bool
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item: AsRef<[u8]>>,
{
    let search_space = s.as_ref();
    sub_iter
        .into_iter()
        .any(|suffix| ends_with_ignore_ascii_case(search_space, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_contains_cases(s: &str, sub: &str, expected: Option<usize>) {
        assert_eq!(
            super::contains_ignore_ascii_case(s, sub),
            expected,
            "contains_ignore_ascii_case({s:?}, {sub:?})",
        );
        assert_eq!(
            super::submatch_ignore_ascii_case(s, sub),
            expected.is_some(),
            "submatch_ignore_ascii_case({s:?}, {sub:?})",
        );
    }

    #[test]
    fn test_starts_with_ignore_ascii_case() {
        assert!(starts_with_ignore_ascii_case("user-agent", "user"));
        assert!(starts_with_ignore_ascii_case("User-Agent", "user"));
        assert!(starts_with_ignore_ascii_case("USER-AGENT", "user"));
        assert!(!starts_with_ignore_ascii_case("user-agent", "agent"));
        assert!(!starts_with_ignore_ascii_case("User-Agent", "agent"));
    }

    #[test]
    fn test_starts_with_ignore_ascii_case_empty_sub() {
        assert!(starts_with_ignore_ascii_case("foo", ""));
        assert!(starts_with_ignore_ascii_case("", ""));
    }

    #[test]
    fn test_any_starts_with_ignore_ascii_case() {
        assert!(any_starts_with_ignore_ascii_case(
            "User-Agent",
            ["user", "host"]
        ));
        assert!(any_starts_with_ignore_ascii_case(
            "User-Agent",
            ["HOST", "USER"]
        ));
        assert!(!any_starts_with_ignore_ascii_case(
            "User-Agent",
            ["host", "accept"]
        ));
    }

    #[test]
    fn test_any_starts_with_ignore_ascii_case_empty_iter() {
        let empty: [&str; 0] = [];
        assert!(!any_starts_with_ignore_ascii_case("foo", empty));
        assert!(!any_starts_with_ignore_ascii_case("", empty));
    }

    #[test]
    fn test_ends_with_ignore_ascii_case() {
        assert!(ends_with_ignore_ascii_case("user-agent", "agent"));
        assert!(ends_with_ignore_ascii_case("User-Agent", "agent"));
        assert!(ends_with_ignore_ascii_case("USER-AGENT", "agent"));
        assert!(!ends_with_ignore_ascii_case("user-agent", "user"));
        assert!(!ends_with_ignore_ascii_case("User-Agent", "user"));
    }

    #[test]
    fn test_ends_with_ignore_ascii_case_empty_sub() {
        assert!(ends_with_ignore_ascii_case("foo", ""));
        assert!(ends_with_ignore_ascii_case("", ""));
    }

    #[test]
    fn test_any_ends_with_ignore_ascii_case() {
        assert!(any_ends_with_ignore_ascii_case(
            "User-Agent",
            ["agent", "host"]
        ));
        assert!(any_ends_with_ignore_ascii_case(
            "User-Agent",
            ["HOST", "AGENT"]
        ));
        assert!(!any_ends_with_ignore_ascii_case(
            "User-Agent",
            ["host", "accept"]
        ));
    }

    #[test]
    fn test_any_ends_with_ignore_ascii_case_empty_iter() {
        let empty: [&str; 0] = [];
        assert!(!any_ends_with_ignore_ascii_case("foo", empty));
        assert!(!any_ends_with_ignore_ascii_case("", empty));
    }

    #[test]
    fn test_any_ends_with_ignore_ascii_case_empty_sub_present() {
        assert!(any_ends_with_ignore_ascii_case("foo", [""]));
        assert!(any_ends_with_ignore_ascii_case("", [""]));
    }

    #[test]
    fn test_any_ends_with_ignore_ascii_case_prefers_truth_over_order() {
        assert!(any_ends_with_ignore_ascii_case("abc", ["@", "bc"]));
        assert!(any_ends_with_ignore_ascii_case("abc", ["bc", "@"]));
    }

    #[test]
    fn test_contains_ignore_ascii_case_empty_sub() {
        assert_contains_cases("foo", "", Some(0));
        assert_contains_cases("", "", Some(0));
    }

    #[test]
    fn test_contains_ignore_ascii_case_common_failures() {
        for (s, sub) in [
            ("", "foo"),
            ("a", "ab"),
            ("pit", "pot"),
            ("speculaas", "loos"),
        ] {
            assert_contains_cases(s, sub, None);
        }
    }

    #[test]
    fn test_contains_ignore_ascii_case_success_start_middle_end() {
        for (s, sub, index) in [
            ("balloon", "b", 0),
            ("balloon", "ba", 0),
            ("balloon", "llo", 2),
            ("balloon", "on", 5),
            ("balloon", "n", 6),
        ] {
            assert_contains_cases(s, sub, Some(index));
        }
    }

    #[test]
    fn test_contains_ignore_ascii_case_success_case_insensitive() {
        for (s, sub, index) in [
            ("balloon", "B", 0),
            ("balloon", "BA", 0),
            ("balloon", "LLO", 2),
            ("balloon", "lLoO", 2),
            ("balloon", "ON", 5),
            ("balloon", "On", 5),
            ("balloon", "oN", 5),
            ("balloon", "N", 6),
        ] {
            assert_contains_cases(s, sub, Some(index));
        }
    }

    #[test]
    fn test_contains_ignore_ascii_case_success_first_match() {
        for (s, sub, index) in [
            ("Ho-HaHa-Hi", "ho", 0),
            ("Ho-HaHa-Hi", "ha", 3),
            ("Ho-HaHa-Hi", "ha-", 5),
            ("Ho-HaHa-Hi", "hi", 8),
        ] {
            assert_contains_cases(s, sub, Some(index));
        }
    }

    #[test]
    fn test_contains_ignore_ascii_case_non_ascii_bytes_are_not_case_folded() {
        let haystack = b"\xC3\xA9"; // UTF8 for é
        assert_eq!(
            super::contains_ignore_ascii_case(haystack.as_slice(), b"\xC3\xA9"),
            Some(0)
        );
        assert_eq!(
            super::contains_ignore_ascii_case(haystack.as_slice(), b"\xC3\x89"),
            None
        );
    }

    #[test]
    fn test_any_contains_ignore_ascii_case_common_failures() {
        for (s, sub) in [
            ("", "foo"),
            ("a", "ab"),
            ("pit", "pot"),
            ("speculaas", "loos"),
        ] {
            assert!(
                !super::any_submatch_ignore_ascii_case(s, &[sub]),
                "{sub:?} in {s:?}",
            );
        }
    }

    #[test]
    fn test_any_contains_ignore_ascii_case_empty_iter_yields_none() {
        let empty: [&str; 0] = [];
        assert_eq!(super::any_contains_ignore_ascii_case("foo", empty), None);
        assert_eq!(super::any_contains_ignore_ascii_case("", empty), None);
        assert!(!super::any_submatch_ignore_ascii_case("foo", empty));
        assert!(!super::any_submatch_ignore_ascii_case("", empty));
    }

    #[test]
    fn test_any_contains_ignore_ascii_case_empty_sub_present() {
        assert_eq!(super::any_contains_ignore_ascii_case("foo", [""]), Some(0));
        assert_eq!(super::any_contains_ignore_ascii_case("", [""]), Some(0));
        assert!(super::any_submatch_ignore_ascii_case("foo", [""]));
        assert!(super::any_submatch_ignore_ascii_case("", [""]));
    }

    #[test]
    fn test_any_contains_ignore_ascii_case_start_middle_end() {
        for (s, subs, index) in [
            ("balloon", vec!["b"], 0),
            ("balloon", vec!["b", "@"], 0),
            ("balloon", vec!["@", "b"], 0),
            ("balloon", vec!["ba"], 0),
            ("balloon", vec!["ba", "@"], 0),
            ("balloon", vec!["@", "ba"], 0),
            ("balloon", vec!["llo"], 2),
            ("balloon", vec!["llo", "@"], 2),
            ("balloon", vec!["@", "llo"], 2),
            ("balloon", vec!["on"], 5),
            ("balloon", vec!["on", "@"], 5),
            ("balloon", vec!["@", "on"], 5),
            ("balloon", vec!["n"], 6),
            ("balloon", vec!["n", "@"], 6),
            ("balloon", vec!["@", "n"], 6),
        ] {
            assert_eq!(
                super::any_contains_ignore_ascii_case(s, &subs[..]),
                Some(index),
                "any_of({subs:?}) in {s:?}",
            );
            assert!(
                super::any_submatch_ignore_ascii_case(s, &subs[..]),
                "any_submatch({subs:?}) in {s:?}",
            );
        }
    }

    #[test]
    fn test_any_contains_ignore_ascii_case_success_first_match_in_iterator_order() {
        assert_eq!(
            super::any_contains_ignore_ascii_case("abc", ["bc", "ab"]),
            Some(1),
        );
        assert_eq!(
            super::any_contains_ignore_ascii_case("abc", ["ab", "bc"]),
            Some(0),
        );
    }

    #[test]
    fn test_any_contains_ignore_ascii_case_success_single_item() {
        for (s, sub, index) in [
            ("Ho-HaHa-Hi", "ho", 0),
            ("Ho-HaHa-Hi", "ha", 3),
            ("Ho-HaHa-Hi", "ha-", 5),
            ("Ho-HaHa-Hi", "hi", 8),
        ] {
            assert_eq!(
                super::any_contains_ignore_ascii_case(s, &[sub]),
                Some(index),
                "{sub:?} in {s:?}",
            );
            assert!(
                super::any_submatch_ignore_ascii_case(s, &[sub]),
                "{sub:?} in {s:?}",
            );
        }
    }
}
