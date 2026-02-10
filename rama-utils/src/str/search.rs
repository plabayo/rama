pub fn submatch_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> bool
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    contains_ignore_ascii_case(s, sub).is_some()
}

pub fn any_submatch_ignore_ascii_case<T, I>(s: T, sub_iter: I) -> bool
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item: AsRef<[u8]>>,
{
    any_contains_ignore_ascii_case(s, sub_iter).is_some()
}

pub fn contains_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> Option<usize>
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    let s = s.as_ref();
    let sub = sub.as_ref();

    let n = sub.len();
    if n > s.len() {
        return None;
    }

    (0..=(s.len() - n)).find(|&i| {
        s.get(i..i + n)
            .map(|s| s.eq_ignore_ascii_case(sub))
            .unwrap_or_default()
    })
}

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

pub fn starts_with_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> bool
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    let s = s.as_ref();
    let sub = sub.as_ref();

    let n = sub.len();
    if n > s.len() {
        return false;
    }

    s.get(..n)
        .map(|s| s.eq_ignore_ascii_case(sub))
        .unwrap_or_default()
}

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

pub fn ends_with_ignore_ascii_case<T1, T2>(s: T1, sub: T2) -> bool
where
    T1: AsRef<[u8]>,
    T2: AsRef<[u8]>,
{
    let s = s.as_ref();
    let sub = sub.as_ref();

    if s.len() < sub.len() {
        return false;
    }

    let start = s.len() - sub.len();
    s.get(start..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(sub))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starts_with_ignore_ascii_case() {
        assert!(starts_with_ignore_ascii_case("user-agent", "user"));
        assert!(starts_with_ignore_ascii_case("User-Agent", "user"));
        assert!(starts_with_ignore_ascii_case("USER-AGENT", "user"));
        assert!(!starts_with_ignore_ascii_case("user-agent", "agent"));
        assert!(!starts_with_ignore_ascii_case("User-Agent", "agent"));
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
    fn test_contains_ignore_ascii_case_empty_sub() {
        assert_eq!(super::contains_ignore_ascii_case("foo", ""), Some(0));
        assert_eq!(super::contains_ignore_ascii_case("", ""), Some(0));
    }

    #[test]
    fn test_contains_ignore_ascii_case_common_failures() {
        for (s, sub) in [
            ("", "foo"),
            ("a", "ab"),
            ("pit", "pot"),
            ("speculaas", "loos"),
        ] {
            assert!(
                !super::submatch_ignore_ascii_case(s, sub),
                "'{sub}' in '{s}'",
            );
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
            assert_eq!(
                super::contains_ignore_ascii_case(s, sub),
                Some(index),
                "'{sub}' in '{s}'",
            );
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
            assert_eq!(
                super::contains_ignore_ascii_case(s, sub),
                Some(index),
                "'{sub}' in '{s}'",
            );
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
            assert_eq!(
                super::contains_ignore_ascii_case(s, sub),
                Some(index),
                "'{sub}' in '{s}'",
            );
        }
    }

    #[test]
    fn test_contains_any_ignore_ascii_case_common_failures() {
        for (s, sub) in [
            ("", "foo"),
            ("a", "ab"),
            ("pit", "pot"),
            ("speculaas", "loos"),
        ] {
            assert!(
                !super::any_submatch_ignore_ascii_case(s, &[sub]),
                "'{sub}' in '{s}'",
            );
        }
    }

    #[test]
    fn test_contains_any_ignore_ascii_case_empty_subs() {
        const EMPTY_SLICE: &[&str] = &[];

        assert_eq!(
            super::any_contains_ignore_ascii_case("foo", EMPTY_SLICE),
            Some(0)
        );
        assert_eq!(
            super::any_contains_ignore_ascii_case("", EMPTY_SLICE),
            Some(0)
        );
    }

    #[test]
    fn test_contains_any_ignore_ascii_case_start_middle_end() {
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
                "any_of({subs:?}) in '{s}'",
            );
        }
    }

    #[test]
    fn test_contains_any_ignore_ascii_case_success_first_match() {
        for (s, sub, index) in [
            ("Ho-HaHa-Hi", "ho", 0),
            ("Ho-HaHa-Hi", "ha", 3),
            ("Ho-HaHa-Hi", "ha-", 5),
            ("Ho-HaHa-Hi", "hi", 8),
        ] {
            assert_eq!(
                super::any_contains_ignore_ascii_case(s, &[sub]),
                Some(index),
                "'{sub}' in '{s}'",
            );
        }
    }
}
