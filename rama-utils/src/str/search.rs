pub fn submatch_ignore_ascii_case<T: AsRef<[u8]>>(s: T, sub: T) -> bool {
    contains_ignore_ascii_case(s, sub).is_some()
}

pub fn contains_ignore_ascii_case<T: AsRef<[u8]>>(s: T, sub: T) -> Option<usize> {
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

pub fn starts_with_ignore_ascii_case<T: AsRef<[u8]>>(s: T, sub: T) -> bool {
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

pub fn submatch_any_ignore_ascii_case<T: AsRef<[u8]>>(s: T, subs: &[T]) -> bool {
    contains_any_ignore_ascii_case(s, subs).is_some()
}

pub fn contains_any_ignore_ascii_case<T: AsRef<[u8]>>(s: T, subs: &[T]) -> Option<usize> {
    let s = s.as_ref();

    let max = s.len();
    let smallest_length = subs.iter().map(|s| s.as_ref().len()).min().unwrap_or(0);
    if smallest_length == 0 {
        return Some(0);
    } else if smallest_length > max {
        return None;
    }

    for i in 0..=(s.len() - smallest_length) {
        for sub in subs.iter().map(AsRef::as_ref) {
            let n = sub.len();
            if i + n > max {
                continue;
            }
            if s.get(i..i + n)
                .map(|s| s.eq_ignore_ascii_case(sub))
                .unwrap_or_default()
            {
                return Some(i);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starts_with_ignore_ascii_case() {
        assert!(starts_with_ignore_ascii_case("user-agent", "user"));
        assert!(!starts_with_ignore_ascii_case("user-agent", "agent"));
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
                !super::submatch_any_ignore_ascii_case(s, &[sub]),
                "'{sub}' in '{s}'",
            );
        }
    }

    #[test]
    fn test_contains_any_ignore_ascii_case_empty_subs() {
        assert_eq!(super::contains_any_ignore_ascii_case("foo", &[]), Some(0));
        assert_eq!(super::contains_any_ignore_ascii_case("", &[]), Some(0));
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
                super::contains_any_ignore_ascii_case(s, &subs[..]),
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
                super::contains_any_ignore_ascii_case(s, &[sub]),
                Some(index),
                "'{sub}' in '{s}'",
            );
        }
    }
}
