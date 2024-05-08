#![allow(dead_code)]

use super::UserAgent;

/// parse the http user agent string and return a [`UserAgent`] info,
/// containing the parsed information or fallback to defaults in case of a parse failure.
pub(crate) fn parse_http_user_agent(ua: impl AsRef<str>) -> Result<UserAgent, UserAgentParseError> {
    let ua = ua.as_ref();

    Ok(UserAgent {
        http_user_agent: ua.to_owned(),
        kind: None,
        version: None,
        platform: None,
        platform_version: None,
    })
}

/// Errors returned for [`UserAgent`] parsing that went wrong.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UserAgentParseError;

fn contains_ignore_ascii_case(s: &str, sub: &str) -> Option<usize> {
    let n = sub.len();
    if n > s.len() {
        return None;
    }

    (0..=(s.len() - n)).find(|&i| s[i..i + n].eq_ignore_ascii_case(sub))
}

fn contains_any_ignore_ascii_case(s: &str, subs: &[&str]) -> Option<usize> {
    let max = s.len();
    let smallest_length = subs.iter().map(|s| s.len()).min().unwrap_or(0);
    if smallest_length == 0 {
        return Some(0);
    } else if smallest_length > max {
        return None;
    }

    for i in 0..=(s.len() - smallest_length) {
        for sub in subs.iter() {
            let n = sub.len();
            if i + n > max {
                continue;
            }
            if s[i..i + n].eq_ignore_ascii_case(sub) {
                return Some(i);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    // test contains_ignore_ascii_case

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
                super::contains_ignore_ascii_case(s, sub).is_none(),
                "'{}' in '{}'",
                sub,
                s
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
                "'{}' in '{}'",
                sub,
                s
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
                "'{}' in '{}'",
                sub,
                s
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
                "'{}' in '{}'",
                sub,
                s
            );
        }
    }

    // test contains_any_ignore_ascii_case#[test]

    #[test]
    fn test_contains_any_ignore_ascii_case_common_failures() {
        for (s, sub) in [
            ("", "foo"),
            ("a", "ab"),
            ("pit", "pot"),
            ("speculaas", "loos"),
        ] {
            assert!(
                super::contains_any_ignore_ascii_case(s, &[sub]).is_none(),
                "'{}' in '{}'",
                sub,
                s
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
                "any_of({:?}) in '{}'",
                subs,
                s
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
                "'{}' in '{}'",
                sub,
                s
            );
        }
    }

    // TODO: port https://github.com/almarklein/fastuaparser/blob/master/fastuaparser.py
}
