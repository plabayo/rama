#![allow(dead_code)]

use super::{
    info::{UserAgentData, UserAgentInfo},
    DeviceKind, PlatformKind, UserAgent, UserAgentKind,
};

/// Maximum length of a User Agent string that we take into consideration.
/// This is significantly longer then expected in the wild where at most we observed around 300 characters.
const MAX_UA_LENGTH: usize = 512;

/// parse the http user agent string and return a [`UserAgent`] info,
/// containing the parsed information or fallback to defaults in case of a parse failure.
///
/// # Remarks
///
/// NOTE that this function does not aim to be:
///
/// - super accurate: it aims to be fast and good for the popular cases;
/// - complete: we do not care about all the possible user agents out there, only the popular ones.
///
/// That said. Do open a ticket if you find bugs or think something is missing.
pub(crate) fn parse_http_user_agent_header(header: String) -> UserAgent {
    let ua = header.as_str();
    let ua = if ua.len() > MAX_UA_LENGTH {
        match ua.get(..MAX_UA_LENGTH) {
            Some(s) => s,
            None => {
                return UserAgent {
                    header,
                    data: UserAgentData::Unknown,
                    http_agent_overwrite: None,
                    tls_agent_overwrite: None,
                    preserve_ua_header: false,
                }
            }
        }
    } else {
        ua
    };

    let (kind, kind_version, maybe_platform) = if let Some(loc) =
        contains_ignore_ascii_case(ua, "Firefox")
    {
        let kind = UserAgentKind::Firefox;
        let kind_version = parse_ua_version_firefox_and_chromium(&ua[loc..]);
        (Some(kind), kind_version, None)
    } else if let Some(loc) = contains_ignore_ascii_case(ua, "Chrom") {
        let kind = UserAgentKind::Chromium;
        let kind_version = parse_ua_version_firefox_and_chromium(&ua[loc..]);
        (Some(kind), kind_version, None)
    } else if contains_ignore_ascii_case(ua, "Safari").is_some() {
        if let Some(firefox_loc) = contains_ignore_ascii_case(ua, "FxiOS") {
            let kind = UserAgentKind::Firefox;
            let kind_version = parse_ua_version_firefox_and_chromium(&ua[firefox_loc..]);
            (Some(kind), kind_version, Some(PlatformKind::IOS))
        } else if let Some(chrome_loc) = contains_ignore_ascii_case(ua, "CriOS") {
            let kind = UserAgentKind::Chromium;
            let kind_version = parse_ua_version_firefox_and_chromium(&ua[chrome_loc..]);
            (Some(kind), kind_version, Some(PlatformKind::IOS))
        } else if let Some(chromium_loc) = contains_any_ignore_ascii_case(ua, &["Opera"]) {
            let kind = UserAgentKind::Chromium;
            let kind_version = parse_ua_version_firefox_and_chromium(&ua[chromium_loc..]);
            (Some(kind), kind_version, None)
        } else {
            let kind = UserAgentKind::Safari;
            let kind_version = parse_ua_version_safari(ua);
            (Some(kind), kind_version, None)
        }
    } else if contains_any_ignore_ascii_case(ua, &["Mobile", "Phone", "Tablet", "Zune"]).is_some() {
        return UserAgent {
            header,
            data: UserAgentData::Device(DeviceKind::Mobile),
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
            preserve_ua_header: false,
        };
    } else if contains_ignore_ascii_case(ua, "Desktop").is_some() {
        return UserAgent {
            header,
            data: UserAgentData::Device(DeviceKind::Desktop),
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
            preserve_ua_header: false,
        };
    } else {
        (None, None, None)
    };

    let maybe_platform = match maybe_platform {
        Some(platform) => Some(platform),
        None => {
            if contains_ignore_ascii_case(ua, "Windows").is_some() {
                if contains_ignore_ascii_case(ua, "X11").is_some() {
                    None
                } else {
                    Some(PlatformKind::Windows)
                }
            } else if contains_ignore_ascii_case(ua, "Android").is_some() {
                if contains_ignore_ascii_case(ua, "iOS").is_some() {
                    Some(PlatformKind::IOS)
                } else {
                    Some(PlatformKind::Android)
                }
            } else if contains_ignore_ascii_case(ua, "Linux").is_some() {
                if contains_any_ignore_ascii_case(ua, &["Mobile", "UCW"]).is_some() {
                    Some(PlatformKind::Android)
                } else {
                    Some(PlatformKind::Linux)
                }
            } else if contains_any_ignore_ascii_case(ua, &["iOS", "iPad", "iPod", "iPhone"])
                .is_some()
            {
                Some(PlatformKind::IOS)
            } else if contains_ignore_ascii_case(ua, "Mac").is_some() {
                Some(PlatformKind::MacOS)
            } else if contains_ignore_ascii_case(ua, "Darwin").is_some() {
                if contains_ignore_ascii_case(ua, "86").is_some() {
                    Some(PlatformKind::MacOS)
                } else {
                    Some(PlatformKind::IOS)
                }
            } else {
                None
            }
        }
    };

    match (kind, kind_version, maybe_platform) {
        (Some(kind), version, platform) => UserAgent {
            header,
            data: UserAgentData::Standard {
                info: UserAgentInfo { kind, version },
                platform,
            },
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
            preserve_ua_header: false,
        },
        (None, _, Some(platform)) => UserAgent {
            header,
            data: UserAgentData::Platform(platform),
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
            preserve_ua_header: false,
        },
        (None, _, None) => UserAgent {
            header,
            data: UserAgentData::Unknown,
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
            preserve_ua_header: false,
        },
    }
}

fn parse_ua_version_firefox_and_chromium(ua: &str) -> Option<usize> {
    ua.find('/').and_then(|i| {
        let start = i + 1;
        let end = ua[start..]
            .find(['.', ' '])
            .map(|i| start + i)
            .unwrap_or(ua.len());
        ua[start..end].parse().ok()
    })
}

fn parse_ua_version_safari(ua: &str) -> Option<usize> {
    ua.find("Version/").and_then(|i| {
        let start = i + 8;
        let mut parts = ua[start..].split(['.', ' ']);
        let major: usize = parts.next()?.parse().ok()?;
        let minor: usize = parts
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default();
        Some(major * 100 + minor)
    })
}

fn contains_ignore_ascii_case(s: &str, sub: &str) -> Option<usize> {
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

    #[test]
    fn test_parse_ua_version_safari() {
        for (test_case, expected_version) in [
            ("Version/14.0.1", Some(1400)),
            ("Version/14.0", Some(1400)),
            ("Version/14.3", Some(1403)),
            ("Version/14.3 ", Some(1403)),
            ("Version/14.3 foo", Some(1403)),
            ("Version/14", Some(1400)),
            ("Version/14 ", Some(1400)),
            ("Version/14 foo", Some(1400)),
            ("Version/14.", Some(1400)),
            ("Version/14.0.", Some(1400)),
            ("Version/14.3.", Some(1403)),
            ("Version/14.0.1.", Some(1400)),
            ("Version/99.99", Some(9999)),
            ("Version/99.99.", Some(9999)),
            ("Version/99.99.99", Some(9999)),
            ("Version/99.99.99.99", Some(9999)),
        ] {
            assert_eq!(
                super::parse_ua_version_safari(test_case),
                expected_version,
                "test_case: '{}'",
                test_case
            );
            assert_eq!(
                super::parse_ua_version_safari(format!("foo {test_case}").as_str()),
                expected_version,
                "[prefixed] test_case: '{}'",
                test_case
            );
            assert_eq!(
                super::parse_ua_version_safari(format!("{test_case} bar").as_str()),
                expected_version,
                "[postfixed] test_case: '{}'",
                test_case
            );
        }
    }

    #[test]
    fn test_parse_ua_version_firefox_and_chromium() {
        for (test_case, expected_version) in [
            ("/14.0.1", Some(14)),
            ("/14.0", Some(14)),
            ("/14.3", Some(14)),
            ("/14.3 ", Some(14)),
            ("/14.3 foo", Some(14)),
            ("/14", Some(14)),
            ("/14 ", Some(14)),
            ("Version/14 ", Some(14)),
            ("/14 foo", Some(14)),
            ("/14.", Some(14)),
            ("/14.0.", Some(14)),
            ("/14.3.", Some(14)),
            ("/14.0.1.", Some(14)),
            ("/99.99", Some(99)),
            ("/99.99.", Some(99)),
            ("/99.99.99", Some(99)),
            ("/99.99.99.99", Some(99)),
        ] {
            assert_eq!(
                super::parse_ua_version_firefox_and_chromium(test_case),
                expected_version,
                "test_case: '{}'",
                test_case
            );
            assert_eq!(
                super::parse_ua_version_firefox_and_chromium(format!("foo {test_case}").as_str()),
                expected_version,
                "[prefixed] test_case: '{}'",
                test_case
            );
            assert_eq!(
                super::parse_ua_version_firefox_and_chromium(format!("{test_case} bar").as_str()),
                expected_version,
                "[postfixed] test_case: '{}'",
                test_case
            );
        }
    }
}
