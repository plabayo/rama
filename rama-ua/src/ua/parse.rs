#![allow(dead_code)]

use std::sync::Arc;

use rama_utils::str::{
    contains_any_ignore_ascii_case, contains_ignore_ascii_case, submatch_any_ignore_ascii_case,
    submatch_ignore_ascii_case,
};

use super::{
    DeviceKind, PlatformKind, UserAgent, UserAgentKind,
    info::{PlatformLike, UserAgentData, UserAgentInfo},
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
pub(crate) fn parse_http_user_agent_header(header: impl Into<Arc<str>>) -> UserAgent {
    let header = header.into();
    let ua = header.as_ref();
    let ua = if ua.len() > MAX_UA_LENGTH {
        match ua.get(..MAX_UA_LENGTH) {
            Some(s) => s,
            None => {
                return UserAgent {
                    header,
                    data: UserAgentData::Unknown,
                    http_agent_overwrite: None,
                    tls_agent_overwrite: None,
                };
            }
        }
    } else {
        ua
    };

    let (kind, kind_version, maybe_platform) =
        if let Some(loc) = contains_ignore_ascii_case(ua, "Firefox") {
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
        } else {
            (None, None, None)
        };

    let (maybe_platform, maybe_device) = match maybe_platform {
        Some(platform) => (Some(platform), None),
        None => {
            if submatch_ignore_ascii_case(ua, "Windows") {
                if submatch_ignore_ascii_case(ua, "X11") {
                    (None, Some(DeviceKind::Mobile))
                } else {
                    (Some(PlatformKind::Windows), None)
                }
            } else if submatch_ignore_ascii_case(ua, "Android") {
                if submatch_ignore_ascii_case(ua, "iOS") {
                    (Some(PlatformKind::IOS), None)
                } else {
                    (Some(PlatformKind::Android), None)
                }
            } else if submatch_ignore_ascii_case(ua, "Linux") {
                if submatch_any_ignore_ascii_case(ua, &["Mobile", "UCW"]) {
                    (Some(PlatformKind::Android), None)
                } else {
                    (Some(PlatformKind::Linux), None)
                }
            } else if submatch_any_ignore_ascii_case(ua, &["iOS", "iPad", "iPod", "iPhone"]) {
                (Some(PlatformKind::IOS), None)
            } else if submatch_ignore_ascii_case(ua, "Mac") {
                (Some(PlatformKind::MacOS), None)
            } else if submatch_ignore_ascii_case(ua, "Darwin") {
                if submatch_ignore_ascii_case(ua, "86") {
                    (Some(PlatformKind::MacOS), None)
                } else {
                    (Some(PlatformKind::IOS), None)
                }
            } else if submatch_any_ignore_ascii_case(ua, &["Mobile", "Phone", "Tablet", "Zune"]) {
                (None, Some(DeviceKind::Mobile))
            } else if submatch_ignore_ascii_case(ua, "Desktop") {
                (None, Some(DeviceKind::Desktop))
            } else {
                (None, None)
            }
        }
    };

    match (kind, kind_version, maybe_platform, maybe_device) {
        (Some(kind), version, platform, device) => UserAgent {
            header,
            data: UserAgentData::Standard {
                info: UserAgentInfo { kind, version },
                platform_like: match (platform, device) {
                    (Some(platform), _) => Some(PlatformLike::Platform(platform)),
                    (None, Some(device)) => Some(PlatformLike::Device(device)),
                    (None, None) => None,
                },
            },
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
        },
        (None, _, Some(platform), _) => UserAgent {
            header,
            data: UserAgentData::Platform(platform),
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
        },
        (None, _, None, Some(device)) => UserAgent {
            header,
            data: UserAgentData::Device(device),
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
        },
        (None, _, None, None) => UserAgent {
            header,
            data: UserAgentData::Unknown,
            http_agent_overwrite: None,
            tls_agent_overwrite: None,
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

#[cfg(test)]
mod tests {
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
                "test_case: '{test_case}'",
            );
            assert_eq!(
                super::parse_ua_version_safari(format!("foo {test_case}").as_str()),
                expected_version,
                "[prefixed] test_case: '{test_case}'",
            );
            assert_eq!(
                super::parse_ua_version_safari(format!("{test_case} bar").as_str()),
                expected_version,
                "[postfixed] test_case: '{test_case}'",
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
                "test_case: '{test_case}'",
            );
            assert_eq!(
                super::parse_ua_version_firefox_and_chromium(format!("foo {test_case}").as_str()),
                expected_version,
                "[prefixed] test_case: '{test_case}'",
            );
            assert_eq!(
                super::parse_ua_version_firefox_and_chromium(format!("{test_case} bar").as_str()),
                expected_version,
                "[postfixed] test_case: '{test_case}'",
            );
        }
    }
}
