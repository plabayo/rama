use crate::profile::model::identity::ProfileKey;
use std::sync::Arc;

use ahash::{HashSet, HashSetExt as _};
use rama_http::{HeaderMap, HeaderValue, header::USER_AGENT};
#[cfg(feature = "tls")]
use rama_tls::client::ClientHello;

use super::*;

#[test]
fn test_ua_db_empty() {
    let db = UserAgentDatabase::default();
    assert_eq!(db.iter().count(), 0);
    assert!(db.get(&UserAgent::new("")).is_none());
    assert!(db.get(&UserAgent::new("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")).is_none());

    let rnd = db.rnd();
    assert!(rnd.is_none());

    assert!(db.iter_ua_str().next().is_none());
    assert!(db.iter_ua_kind().next().is_none());
    assert!(db.iter_platform().next().is_none());
    assert!(db.iter_device().next().is_none());
}

#[test]
fn test_ua_db_get_by_ua_str() {
    let db = get_dummy_ua_db();

    let profile = db.get(&UserAgent::new("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")).unwrap();
    assert_eq!(profile.ua_kind, Some(UserAgentKind::Chromium));
    assert_eq!(profile.ua_version, Some(120));
    assert_eq!(profile.platform, Some(PlatformKind::Windows));
    assert_eq!(
        profile
            .http
            .as_ref()
            .unwrap()
            .h1
            .as_ref()
            .unwrap()
            .headers
            .navigate
            .as_ref()
            .unwrap()
            .get(USER_AGENT)
            .unwrap()
            .to_str()
            .unwrap(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    );
    assert_eq!(
        profile
            .http
            .as_ref()
            .unwrap()
            .h2
            .as_ref()
            .unwrap()
            .headers
            .navigate
            .as_ref()
            .unwrap()
            .get(USER_AGENT)
            .unwrap()
            .to_str()
            .unwrap(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    );
}

#[test]
fn test_ua_db_get_by_ua_kind_and_device() {
    let db = get_dummy_ua_db();
    let test_cases = [
        (
            "Chrome Desktop",
            UserAgentKind::Chromium,
            DeviceKind::Desktop,
        ),
        ("Chrome Mobile", UserAgentKind::Chromium, DeviceKind::Mobile),
        (
            "Desktop Firefox",
            UserAgentKind::Firefox,
            DeviceKind::Desktop,
        ),
        (
            "Mobile with Firefox",
            UserAgentKind::Firefox,
            DeviceKind::Mobile,
        ),
        (
            "Safari on Desktop",
            UserAgentKind::Safari,
            DeviceKind::Desktop,
        ),
        ("mobile&safari", UserAgentKind::Safari, DeviceKind::Mobile),
    ];

    for (ua_str, ua_kind, device) in test_cases {
        let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
        assert_eq!(profile.ua_kind, Some(ua_kind));
        assert!(
            profile
                .platform
                .map(|p| p.device() == device)
                .unwrap_or_default()
        );
    }
}

#[test]
fn test_ua_db_get_by_ua_kind_and_platform() {
    let db = get_dummy_ua_db();
    let test_cases = [
        (
            "Chrome Windows",
            UserAgentKind::Chromium,
            PlatformKind::Windows,
        ),
        ("MacOS Chrome", UserAgentKind::Chromium, PlatformKind::MacOS),
        (
            "Chrome&Windows",
            UserAgentKind::Chromium,
            PlatformKind::Windows,
        ),
        (
            "Firefox on Windows",
            UserAgentKind::Firefox,
            PlatformKind::Windows,
        ),
        (
            "MacOS with Firefox",
            UserAgentKind::Firefox,
            PlatformKind::MacOS,
        ),
        (
            "Firefox + Linux",
            UserAgentKind::Firefox,
            PlatformKind::Linux,
        ),
    ];

    for (ua_str, ua_kind, platform) in test_cases {
        let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
        assert_eq!(profile.ua_kind, Some(ua_kind));
        assert_eq!(profile.platform, Some(platform));
    }
}

#[test]
fn test_ua_db_get_by_ua_kind() {
    let db = get_dummy_ua_db();
    let test_cases = [
        ("Firefox", UserAgentKind::Firefox),
        ("Safari", UserAgentKind::Safari),
        ("Chrome", UserAgentKind::Chromium),
        ("Chromium", UserAgentKind::Chromium),
    ];

    for (ua_str, ua_kind) in test_cases {
        let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
        assert_eq!(profile.ua_kind, Some(ua_kind), "ua_str: {ua_str}");
    }
}

#[test]
fn test_ua_db_get_by_device() {
    let db = get_dummy_ua_db();
    let test_cases = [
        ("Desktop", DeviceKind::Desktop),
        ("DESKTOP", DeviceKind::Desktop),
        ("desktop", DeviceKind::Desktop),
        ("Mobile", DeviceKind::Mobile),
        ("MOBILE", DeviceKind::Mobile),
        ("mobile", DeviceKind::Mobile),
    ];

    for (ua_str, device) in test_cases {
        let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
        assert_eq!(
            profile.platform.map(|p| p.device() == device),
            Some(true),
            "ua_str: {ua_str}",
        );
    }
}

#[test]
fn test_ua_db_get_rnd_due_to_unknown_data() {
    let db = get_dummy_ua_db();
    for _ in 0..100 {
        assert!(db.get(&UserAgent::new("curl")).is_some());
    }
}

#[test]
fn test_ua_db_get_none_due_to_unknown_data_rnd_disabled() {
    let db = get_dummy_ua_db().with_disable_unknown_user_agent_data(true);
    for _ in 0..100 {
        assert!(db.get(&UserAgent::new("curl")).is_none());
    }
}

#[test]
fn test_ua_db_rnd() {
    let db = get_dummy_ua_db();

    let mut set = HashSet::new();
    for _ in 0..db.len() * 1000 {
        let rnd = db.rnd().unwrap();
        set.insert(
            rnd.http
                .as_ref()
                .unwrap()
                .h1
                .as_ref()
                .unwrap()
                .headers
                .navigate
                .as_ref()
                .unwrap()
                .get(USER_AGENT)
                .expect("ua header")
                .to_str()
                .expect("utf-8 ua header value")
                .to_owned(),
        );
    }

    assert_eq!(set.len(), db.len());
}

#[test]
fn test_ua_db_rnd_falls_back_to_a_kind_available_in_sparse_database() {
    let mut db = UserAgentDatabase::default();
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ));

    for _ in 0..100 {
        assert_eq!(db.rnd().unwrap().ua_kind, Some(UserAgentKind::Safari));
    }
}

fn dummy_ua_profile_from_str(s: &str) -> UserAgentProfile {
    let ua = UserAgent::new(s);
    UserAgentProfile {
        key: ProfileKey::new("synthetic-test"),
        captured: None,
        ua_kind: Some(ua.ua_kind().unwrap()),
        ua_version: ua.ua_version(),
        platform: ua.platform(),
        http: Some(Arc::new(crate::profile::model::http::HttpProfile {
            h1: Some(crate::profile::model::http::Http1Profile {
                headers: crate::profile::model::http::HttpHeadersProfile {
                    navigate: Some(HeaderMap::from_iter([(
                        USER_AGENT,
                        HeaderValue::from_str(s).unwrap(),
                    )])),
                    fetch: None,
                    xhr: None,
                    form: None,
                    ws: None,
                },
                settings: Some(crate::profile::model::http::Http1Settings::default()),
            }),
            h2: Some(crate::profile::model::http::Http2Profile {
                headers: crate::profile::model::http::HttpHeadersProfile {
                    navigate: Some(HeaderMap::from_iter([(
                        USER_AGENT,
                        HeaderValue::from_str(s).unwrap(),
                    )])),
                    fetch: None,
                    xhr: None,
                    form: None,
                    ws: None,
                },
                settings: Some(crate::profile::model::http::Http2Settings::default()),
            }),
        })),
        #[cfg(feature = "tls")]
        tls: Some(Arc::new(crate::profile::model::tls::TlsProfile {
            client_hello: ClientHello::new(
                rama_tls::ProtocolVersion::TLSv1_3,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            permute_extensions: false,
            ws_client_config_overwrites: None,
        })),
        runtime: None,
    }
}

fn get_dummy_ua_db() -> UserAgentDatabase {
    let mut db = UserAgentDatabase::default();

    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.0.0"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 EdgiOS/120.0.0.0 Mobile/15E148 Safari/605.1.15"));
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ));
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ));
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    ));
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:120.0) Gecko/20100101 Firefox/120.0",
    ));
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ));
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ));
    db.insert(dummy_ua_profile_from_str(
        "Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
    ));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/605.1.15"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"));
    db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"));

    db
}

#[cfg(feature = "embed-profiles")]
#[test]
fn test_ua_db_embedded() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    assert!(!db.is_empty());
}
#[test]
fn analysis_and_partial_profiles_are_not_implicit_emulation_candidates() {
    let mut profile = dummy_ua_profile_from_str("Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36");
    let ua = UserAgent::new(profile.ua_str().unwrap().to_owned());
    profile.key.user_agent = Some(ua.header_str().into());
    profile.http = None;
    let mut db = UserAgentDatabase::default();
    db.insert(profile);
    assert_eq!(db.len(), 1);
    assert!(db.get_exact_header_str(ua.header_str()).is_some());
    assert!(db.get(&ua).is_none());
    assert!(db.rnd().is_none());
    let mut profile = dummy_ua_profile_from_str("Mozilla/5.0 Chrome/155.0.0.0 Safari/537.36");
    Arc::get_mut(profile.http.as_mut().unwrap()).unwrap().h2 = None;
    db.insert(profile);
    assert!(db.rnd().is_none());
    let complete = dummy_ua_profile_from_str("Mozilla/5.0 Chrome/156.0.0.0 Safari/537.36");
    db.insert(complete);
    assert_eq!(db.rnd().unwrap().ua_version, Some(156));
}
