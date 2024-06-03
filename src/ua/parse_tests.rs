use crate::ua::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentInfo, UserAgentKind,
};

#[test]
fn test_parse_desktop_ua() {
    let ua_str = "desktop";
    let mut ua = UserAgent::new(ua_str);

    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);
    assert!(ua.info().is_none());
    assert_eq!(ua.platform(), None);

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Rustls);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_too_long_ua() {
    let ua_str = " ".repeat(512) + "desktop";
    let mut ua = UserAgent::new(ua_str.clone());

    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);
    assert_eq!(ua.info(), None);
    assert_eq!(ua.platform(), None);

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Rustls);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_windows() {
    let ua_str = "windows";
    let mut ua = UserAgent::new(ua_str);

    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);
    assert_eq!(ua.info(), None);
    assert_eq!(ua.platform(), Some(PlatformKind::Windows));

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Rustls);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_chrome() {
    let ua_str = "chrome";
    let mut ua = UserAgent::new(ua_str);

    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);
    assert_eq!(
        ua.info(),
        Some(UserAgentInfo {
            kind: UserAgentKind::Chromium,
            version: None,
        })
    );
    assert_eq!(ua.platform(), None);

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Boringssl);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_windows_chrome() {
    let ua_str = "windows chrome";
    let mut ua = UserAgent::new(ua_str);

    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);
    assert_eq!(
        ua.info(),
        Some(UserAgentInfo {
            kind: UserAgentKind::Chromium,
            version: None,
        })
    );
    assert_eq!(ua.platform(), Some(PlatformKind::Windows));

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Boringssl);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_windows_chrome_with_version() {
    let ua_str = "windows chrome/124";
    let mut ua = UserAgent::new(ua_str);

    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);
    assert_eq!(
        ua.info(),
        Some(UserAgentInfo {
            kind: UserAgentKind::Chromium,
            version: Some(124),
        })
    );
    assert_eq!(ua.platform(), Some(PlatformKind::Windows));

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Boringssl);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_mobile_ua() {
    for ua_str in &["mobile", "phone", "tablet"] {
        let mut ua = UserAgent::new(*ua_str);

        assert_eq!(ua.header_str(), *ua_str);
        assert_eq!(ua.device(), DeviceKind::Mobile);
        assert_eq!(ua.info(), None);
        assert_eq!(ua.platform(), None);

        // Http/Tls agents do have defaults
        assert_eq!(ua.http_agent(), HttpAgent::Chromium);
        assert_eq!(ua.tls_agent(), TlsAgent::Rustls);

        // Overwrite http agent
        ua.with_http_agent(HttpAgent::Firefox);
        assert_eq!(ua.http_agent(), HttpAgent::Firefox);

        // Overwrite tls agent
        ua.with_tls_agent(TlsAgent::Nss);
        assert_eq!(ua.tls_agent(), TlsAgent::Nss);
        assert_eq!(ua.http_agent(), HttpAgent::Firefox);
    }
}

#[test]
fn test_parse_happy_path_unknown_ua() {
    let ua_str = "rama/0.2.0";
    let mut ua = UserAgent::new(ua_str);

    // UA Is always stored as is.
    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);

    // No information should be known about the UA.
    assert!(ua.info().is_none());
    assert!(ua.platform().is_none());

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Rustls);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_happy_path_ua_macos_chrome() {
    let ua_str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    let mut ua = UserAgent::new(ua_str);

    assert_eq!(ua.header_str(), ua_str);
    assert_eq!(ua.device(), DeviceKind::Desktop);
    assert_eq!(
        ua.info(),
        Some(UserAgentInfo {
            kind: UserAgentKind::Chromium,
            version: Some(124),
        })
    );
    assert_eq!(ua.platform(), Some(PlatformKind::MacOS));

    // Http/Tls
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Boringssl);

    // Overwrite http agent
    ua.with_http_agent(HttpAgent::Firefox);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);

    // Overwrite tls agent
    ua.with_tls_agent(TlsAgent::Nss);
    assert_eq!(ua.tls_agent(), TlsAgent::Nss);
    assert_eq!(ua.http_agent(), HttpAgent::Firefox);
}

#[test]
fn test_parse_happy_uas() {
    struct TestCase {
        ua: &'static str,
        kind: Option<UserAgentKind>,
        version: Option<usize>,
        platform: Option<PlatformKind>,
    }
    for test_case in &[
        TestCase {
            ua: "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0",
            kind: Some(UserAgentKind::Firefox),
            version: Some(12),
            platform: Some(PlatformKind::Windows),
        },
        TestCase {
            ua: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
            kind: None,
            version: None,
            platform: Some(PlatformKind::Windows),
        },
        TestCase {
            ua: "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5",
            kind: Some(UserAgentKind::Chromium),
            version: Some(19),
            platform: Some(PlatformKind::Windows),
        },
        TestCase {
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
            kind: Some(UserAgentKind::Chromium),
            version: Some(51),
            platform: Some(PlatformKind::Windows),
        },
        TestCase {
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.",
            kind: Some(UserAgentKind::Firefox),
            version: Some(125),
            platform: Some(PlatformKind::MacOS),
        },
        TestCase {
            ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Safari/537.3",
            kind: Some(UserAgentKind::Chromium),
            version: Some(121),
            platform: Some(PlatformKind::Linux),
        },
        TestCase {
            ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.",
            kind: Some(UserAgentKind::Safari),
            version: Some(1704),
            platform: Some(PlatformKind::IOS),
        },
        TestCase {
            ua: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.3",
            kind: Some(UserAgentKind::Chromium),
            version: Some(124),
            platform: Some(PlatformKind::Android),
        },
        TestCase {
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
            kind: Some(UserAgentKind::Safari),
            version: Some(1704),
            platform: Some(PlatformKind::MacOS),
        },
        TestCase {
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.a.1 Safari/605.1.15",
            kind: Some(UserAgentKind::Safari),
            version: Some(1700),
            platform: Some(PlatformKind::MacOS),
        },
        TestCase {
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            version: Some(1705),
            kind: Some(UserAgentKind::Safari),
            platform: Some(PlatformKind::MacOS),
        },
        TestCase {
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17 Safari/605.1.15",
            kind: Some(UserAgentKind::Safari),
            version: Some(1700),
            platform: Some(PlatformKind::MacOS),
        },
        TestCase {
            ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/109.0.0.0",
            kind: Some(UserAgentKind::Chromium),
            version: Some(124),
            platform: Some(PlatformKind::Linux),
        },
        TestCase {
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
            kind: Some(UserAgentKind::Chromium),
            version: Some(124),
            platform: Some(PlatformKind::Windows),
        },
    ] {
        let ua = UserAgent::new(test_case.ua);

        assert_eq!(ua.header_str(), test_case.ua);
        assert_eq!(ua.info(), test_case.kind.map(|kind| UserAgentInfo {
            kind,
            version: test_case.version,
        }),
        "UA = '{}'", test_case.ua);
        assert_eq!(ua.platform(), test_case.platform, "UA: {}", test_case.ua);
    }
}
