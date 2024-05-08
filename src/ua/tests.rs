use crate::ua::{DeviceKind, HttpAgent, TlsAgent, UserAgent};

#[test]
fn test_parse_happy_path_unknown_ua() {
    let ua_str = "rama/0.2.0";
    let ua: UserAgent = ua_str.parse().unwrap();

    // UA Is always stored as is.
    assert_eq!(ua.header_str(), Some(ua_str));
    assert_eq!(ua.device(), DeviceKind::Desktop);

    // No information should be known about the UA.
    assert!(ua.kind().is_none());
    assert!(ua.version().is_none());
    assert!(ua.platform().is_none());

    // Http/Tls agents do have defaults
    assert_eq!(ua.http_agent(), HttpAgent::Chromium);
    assert_eq!(ua.tls_agent(), TlsAgent::Rustls);
}

// #[test]
// fn test_parse_happy_path_ua_macos_chrome() {
//     let ua_str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
//     let ua: UserAgent = ua_str.parse().unwrap();
//     assert_eq!(ua.header_str(), Some(ua_str));
//     assert_eq!(ua.device(), DeviceKind::Desktop);

//     // assert_eq!(ua.kind, UserAgentKind::Chrome);
//     // assert_eq!(ua.version, 124);
//     // assert_eq!(ua.platform, PlatformKind::MacOS);
//     // assert_eq!(ua.platform_version, None);
// }
