use crate::ua::{
    //PlatformKind,
    UserAgent,
    //UserAgentKind,
};

#[test]
fn test_parse_happy_path_ua_macos_chrome() {
    let ua_str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    let ua: UserAgent = ua_str.parse().unwrap();
    assert_eq!(ua.http_user_agent, ua_str);

    // assert_eq!(ua.kind, UserAgentKind::Chrome);
    // assert_eq!(ua.version, 124);
    // assert_eq!(ua.platform, PlatformKind::MacOS);
    // assert_eq!(ua.platform_version, None);
}
