#![allow(dead_code)]

use super::UserAgentInfo;
use regex::Regex;
use std::sync::OnceLock;

/// parse the http user agent string and return a [`UserAgentInfo`] struct,
/// containing the parsed information or fallback to defaults in case of a parse failure.
pub fn parse_http_user_agent(_ua: impl AsRef<str>) -> Result<UserAgentInfo, UserAgentParseError> {
    panic!("TODO");
}

/// Error returned by [`parse_http_user_agent`] in case something went wrong,
/// and no [`UserAgentInfo`] could be created.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UserAgentParseError;

impl std::fmt::Display for UserAgentParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserAgentParseError")
    }
}

impl std::error::Error for UserAgentParseError {}

macro_rules! lazy_regex {
    ($($name:ident = $value:expr;)+) => {
        $(
            #[allow(non_snake_case)]
            fn $name() -> &'static Regex {
                static $name: OnceLock<Regex> = OnceLock::new();
                $name.get_or_init(|| Regex::new($value).unwrap())
            }
        )+
    };
}

lazy_regex! {
    RE_NAME_VERSION_PAIR = r"([a-zA-Z\s\-_\/:]+)\s*(?:[vV]\s*)?([\d_\-\.]+)?";

    RE_BROWSER_EDGE = r"(?i)\bEdg(?:e|iOS|A)?";

    RE_PLATFORM_WINDOWS_MOBILE = r"(?i)\bwindows\s+mobile\b";
    RE_PLATFORM_WINDOWS = r"(?i)\bwindows\b";
    RE_PLATFORM_MAC_OS = r"(?i)\bmac(?:\s*|-)?os\b";
    RE_PLATFORM_LINUX = r"(?i)\blinux\b";
    RE_PLATFORM_ANDROID = r"(?i)\bandroid\b";
    RE_PLATFORM_IOS = r"(?i)\b(?:iPhone|iPad|iPod|iOS)\b";
}

const BROWSER_SUB_SLICE_FIREFOX_IOS: &[u8] = b"FxiOS";
const BROWSER_SUB_SLICE_FIREFOX: &[u8] = b"Firefox";
const BROWSER_SUB_SLICE_FIREFOX_LOWER: &[u8] = b"firefox";
const BROWSER_SUB_SLICE_SAFARI: &[u8] = b"Safari";
const BROWSER_SUB_SLICE_SAFARI_LOWER: &[u8] = b"safari";
const BROWSER_SUB_SLICE_ANDROID: &[u8] = b"Android";
const BROWSER_SUB_SLICE_ANDROID_LOWER: &[u8] = b"android";
const BROWSER_SUB_SLICE_CHROME: &[u8] = b"Chrome";
const BROWSER_SUB_SLICE_CHROME_IOS: &[u8] = b"CriOS";
const BROWSER_SUB_SLICE_CHROME_LOWER: &[u8] = b"chrome";
const BROWSER_SUB_SLICE_TRIDENT: &[u8] = b"Trident";
const BROWSER_SUB_SLICE_OPRGX: &[u8] = b"OPRGX";
const BROWSER_SUB_SLICE_OPR: &[u8] = b"OPR";
const BROWSER_SUB_SLICE_MMS: &[u8] = b"MMS";
const BROWSER_SUB_SLICE_BRAVE: &[u8] = b"Brave";
const BROWSER_SUB_SLICE_VIVALDI: &[u8] = b"Vivaldi";
const BROWSER_SUB_SLICE_SLIMBROWSER: &[u8] = b"SlimBrowser";
const BROWSER_SUB_SLICE_IRON: &[u8] = b"Iron";
const BROWSER_SUB_SLICE_COMODO_UNDERSCORE_DRAGON: &[u8] = b"Comodo_Dragon";
const BROWSER_SUB_SLICE_IRIDIUM: &[u8] = b"Iridium";
const BROWSER_SUB_SLICE_SAMSUNGBROWSER: &[u8] = b"SamsungBrowser";
const BROWSER_SUB_SLICE_CENT: &[u8] = b"Cent/";
const BROWSER_SUB_SLICE_YABROWSER: &[u8] = b"YaBrowser";
const BROWSER_SUB_SLICE_SLIMJET: &[u8] = b"Slimjet";
const BROWSER_SUB_SLICE_CHROMIUM: &[u8] = b"Chromium";

const EXTRACT_VERSION_FN_SUFFIX_VERSION: &[u8] = b"Version/";
const EXTRACT_VERSION_FN_SUB_SLICE_RV: &[u8] = b"rv:";
