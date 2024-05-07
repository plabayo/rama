use super::{PlatformKind, UserAgent, UserAgentKind};

/// parse the http user agent string and return a [`UserAgent`] info,
/// containing the parsed information or fallback to defaults in case of a parse failure.
pub(crate) fn parse_http_user_agent(ua: impl AsRef<str>) -> Result<UserAgent, UserAgentParseError> {
    let ua = ua.as_ref();

    Ok(UserAgent {
        http_user_agent: ua.to_owned(),
        kind: UserAgentKind::Unknown,
        version: 0,
        platform: PlatformKind::Unknown,
        platform_version: None,
    })
}

/// Errors returned for [`UserAgent`] parsing that went wrong.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UserAgentParseError;
