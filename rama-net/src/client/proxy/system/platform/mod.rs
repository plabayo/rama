#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use std::str::FromStr;

#[cfg(any(
    test,
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext};

#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use crate::Protocol;
#[cfg(any(
    test,
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use crate::address::ProxyAddress;
#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use crate::uri::Uri;

#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use super::super::bypass::BypassRuleDialect;
#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use super::proxy_address;
use super::{SystemProxyConfig, SystemProxyInvalidBypassRulePolicy};

#[cfg(target_os = "android")]
mod android;
#[cfg(all(target_vendor = "apple", not(target_os = "android")))]
mod apple;
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )),
    expect(
        dead_code,
        reason = "native desktop readers are unused when parser tests run on another target"
    )
)]
mod desktop_unix;
#[cfg(any(test, target_os = "windows"))]
mod windows;

pub(super) async fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    #[cfg(target_os = "android")]
    return android::read(policy);

    #[cfg(all(target_vendor = "apple", not(target_os = "android")))]
    return apple::read(policy);

    #[cfg(target_os = "windows")]
    return windows::read(policy);

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    return desktop_unix::read(policy).await;

    #[cfg(not(any(
        target_os = "android",
        target_vendor = "apple",
        target_os = "windows",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = policy;
        Ok(SystemProxyConfig::default())
    }
}

#[cfg(any(
    test,
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn parse_proxy_endpoint(value: &str, default_protocol: Protocol) -> Result<ProxyAddress, BoxError> {
    let mut value = value.trim().trim_matches(['\'', '"']).trim().to_owned();
    if value.is_empty() {
        return Err(BoxError::from_static_str("system proxy endpoint is empty"));
    }
    if value
        .as_bytes()
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"socks://"))
    {
        value.replace_range(..8, "socks5://");
    }
    if !value.contains("://") {
        value = format!("{}://{value}", default_protocol.as_str());
    }
    let mut proxy =
        ProxyAddress::try_from(value.as_str()).context("parse system proxy endpoint")?;
    if proxy.protocol.is_none() {
        proxy.protocol = Some(default_protocol);
    }
    Ok(proxy)
}

#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn parse_uri(value: &str) -> Result<Option<Uri>, BoxError> {
    let value = value.trim().trim_matches(['\'', '"']);
    if value.is_empty() {
        Ok(None)
    } else {
        Uri::from_str(value)
            .context("parse system PAC URI")
            .map(Some)
    }
}

#[cfg(any(
    test,
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn parse_delimited_string_list(value: &str) -> Vec<String> {
    value
        .trim()
        .split(|character: char| matches!(character, ',' | ';') || character.is_whitespace())
        .map(|value| value.trim().trim_matches(['\'', '"']))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn parse_gvariant_string_list(value: &str) -> Vec<String> {
    let value = value.trim();
    let value = value.strip_prefix("@as ").unwrap_or(value).trim();
    let value = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    parse_delimited_string_list(value)
        .into_iter()
        .filter_map(|value| unescape_gvariant_string(&value))
        .collect()
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn unescape_gvariant_string(value: &str) -> Option<String> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }

        match chars.next()? {
            '\\' => output.push('\\'),
            '\'' => output.push('\''),
            '"' => output.push('"'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            prefix @ ('u' | 'U') => {
                let digits = if prefix == 'u' { 4 } else { 8 };
                let mut codepoint = 0_u32;
                for _ in 0..digits {
                    codepoint = codepoint
                        .checked_mul(16)?
                        .checked_add(chars.next()?.to_digit(16)?)?;
                }
                output.push(char::from_u32(codepoint)?);
            }
            _ => return None,
        }
    }
    Some(output)
}
