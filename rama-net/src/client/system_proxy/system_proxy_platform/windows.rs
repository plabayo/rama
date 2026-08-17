#[cfg(target_os = "windows")]
use std::io;

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::GlobalFree,
    Networking::WinHttp::{
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WinHttpGetIEProxyConfigForCurrentUser,
    },
};

use super::*;

#[cfg(target_os = "windows")]
pub(super) fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let mut native = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&raw mut native) } == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(2) {
            Ok(SystemProxyConfig::default())
        } else {
            Err(error.into())
        };
    }

    let pac = unsafe { take_wide_string(native.lpszAutoConfigUrl) };
    let proxy = unsafe { take_wide_string(native.lpszProxy) };
    let bypass = unsafe { take_wide_string(native.lpszProxyBypass) };

    let mut config = proxy
        .as_deref()
        .map(parse_proxy)
        .transpose()?
        .unwrap_or_default();
    config.pac_uri = pac.as_deref().map(parse_uri).transpose()?.flatten();
    if let Some(bypass) = bypass {
        config.try_set_bypass(parse_string_list(&bypass), policy)?;
    }
    Ok(config)
}

#[cfg(target_os = "windows")]
unsafe fn take_wide_string(pointer: windows_sys::core::PWSTR) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0;
    loop {
        let current = unsafe { pointer.add(length) };
        if unsafe { *current } == 0 {
            break;
        }
        length += 1;
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) });
    unsafe { GlobalFree(pointer.cast()) };
    Some(value)
}

fn parse_proxy(value: &str) -> Result<SystemProxyConfig, BoxError> {
    if value.trim().is_empty() {
        return Ok(SystemProxyConfig::default());
    }

    let mut config = SystemProxyConfig::default();
    let mut fallback = None;
    for item in value
        .split(|character: char| character == ';' || character.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let Some((kind, endpoint)) = item.split_once('=') else {
            fallback = Some(parse_proxy_endpoint(item, Protocol::HTTP)?);
            continue;
        };
        match kind.trim().to_ascii_lowercase().as_str() {
            "http" => config.http = Some(parse_proxy_endpoint(endpoint, Protocol::HTTP)?),
            "https" => config.https = Some(parse_proxy_endpoint(endpoint, Protocol::HTTP)?),
            // Rama intentionally supports SOCKS5 only. Treat WinINET's
            // historical `socks=` spelling as that modern protocol.
            "socks" | "socks5" => {
                config.socks5 = Some(parse_proxy_endpoint(endpoint, Protocol::SOCKS5)?)
            }
            _ => {}
        }
    }

    if let Some(proxy) = fallback {
        config.http.get_or_insert_with(|| proxy.clone());
        config.https.get_or_insert(proxy);
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_mapping_and_bare_proxy() {
        let config = parse_proxy("http=web:8080;https=secure:8443;socks=socks:1080").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://secure:8443");
        assert_eq!(config.socks5.unwrap().to_string(), "socks5://socks:1080");

        let config = parse_proxy("proxy.example:3128").unwrap();
        assert_eq!(config.http, config.https);

        let config = parse_proxy("http=web:8080 https=secure:8443 socks=socks:1080").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://secure:8443");
        assert_eq!(config.socks5.unwrap().to_string(), "socks5://socks:1080");

        let config = parse_proxy("http=web:8080 default:3128").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://default:3128");
        assert!(parse_proxy("").unwrap().is_empty());

        parse_proxy_endpoint("", Protocol::HTTP).unwrap_err();
        for endpoint in ["socks://localhost:1080", "SOCKS://localhost:1080"] {
            assert_eq!(
                parse_proxy_endpoint(endpoint, Protocol::HTTP)
                    .unwrap()
                    .protocol,
                Some(Protocol::SOCKS5)
            );
        }
    }
}
