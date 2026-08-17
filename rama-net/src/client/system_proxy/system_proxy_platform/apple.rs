use core_foundation::{
    array::CFArray,
    base::{CFType, CFTypeRef, TCFType},
    dictionary::{CFDictionary, CFDictionaryRef},
    number::CFNumber,
    string::CFString,
};

use super::*;

#[link(name = "CFNetwork", kind = "framework")]
unsafe extern "C" {
    fn CFNetworkCopySystemProxySettings() -> CFDictionaryRef;
}

pub(super) fn read() -> Result<SystemProxyConfig, BoxError> {
    let raw = unsafe { CFNetworkCopySystemProxySettings() };
    if raw.is_null() {
        return Ok(SystemProxyConfig::default());
    }
    let settings: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let mut config = SystemProxyConfig::default();

    if enabled(&settings, "HTTPEnable")
        && let (Some(host), Some(port)) = (
            string(&settings, "HTTPProxy"),
            number(&settings, "HTTPPort"),
        )
    {
        config.http = Some(proxy_address(Protocol::HTTP, host, port)?);
    }
    if enabled(&settings, "HTTPSEnable")
        && let (Some(host), Some(port)) = (
            string(&settings, "HTTPSProxy"),
            number(&settings, "HTTPSPort"),
        )
    {
        config.https = Some(proxy_address(Protocol::HTTP, host, port)?);
    }
    // iOS does not expose the macOS HTTPS proxy keys. Its networking stack
    // applies the configured HTTP proxy to both HTTP and HTTPS destinations.
    #[cfg(target_os = "ios")]
    if config.https.is_none() {
        config.https.clone_from(&config.http);
    }
    if enabled(&settings, "SOCKSEnable")
        && let (Some(host), Some(port)) = (
            string(&settings, "SOCKSProxy"),
            number(&settings, "SOCKSPort"),
        )
    {
        config.socks5 = Some(proxy_address(Protocol::SOCKS5, host, port)?);
    }
    if enabled(&settings, "ProxyAutoConfigEnable")
        && let Some(value) = string(&settings, "ProxyAutoConfigURLString")
    {
        config.pac_uri = parse_uri(&value)?;
    }
    config.exclude_simple_hostnames = enabled(&settings, "ExcludeSimpleHostnames");
    config.set_bypass(string_array(&settings, "ExceptionsList"));
    Ok(config)
}

fn value(settings: &CFDictionary<CFString, CFType>, key: &str) -> Option<CFType> {
    settings.find(CFString::new(key)).map(|value| value.clone())
}

fn enabled(settings: &CFDictionary<CFString, CFType>, key: &str) -> bool {
    number(settings, key).is_some_and(|value| value != 0)
}

fn number(settings: &CFDictionary<CFString, CFType>, key: &str) -> Option<u16> {
    value(settings, key)?
        .downcast::<CFNumber>()?
        .to_i64()?
        .try_into()
        .ok()
}

fn string(settings: &CFDictionary<CFString, CFType>, key: &str) -> Option<String> {
    value(settings, key)?
        .downcast::<CFString>()
        .map(|value| value.to_string())
}

fn string_array(settings: &CFDictionary<CFString, CFType>, key: &str) -> Vec<String> {
    let Some(array) = value(settings, key).and_then(|value| value.downcast::<CFArray>()) else {
        return Vec::new();
    };
    array
        .get_all_values()
        .into_iter()
        .filter_map(|value| {
            if value.is_null() {
                return None;
            }
            unsafe { CFType::wrap_under_get_rule(value as CFTypeRef) }
                .downcast::<CFString>()
                .map(|value| value.to_string())
        })
        .collect()
}
