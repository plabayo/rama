use core_foundation::{
    array::CFArray,
    base::{CFType, CFTypeRef, TCFType},
    dictionary::{CFDictionary, CFDictionaryRef},
    number::CFNumber,
    string::CFString,
};
use rama_core::error::{BoxErrorExt as _, ErrorExt as _};

use super::*;

#[link(name = "CFNetwork", kind = "framework")]
unsafe extern "C" {
    fn CFNetworkCopySystemProxySettings() -> CFDictionaryRef;
}

pub(super) fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let raw = unsafe { CFNetworkCopySystemProxySettings() };
    if raw.is_null() {
        return Ok(SystemProxyConfig::default());
    }
    let settings: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw) };
    parse_settings(&settings, policy)
}

fn parse_settings(
    settings: &CFDictionary<CFString, CFType>,
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let mut config = SystemProxyConfig::default();

    if enabled(settings, "HTTPEnable") {
        config.http = Some(proxy_address(
            Protocol::HTTP,
            required_string(settings, "HTTPProxy")?,
            required_number(settings, "HTTPPort")?,
        )?);
    }
    if enabled(settings, "HTTPSEnable") {
        config.https = Some(proxy_address(
            Protocol::HTTP,
            required_string(settings, "HTTPSProxy")?,
            required_number(settings, "HTTPSPort")?,
        )?);
    }
    if enabled(settings, "SOCKSEnable") {
        config.socks5 = Some(proxy_address(
            Protocol::SOCKS5,
            required_string(settings, "SOCKSProxy")?,
            required_number(settings, "SOCKSPort")?,
        )?);
    }
    if enabled(settings, "ProxyAutoConfigEnable") {
        config.pac_uri = parse_uri(&required_string(settings, "ProxyAutoConfigURLString")?)?;
        if config.pac_uri.is_none() {
            return Err(BoxError::from_static_str(
                "enabled Apple proxy auto-configuration URL is empty",
            ));
        }
    }
    config.auto_detect = enabled(settings, "ProxyAutoDiscoveryEnable");
    config.exclude_simple_hostnames = enabled(settings, "ExcludeSimpleHostnames");
    // CFNetwork treats exception entries as flat wildcard patterns: a plain
    // domain is exact, while `*.example.com` and `.example.com` match only
    // descendants. Do not parse them using Rama's subtree shorthand because
    // that would incorrectly add the domain apex.
    config.try_set_bypass_with_dialect(
        string_array(settings, "ExceptionsList"),
        policy,
        BypassRuleDialect::FlatGlob,
    )?;
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

fn required_number(settings: &CFDictionary<CFString, CFType>, key: &str) -> Result<u16, BoxError> {
    number(settings, key).ok_or_else(|| {
        BoxError::from_static_str("enabled Apple proxy setting has no valid numeric value")
            .context_str_field("setting", key)
    })
}

fn required_string(
    settings: &CFDictionary<CFString, CFType>,
    key: &str,
) -> Result<String, BoxError> {
    string(settings, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            BoxError::from_static_str("enabled Apple proxy setting has no valid string value")
                .context_str_field("setting", key)
        })
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

#[cfg(test)]
mod tests {
    use crate::address::Host;

    use super::*;

    fn settings(entries: Vec<(&str, CFType)>) -> CFDictionary<CFString, CFType> {
        let entries = entries
            .into_iter()
            .map(|(key, value)| (CFString::new(key), value))
            .collect::<Vec<_>>();
        CFDictionary::from_CFType_pairs(&entries)
    }

    #[test]
    fn http_and_https_proxy_settings_are_independent() {
        let http_only = settings(vec![
            ("HTTPEnable", CFNumber::from(1_i32).as_CFType()),
            ("HTTPProxy", CFString::new("proxy.example").as_CFType()),
            ("HTTPPort", CFNumber::from(8080_i32).as_CFType()),
            ("HTTPSEnable", CFNumber::from(0_i32).as_CFType()),
        ]);
        let config =
            parse_settings(&http_only, SystemProxyInvalidBypassRulePolicy::Ignore).unwrap();
        assert_eq!(
            config.http.unwrap().to_string(),
            "http://proxy.example:8080"
        );
        assert!(config.https.is_none());

        let both = settings(vec![
            ("HTTPEnable", CFNumber::from(1_i32).as_CFType()),
            ("HTTPProxy", CFString::new("proxy.example").as_CFType()),
            ("HTTPPort", CFNumber::from(8080_i32).as_CFType()),
            ("HTTPSEnable", CFNumber::from(1_i32).as_CFType()),
            (
                "HTTPSProxy",
                CFString::new("secure-proxy.example").as_CFType(),
            ),
            ("HTTPSPort", CFNumber::from(8443_i32).as_CFType()),
        ]);
        let config = parse_settings(&both, SystemProxyInvalidBypassRulePolicy::Ignore).unwrap();
        assert_eq!(
            config.https.unwrap().to_string(),
            "http://secure-proxy.example:8443"
        );
    }

    #[test]
    fn exception_list_uses_cfnetwork_flat_wildcard_semantics() {
        for (pattern, apex_matches, descendant_matches) in [
            ("example.com", true, false),
            ("*.example.com", false, true),
            (".example.com", false, true),
        ] {
            let exceptions = CFArray::from_CFTypes(&[CFString::new(pattern)]);
            let settings = settings(vec![("ExceptionsList", exceptions.as_CFType())]);
            let config =
                parse_settings(&settings, SystemProxyInvalidBypassRulePolicy::Ignore).unwrap();
            let protocol = Protocol::HTTP;

            assert_eq!(
                config.bypasses(
                    Some(&protocol),
                    Host::try_from("example.com").unwrap().view(),
                    Some(80),
                ),
                apex_matches,
                "pattern={pattern:?} apex",
            );
            assert_eq!(
                config.bypasses(
                    Some(&protocol),
                    Host::try_from("api.example.com").unwrap().view(),
                    Some(80),
                ),
                descendant_matches,
                "pattern={pattern:?} descendant",
            );
        }
    }

    #[test]
    fn enabled_settings_require_complete_values_and_preserve_auto_discovery() {
        for entries in [
            vec![("HTTPEnable", CFNumber::from(1_i32).as_CFType())],
            vec![
                ("HTTPEnable", CFNumber::from(1_i32).as_CFType()),
                ("HTTPProxy", CFString::new("proxy.example").as_CFType()),
            ],
            vec![("ProxyAutoConfigEnable", CFNumber::from(1_i32).as_CFType())],
        ] {
            parse_settings(
                &settings(entries),
                SystemProxyInvalidBypassRulePolicy::Ignore,
            )
            .unwrap_err();
        }

        let config = parse_settings(
            &settings(vec![(
                "ProxyAutoDiscoveryEnable",
                CFNumber::from(1_i32).as_CFType(),
            )]),
            SystemProxyInvalidBypassRulePolicy::Ignore,
        )
        .unwrap();
        assert!(config.auto_detect());
        assert!(!config.is_empty());
    }
}
