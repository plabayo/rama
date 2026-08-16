use std::str::FromStr;

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use std::path::Path;

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
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use crate::address::ProxyAddress;
use crate::{Protocol, uri::Uri};

use super::SystemProxyConfig;
#[cfg(any(
    target_vendor = "apple",
    target_os = "android",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use super::proxy_address;

pub(super) fn read() -> Result<SystemProxyConfig, BoxError> {
    #[cfg(target_os = "android")]
    return android::read();

    #[cfg(all(target_vendor = "apple", not(target_os = "android")))]
    return apple::read();

    #[cfg(target_os = "windows")]
    return windows::read();

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    return desktop_unix::read();

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
    if value.starts_with("socks://") {
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
fn parse_string_list(value: &str) -> Vec<String> {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(|character: char| matches!(character, ',' | ';') || character.is_whitespace())
        .map(|value| value.trim().trim_matches(['\'', '"']))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(target_os = "windows")]
mod windows {
    use std::io;

    use windows_sys::Win32::{
        Foundation::GlobalFree,
        Networking::WinHttp::{
            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WinHttpGetIEProxyConfigForCurrentUser,
        },
    };

    use super::*;

    pub(super) fn read() -> Result<SystemProxyConfig, BoxError> {
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
            .map(parse_windows_proxy)
            .transpose()?
            .unwrap_or_default();
        config.pac_uri = pac.as_deref().map(parse_uri).transpose()?.flatten();
        if let Some(bypass) = bypass {
            config.set_bypass(parse_string_list(&bypass));
        }
        Ok(config)
    }

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
        let value =
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) });
        unsafe { GlobalFree(pointer.cast()) };
        Some(value)
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_proxy(value: &str) -> Result<SystemProxyConfig, BoxError> {
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

#[cfg(target_vendor = "apple")]
mod apple {
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
}

#[cfg(target_os = "android")]
mod android {
    use jni::{
        jni_sig, jni_str,
        objects::{JObject, JObjectArray, JString, JValue},
    };

    use super::*;

    pub(super) fn read() -> Result<SystemProxyConfig, BoxError> {
        let context = std::panic::catch_unwind(ndk_context::android_context).map_err(|panic| {
            drop(panic);
            BoxError::from_static_str("Android context is not initialized")
        })?;
        let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) };
        vm.attach_current_thread(|env| -> Result<SystemProxyConfig, BoxError> {
            let context = unsafe { JObject::from_raw(env, context.context().cast()) };
            let sdk_int = env
                .get_static_field(
                    jni_str!("android/os/Build$VERSION"),
                    jni_str!("SDK_INT"),
                    jni_sig!("I"),
                )?
                .i()?;
            if sdk_int < 23 {
                let host = env
                    .call_static_method(
                        jni_str!("android/net/Proxy"),
                        jni_str!("getHost"),
                        jni_sig!("(Landroid/content/Context;)Ljava/lang/String;"),
                        &[JValue::Object(&context)],
                    )?
                    .l()?;
                let port = env
                    .call_static_method(
                        jni_str!("android/net/Proxy"),
                        jni_str!("getPort"),
                        jni_sig!("(Landroid/content/Context;)I"),
                        &[JValue::Object(&context)],
                    )?
                    .i()?;
                let mut config = SystemProxyConfig::default();
                if !host.is_null()
                    && let Ok(port) = u16::try_from(port)
                {
                    let host = env.cast_local::<JString<'_>>(host)?.try_to_string(env)?;
                    let proxy = proxy_address(Protocol::HTTP, host, port)?;
                    config.http = Some(proxy.clone());
                    config.https = Some(proxy);
                }
                return Ok(config);
            }

            let service_name = env.new_string("connectivity")?;
            let manager = env
                .call_method(
                    &context,
                    jni_str!("getSystemService"),
                    jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                    &[JValue::Object(&service_name)],
                )?
                .l()?;
            let info = env
                .call_method(
                    manager,
                    jni_str!("getDefaultProxy"),
                    jni_sig!("()Landroid/net/ProxyInfo;"),
                    &[],
                )?
                .l()?;
            if info.is_null() {
                return Ok(SystemProxyConfig::default());
            }

            let mut config = SystemProxyConfig::default();
            let pac_file = env
                .call_method(
                    &info,
                    jni_str!("getPacFileUrl"),
                    jni_sig!("()Landroid/net/Uri;"),
                    &[],
                )?
                .l()?;
            if !pac_file.is_null() {
                let text = env
                    .call_method(
                        pac_file,
                        jni_str!("toString"),
                        jni_sig!("()Ljava/lang/String;"),
                        &[],
                    )?
                    .l()?;
                let text = env.cast_local::<JString<'_>>(text)?.try_to_string(env)?;
                config.pac_uri = parse_uri(&text)?;
            }

            if config.pac_uri.is_none() {
                let host = env
                    .call_method(
                        &info,
                        jni_str!("getHost"),
                        jni_sig!("()Ljava/lang/String;"),
                        &[],
                    )?
                    .l()?;
                let port = env
                    .call_method(&info, jni_str!("getPort"), jni_sig!("()I"), &[])?
                    .i()?;
                if !host.is_null()
                    && let Ok(port) = u16::try_from(port)
                {
                    let host = env.cast_local::<JString<'_>>(host)?.try_to_string(env)?;
                    let proxy = proxy_address(Protocol::HTTP, host, port)?;
                    config.http = Some(proxy.clone());
                    config.https = Some(proxy);
                }
            }

            let exclusions = env
                .call_method(
                    &info,
                    jni_str!("getExclusionList"),
                    jni_sig!("()[Ljava/lang/String;"),
                    &[],
                )?
                .l()?;
            if !exclusions.is_null() {
                let exclusions = env.cast_local::<JObjectArray<'_, JString<'_>>>(exclusions)?;
                let length = exclusions.len(env)?;
                let mut values = Vec::with_capacity(length);
                for index in 0..length {
                    values.push(exclusions.get_element(env, index)?.try_to_string(env)?);
                }
                config.set_bypass(values);
            }
            Ok(config)
        })
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod desktop_unix {
    use std::{env, fs, process::Command};

    use super::*;

    pub(super) fn read() -> Result<SystemProxyConfig, BoxError> {
        if desktop_prefers_kde()
            && let Some(config) = read_kde()
        {
            return config;
        }
        if let Some(config) = read_gnome()? {
            return Ok(config);
        }
        read_kde().transpose().map(Option::unwrap_or_default)
    }

    fn desktop_prefers_kde() -> bool {
        env::var("XDG_CURRENT_DESKTOP")
            .is_ok_and(|desktop| desktop.to_ascii_lowercase().contains("kde"))
            || env::var_os("KDE_FULL_SESSION").is_some()
    }

    fn gsettings(schema: &str, key: &str) -> Option<String> {
        let output = Command::new("gsettings")
            .args(["get", schema, key])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn read_gnome() -> Result<Option<SystemProxyConfig>, BoxError> {
        let Some(mode) = gsettings("org.gnome.system.proxy", "mode") else {
            return Ok(None);
        };
        let mode = mode.trim_matches(['\'', '"']);
        match mode {
            "none" => Ok(Some(SystemProxyConfig::default())),
            "auto" => {
                let mut config = SystemProxyConfig::default();
                config.pac_uri = gsettings("org.gnome.system.proxy", "autoconfig-url")
                    .as_deref()
                    .map(parse_uri)
                    .transpose()?
                    .flatten();
                Ok(Some(config))
            }
            "manual" => {
                let mut config = SystemProxyConfig::default();
                config.http = gnome_endpoint("http", Protocol::HTTP)?;
                config.https = gnome_endpoint("https", Protocol::HTTP)?;
                config.socks5 = gnome_endpoint("socks", Protocol::SOCKS5)?;
                if config.https.is_none()
                    && parse_gvariant_bool(
                        gsettings("org.gnome.system.proxy", "use-same-proxy").as_deref(),
                    )
                {
                    config.https.clone_from(&config.http);
                }
                if let Some(ignore) = gsettings("org.gnome.system.proxy", "ignore-hosts") {
                    config.set_bypass(parse_string_list(&ignore));
                }
                Ok(Some(config))
            }
            _ => Ok(None),
        }
    }

    fn gnome_endpoint(kind: &str, protocol: Protocol) -> Result<Option<ProxyAddress>, BoxError> {
        let schema = format!("org.gnome.system.proxy.{kind}");
        let Some(host) = gsettings(&schema, "host") else {
            return Ok(None);
        };
        let host = host.trim_matches(['\'', '"']);
        if host.is_empty() {
            return Ok(None);
        }
        let Some(port) = gsettings(&schema, "port").and_then(|port| port.parse::<u16>().ok())
        else {
            return Ok(None);
        };
        proxy_address(protocol, host, port).map(Some)
    }

    fn read_kde() -> Option<Result<SystemProxyConfig, BoxError>> {
        kde_paths().find_map(|path| {
            fs::read_to_string(path)
                .ok()
                .map(|contents| parse_kde_config(&contents))
        })
    }

    fn kde_paths() -> impl Iterator<Item = std::path::PathBuf> {
        let mut paths = Vec::new();
        if let Some(dir) = env::var_os("XDG_CONFIG_HOME") {
            paths.push(Path::new(&dir).join("kioslaverc"));
        }
        if let Some(home) = env::var_os("HOME") {
            let home = Path::new(&home);
            paths.push(home.join(".config/kioslaverc"));
            paths.push(home.join(".kde/share/config/kioslaverc"));
            paths.push(home.join(".kde4/share/config/kioslaverc"));
        }
        paths.into_iter()
    }
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn parse_gvariant_bool(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn parse_kde_config(contents: &str) -> Result<SystemProxyConfig, BoxError> {
    let mut in_proxy_settings = false;
    let mut entries = ahash::HashMap::default();
    for line in contents.lines().map(str::trim) {
        if let Some(section) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            in_proxy_settings = section.starts_with("Proxy Settings");
        } else if in_proxy_settings
            && !line.starts_with('#')
            && let Some((key, value)) = line.split_once('=')
        {
            entries.insert(key.trim(), value.trim());
        }
    }

    let proxy_type = entries
        .get("ProxyType")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let mut config = SystemProxyConfig::default();
    match proxy_type {
        1 => {
            config.http = kde_endpoint(entries.get("httpProxy").copied(), Protocol::HTTP)?;
            config.https = kde_endpoint(entries.get("httpsProxy").copied(), Protocol::HTTP)?;
            config.socks5 = kde_endpoint(entries.get("socksProxy").copied(), Protocol::SOCKS5)?;
        }
        2 => {
            if let Some(value) = entries.get("Proxy Config Script") {
                config.pac_uri = parse_kde_pac_uri(value)?;
            }
        }
        // ProxyType 3 is WPAD without a concrete PAC URI. Type 4 delegates to
        // environment variables, which Rama's separate HTTP env layer owns.
        _ => {}
    }
    if let Some(value) = entries.get("NoProxyFor") {
        config.set_bypass(parse_string_list(value));
    }
    config.reversed_bypass = entries
        .get("ReversedException")
        .is_some_and(|value| parse_gvariant_bool(Some(value)));
    Ok(config)
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn kde_endpoint(
    value: Option<&str>,
    default_protocol: Protocol,
) -> Result<Option<ProxyAddress>, BoxError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let mut value = value.to_owned();
    if let Some((host, port)) = value.rsplit_once(' ')
        && port.parse::<u16>().is_ok()
    {
        value = format!("{}:{}", host.trim_end_matches('/'), port);
    }
    parse_proxy_endpoint(&value, default_protocol).map(Some)
}

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn parse_kde_pac_uri(value: &str) -> Result<Option<Uri>, BoxError> {
    let value = value.trim().trim_matches(['\'', '"']);
    if value.is_empty() {
        return Ok(None);
    }
    if Path::new(value).is_absolute() {
        parse_uri(&format!("file://{value}"))
    } else {
        parse_uri(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_protocol_mapping_and_bare_proxy() {
        let config =
            parse_windows_proxy("http=web:8080;https=secure:8443;socks=socks:1080").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://secure:8443");
        assert_eq!(config.socks5.unwrap().to_string(), "socks5://socks:1080");

        let config = parse_windows_proxy("proxy.example:3128").unwrap();
        assert_eq!(config.http, config.https);

        let config =
            parse_windows_proxy("http=web:8080 https=secure:8443 socks=socks:1080").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://secure:8443");
        assert_eq!(config.socks5.unwrap().to_string(), "socks5://socks:1080");

        let config = parse_windows_proxy("http=web:8080 default:3128").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://default:3128");
        assert!(parse_windows_proxy("").unwrap().is_empty());

        parse_proxy_endpoint("", Protocol::HTTP).unwrap_err();
        assert_eq!(
            parse_proxy_endpoint("socks://localhost:1080", Protocol::HTTP)
                .unwrap()
                .protocol,
            Some(Protocol::SOCKS5)
        );
    }

    #[test]
    fn kde_manual_proxy_and_exceptions() {
        let config = parse_kde_config(
            "[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy.example 8080\nhttpsProxy=secure.example:8443\nsocksProxy=socks://socks.example 1080\nNoProxyFor=localhost,.example.test\nReversedException=true\n",
        )
        .unwrap();
        assert_eq!(
            config.http.unwrap().to_string(),
            "http://proxy.example:8080"
        );
        assert_eq!(
            config.https.unwrap().to_string(),
            "http://secure.example:8443"
        );
        assert_eq!(
            config.socks5.unwrap().to_string(),
            "socks5://socks.example:1080"
        );
        assert_eq!(config.bypass.as_ref(), ["localhost", ".example.test"]);
        assert!(config.reversed_bypass);
    }

    #[test]
    fn kde_pac_url_and_environment_mode() {
        let config = parse_kde_config(
            "[Proxy Settings][$i]\nProxyType=2\nProxy Config Script=https://config.test/proxy.pac\n",
        )
        .unwrap();
        assert_eq!(
            config.pac_uri.unwrap().to_string(),
            "https://config.test/proxy.pac"
        );

        let config =
            parse_kde_config("[Proxy Settings]\nProxyType=4\nhttpProxy=ignored:80\n").unwrap();
        assert!(config.is_empty());

        assert_eq!(
            parse_kde_pac_uri("/etc/proxy.pac")
                .unwrap()
                .unwrap()
                .to_string(),
            "file:///etc/proxy.pac"
        );
    }

    #[test]
    fn gvariant_lists_and_boolean_are_parsed() {
        assert_eq!(
            parse_string_list("['localhost', '*.example.test']"),
            ["localhost", "*.example.test"]
        );
        assert_eq!(
            parse_string_list("*.local <local> 10.0.0.0/8"),
            ["*.local", "<local>", "10.0.0.0/8"]
        );
        assert!(parse_gvariant_bool(Some("true")));
        assert!(!parse_gvariant_bool(Some("false")));
    }
}
