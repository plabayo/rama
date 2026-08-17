use std::{env, fs, path::Path, process::Command};

use ahash::HashMap;

use super::*;

pub(super) fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    if desktop_prefers_kde()
        && let Some(config) = read_kde(policy)
    {
        return config;
    }
    if let Some(config) = read_gnome(policy)? {
        return Ok(config);
    }
    read_kde(policy).transpose().map(Option::unwrap_or_default)
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

fn read_gnome(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<Option<SystemProxyConfig>, BoxError> {
    let Some(mode) = gsettings("org.gnome.system.proxy", "mode") else {
        return Ok(None);
    };
    let mode = mode.trim_matches(['\'', '"']);
    match mode {
        "none" => Ok(Some(SystemProxyConfig::default())),
        "auto" => {
            let config = SystemProxyConfig {
                pac_uri: gsettings("org.gnome.system.proxy", "autoconfig-url")
                    .as_deref()
                    .map(parse_uri)
                    .transpose()?
                    .flatten(),
                ..SystemProxyConfig::default()
            };
            Ok(Some(config))
        }
        "manual" => {
            let mut config = SystemProxyConfig {
                http: gnome_endpoint("http", Protocol::HTTP)?,
                https: gnome_endpoint("https", Protocol::HTTP)?,
                socks5: gnome_endpoint("socks", Protocol::SOCKS5)?,
                ..SystemProxyConfig::default()
            };
            if config.https.is_none()
                && parse_gvariant_bool(
                    gsettings("org.gnome.system.proxy", "use-same-proxy").as_deref(),
                )
            {
                config.https.clone_from(&config.http);
            }
            if let Some(ignore) = gsettings("org.gnome.system.proxy", "ignore-hosts") {
                config.try_set_bypass(parse_string_list(&ignore), policy)?;
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
    let Some(port) = gsettings(&schema, "port").and_then(|port| port.parse::<u16>().ok()) else {
        return Ok(None);
    };
    proxy_address(protocol, host, port).map(Some)
}

fn read_kde(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Option<Result<SystemProxyConfig, BoxError>> {
    kde_paths().find_map(|path| {
        fs::read_to_string(path)
            .ok()
            .map(|contents| parse_kde_config(&contents, policy))
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

fn parse_gvariant_bool(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

fn parse_kde_config(
    contents: &str,
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let mut in_proxy_settings = false;
    let mut entries = HashMap::default();
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
        config.try_set_bypass(parse_string_list(value), policy)?;
    }
    config.reversed_bypass = entries
        .get("ReversedException")
        .is_some_and(|value| parse_gvariant_bool(Some(value)));
    Ok(config)
}

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
    fn kde_manual_proxy_and_exceptions() {
        let config = parse_kde_config(
            "[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy.example 8080\nhttpsProxy=secure.example:8443\nsocksProxy=socks://socks.example 1080\nNoProxyFor=localhost,.example.test\nReversedException=true\n",
            SystemProxyInvalidBypassRulePolicy::Ignore,
        )
        .unwrap();
        assert_eq!(
            config.http.as_ref().unwrap().to_string(),
            "http://proxy.example:8080"
        );
        assert_eq!(
            config.https.as_ref().unwrap().to_string(),
            "http://secure.example:8443"
        );
        assert_eq!(
            config.socks5.as_ref().unwrap().to_string(),
            "socks5://socks.example:1080"
        );
        assert_eq!(
            config.bypass().collect::<Vec<_>>(),
            ["localhost", ".example.test"]
        );
        assert!(config.reversed_bypass);
    }

    #[test]
    fn kde_pac_url_and_environment_mode() {
        let config = parse_kde_config(
            "[Proxy Settings]\nProxyType=2\nProxy Config Script=/tmp/proxy.pac\n",
            SystemProxyInvalidBypassRulePolicy::Ignore,
        )
        .unwrap();
        assert_eq!(config.pac_uri.unwrap().to_string(), "file:///tmp/proxy.pac");

        let config = parse_kde_config(
            "[Proxy Settings]\nProxyType=4\nhttpProxy=ignored.example:8080\n",
            SystemProxyInvalidBypassRulePolicy::Ignore,
        )
        .unwrap();
        assert!(config.is_empty());
    }

    #[test]
    fn invalid_kde_bypass_policy_is_independent_of_reversal() {
        for reversed in ["false", "true"] {
            let contents = format!(
                "[Proxy Settings]\nProxyType=1\nhttpProxy=proxy.example 8080\nNoProxyFor=valid.example,bad/rule\nReversedException={reversed}\n"
            );

            let config =
                parse_kde_config(&contents, SystemProxyInvalidBypassRulePolicy::Ignore).unwrap();
            assert_eq!(config.bypass().collect::<Vec<_>>(), ["valid.example"]);
            assert_eq!(config.reversed_bypass(), reversed == "true");

            parse_kde_config(&contents, SystemProxyInvalidBypassRulePolicy::Reject).unwrap_err();
        }
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
        assert!(parse_string_list("@as []").is_empty());
        assert!(parse_gvariant_bool(Some("true")));
        assert!(!parse_gvariant_bool(Some("false")));
    }
}
