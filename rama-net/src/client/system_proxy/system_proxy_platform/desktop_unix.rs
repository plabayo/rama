use std::{env, io, path::Path, process::Output, time::Duration};

use ahash::HashMap;
use rama_core::{Service, error::ErrorExt as _};
use tokio::{process::Command, time::timeout};

use super::*;

pub(super) async fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    if desktop_prefers_kde()
        && let Some(config) = read_kde(policy).await
    {
        return config;
    }
    if let Some(config) = read_gnome(policy).await? {
        return Ok(config);
    }
    read_kde(policy)
        .await
        .transpose()
        .map(Option::unwrap_or_default)
}

fn desktop_prefers_kde() -> bool {
    env::var("XDG_CURRENT_DESKTOP")
        .is_ok_and(|desktop| desktop.to_ascii_lowercase().contains("kde"))
        || env::var_os("KDE_FULL_SESSION").is_some()
}

const GSETTINGS_TIMEOUT: Duration = Duration::from_secs(5);

async fn gsettings(schema: &str, key: &str) -> Result<Option<String>, BoxError> {
    let mut command = Command::new("gsettings");
    command.args(["get", schema, key]);
    let output = match command_output_with_timeout(command, GSETTINGS_TIMEOUT).await {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("execute gsettings"),
    };
    Ok(output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned()))
}

async fn command_output_with_timeout(
    mut command: Command,
    duration: Duration,
) -> io::Result<Output> {
    command.kill_on_drop(true);
    match timeout(duration, command.output()).await {
        Ok(output) => output,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "gsettings command timed out",
        )),
    }
}

async fn read_gnome(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<Option<SystemProxyConfig>, BoxError> {
    read_gnome_with(policy, GSettings).await
}

#[derive(Debug, Clone, Copy)]
struct GSettings;

impl Service<(String, String)> for GSettings {
    type Output = Option<String>;
    type Error = BoxError;

    async fn serve(&self, (schema, key): (String, String)) -> Result<Self::Output, Self::Error> {
        gsettings(&schema, &key).await
    }
}

async fn read_gnome_with<S>(
    policy: SystemProxyInvalidBypassRulePolicy,
    settings: S,
) -> Result<Option<SystemProxyConfig>, BoxError>
where
    S: Service<(String, String), Output = Option<String>>,
    S::Error: Into<BoxError>,
{
    let Some(mode) = setting(&settings, "org.gnome.system.proxy", "mode").await? else {
        return Ok(None);
    };
    let mode = mode.trim_matches(['\'', '"']);
    match mode {
        "none" => Ok(Some(SystemProxyConfig::default())),
        "auto" => {
            let config = SystemProxyConfig {
                pac_uri: parse_uri(
                    &required_setting(&settings, "org.gnome.system.proxy", "autoconfig-url")
                        .await?,
                )?,
                ..SystemProxyConfig::default()
            };
            Ok(Some(config))
        }
        "manual" => {
            let mut config = SystemProxyConfig {
                http: gnome_endpoint(&settings, "http", Protocol::HTTP).await?,
                https: gnome_endpoint(&settings, "https", Protocol::HTTP).await?,
                socks5: gnome_endpoint(&settings, "socks", Protocol::SOCKS5).await?,
                ..SystemProxyConfig::default()
            };
            // GNOME's `use-same-proxy` setting is obsolete and explicitly
            // unused. GLib applies the HTTP proxy to HTTPS when no dedicated
            // HTTPS proxy is configured.
            if config.https.is_none() {
                config.https.clone_from(&config.http);
            }
            let ignore =
                required_setting(&settings, "org.gnome.system.proxy", "ignore-hosts").await?;
            config.try_set_bypass_with_dialect(
                parse_gvariant_string_list(&ignore),
                policy,
                BypassRuleDialect::Glib,
            )?;
            Ok(Some(config))
        }
        _ => Ok(None),
    }
}

async fn gnome_endpoint<S>(
    settings: &S,
    kind: &str,
    protocol: Protocol,
) -> Result<Option<ProxyAddress>, BoxError>
where
    S: Service<(String, String), Output = Option<String>>,
    S::Error: Into<BoxError>,
{
    let schema = format!("org.gnome.system.proxy.{kind}");
    let host = required_setting(settings, &schema, "host").await?;
    let host = host.trim_matches(['\'', '"']);
    if host.is_empty() {
        return Ok(None);
    }
    let port = required_setting(settings, &schema, "port")
        .await?
        .parse::<u16>()
        .context("parse GNOME system proxy port")?;
    if port == 0 {
        return Ok(None);
    }
    proxy_address(protocol, host, port).map(Some)
}

async fn setting<S>(settings: &S, schema: &str, key: &str) -> Result<Option<String>, BoxError>
where
    S: Service<(String, String), Output = Option<String>>,
    S::Error: Into<BoxError>,
{
    settings
        .serve((schema.to_owned(), key.to_owned()))
        .await
        .context("read GNOME proxy setting")
        .context_str_field("schema", schema)
        .context_str_field("key", key)
}

async fn required_setting<S>(settings: &S, schema: &str, key: &str) -> Result<String, BoxError>
where
    S: Service<(String, String), Output = Option<String>>,
    S::Error: Into<BoxError>,
{
    setting(settings, schema, key).await?.ok_or_else(|| {
        BoxError::from_static_str("GNOME proxy setting is unavailable")
            .context_str_field("schema", schema)
            .context_str_field("key", key)
    })
}

async fn read_kde(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Option<Result<SystemProxyConfig, BoxError>> {
    for path in kde_paths() {
        match tokio::fs::read_to_string(path).await {
            Ok(contents) => return Some(parse_kde_config(&contents, policy)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Some(Err(error).context("read KDE system proxy configuration")),
        }
    }
    None
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
        config.try_set_bypass(parse_delimited_string_list(value), policy)?;
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
    use std::convert::Infallible;

    use rama_core::service::service_fn;

    use super::*;

    fn test_settings(
        values: HashMap<(&'static str, &'static str), &'static str>,
    ) -> impl Service<(String, String), Output = Option<String>, Error = Infallible> {
        service_fn(move |(schema, key): (String, String)| {
            let value = values
                .iter()
                .find(|((candidate_schema, candidate_key), _)| {
                    schema == *candidate_schema && key == *candidate_key
                })
                .map(|(_, value)| (*value).to_owned());
            async move { Ok::<_, Infallible>(value) }
        })
    }

    #[tokio::test]
    async fn gnome_manual_proxy_and_exceptions() {
        let values = HashMap::from_iter([
            (("org.gnome.system.proxy", "mode"), "'manual'"),
            (
                ("org.gnome.system.proxy", "ignore-hosts"),
                "['localhost', '.example.test']",
            ),
            (("org.gnome.system.proxy.http", "host"), "'proxy.example'"),
            (("org.gnome.system.proxy.http", "port"), "8080"),
            (("org.gnome.system.proxy.https", "host"), "'secure.example'"),
            (("org.gnome.system.proxy.https", "port"), "8443"),
            (("org.gnome.system.proxy.socks", "host"), "'socks.example'"),
            (("org.gnome.system.proxy.socks", "port"), "1080"),
        ]);
        let config = read_gnome_with(
            SystemProxyInvalidBypassRulePolicy::Ignore,
            test_settings(values),
        )
        .await
        .unwrap()
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
    }

    #[tokio::test]
    async fn gnome_http_proxy_covers_https_and_auto_mode_loads_pac() {
        let manual = HashMap::from_iter([
            (("org.gnome.system.proxy", "mode"), "'manual'"),
            // This obsolete value must not prevent GLib's HTTP-to-HTTPS
            // fallback.
            (("org.gnome.system.proxy", "use-same-proxy"), "false"),
            (("org.gnome.system.proxy.http", "host"), "'proxy.example'"),
            (("org.gnome.system.proxy.http", "port"), "8080"),
            (("org.gnome.system.proxy.https", "host"), "''"),
            (("org.gnome.system.proxy.socks", "host"), "''"),
            (("org.gnome.system.proxy", "ignore-hosts"), "[]"),
        ]);
        let config = read_gnome_with(
            SystemProxyInvalidBypassRulePolicy::Ignore,
            test_settings(manual),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(config.https, config.http);

        let auto = HashMap::from_iter([
            (("org.gnome.system.proxy", "mode"), "'auto'"),
            (
                ("org.gnome.system.proxy", "autoconfig-url"),
                "https://config.example/proxy.pac",
            ),
        ]);
        let config = read_gnome_with(
            SystemProxyInvalidBypassRulePolicy::Ignore,
            test_settings(auto),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            config.pac_uri.unwrap().to_string(),
            "https://config.example/proxy.pac"
        );
    }

    #[tokio::test]
    async fn gnome_zero_port_disables_the_endpoint() {
        let values = HashMap::from_iter([
            (("org.gnome.system.proxy", "mode"), "'manual'"),
            (("org.gnome.system.proxy", "use-same-proxy"), "false"),
            (("org.gnome.system.proxy", "ignore-hosts"), "[]"),
            (("org.gnome.system.proxy.http", "host"), "'proxy.example'"),
            (("org.gnome.system.proxy.http", "port"), "0"),
            (("org.gnome.system.proxy.https", "host"), "''"),
            (("org.gnome.system.proxy.socks", "host"), "''"),
        ]);

        let config = read_gnome_with(
            SystemProxyInvalidBypassRulePolicy::Ignore,
            test_settings(values),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(config.http.is_none());
    }

    #[tokio::test]
    async fn gnome_incomplete_manual_settings_are_rejected() {
        let values = HashMap::from_iter([
            (("org.gnome.system.proxy", "mode"), "'manual'"),
            (("org.gnome.system.proxy.http", "host"), "'proxy.example'"),
        ]);

        read_gnome_with(
            SystemProxyInvalidBypassRulePolicy::Ignore,
            test_settings(values),
        )
        .await
        .unwrap_err();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_output_timeout_terminates_the_child() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 1"]);

        let error = command_output_with_timeout(command, Duration::from_millis(10))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

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
            parse_gvariant_string_list("['localhost', '*.example.test']"),
            ["localhost", "*.example.test"]
        );
        assert_eq!(
            parse_delimited_string_list("*.local <local> 10.0.0.0/8"),
            ["*.local", "<local>", "10.0.0.0/8"]
        );
        assert!(parse_gvariant_string_list("@as []").is_empty());
        assert_eq!(
            parse_gvariant_string_list("['[::1]', '[2001:db8::5]:443']"),
            ["[::1]", "[2001:db8::5]:443"]
        );
        assert_eq!(
            parse_delimited_string_list("[::1];[2001:db8::5]"),
            ["[::1]", "[2001:db8::5]"]
        );
        assert!(parse_gvariant_bool(Some("true")));
        assert!(!parse_gvariant_bool(Some("false")));
    }
}
