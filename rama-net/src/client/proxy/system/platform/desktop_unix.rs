use std::{
    env,
    ffi::{OsStr, OsString},
    future::Future,
    io,
    path::{Path, PathBuf},
    process::Output,
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    mem::size_of,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt as _,
    },
};

use ahash::HashMap;
use rama_core::{Service, error::ErrorExt as _};
use rama_utils::str::trim_ascii_quotes_non_empty;
use tokio::{process::Command, time::timeout};

use crate::user::{Basic, ProxyCredential};

use super::*;

#[cfg(target_os = "linux")]
pub(super) fn config_change_monitor() -> Result<Option<ConfigChangeMonitor>, BoxError> {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd == -1 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut filters = HashMap::default();
    for (directory, filter) in config_watch_directories() {
        let Ok(directory) = CString::new(directory.as_os_str().as_bytes()) else {
            continue;
        };
        let result = unsafe {
            libc::inotify_add_watch(
                fd.as_raw_fd(),
                directory.as_ptr(),
                libc::IN_ATTRIB
                    | libc::IN_CLOSE_WRITE
                    | libc::IN_CREATE
                    | libc::IN_DELETE
                    | libc::IN_DELETE_SELF
                    | libc::IN_MOVED_FROM
                    | libc::IN_MOVED_TO
                    | libc::IN_MOVE_SELF,
            )
        };
        if result != -1 {
            filters.insert(result, filter);
        }
    }
    if filters.is_empty() {
        return Ok(None);
    }

    let (monitor, changed, lifetime) = ConfigChangeMonitor::channel();
    std::thread::Builder::new()
        .name("rama-system-proxy-watch".to_owned())
        .spawn(move || {
            let mut events = [0_u8; 4096];
            while lifetime.upgrade().is_some() {
                let mut descriptor = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&raw mut descriptor, 1, 1_000) };
                if ready <= 0 || descriptor.revents & libc::POLLIN == 0 {
                    continue;
                }
                let length =
                    unsafe { libc::read(fd.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
                if length > 0 && inotify_events_changed(&events[..length as usize], &filters) {
                    changed.store(true, std::sync::atomic::Ordering::Release);
                }
            }
        })
        .context("spawn Linux system proxy configuration watcher")?;
    Ok(Some(monitor))
}

#[cfg(target_os = "linux")]
fn config_watch_directories() -> Vec<(PathBuf, Option<OsString>)> {
    let mut directories = kde_paths()
        .into_iter()
        .filter_map(|path| {
            let directory = path.parent()?.to_owned();
            let file_name = path.file_name()?.to_owned();
            Some((directory, Some(file_name)))
        })
        .collect::<Vec<_>>();
    let config_home = env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|path| path.join(".config"))
        });
    if let Some(config_home) = config_home {
        directories.push((config_home.join("dconf"), None));
    }
    directories.push((PathBuf::from("/etc/dconf/db"), None));
    directories.retain(|(path, _)| path.is_dir());
    directories.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    directories.dedup();
    directories
}

#[cfg(target_os = "linux")]
fn inotify_events_changed(events: &[u8], filters: &HashMap<i32, Option<OsString>>) -> bool {
    let event_size = size_of::<libc::inotify_event>();
    let mut offset = 0;
    while offset + event_size <= events.len() {
        let event = unsafe {
            events
                .as_ptr()
                .add(offset)
                .cast::<libc::inotify_event>()
                .read_unaligned()
        };
        if event.mask & (libc::IN_Q_OVERFLOW | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
            return true;
        }
        let name_length = event.len as usize;
        let next = offset
            .saturating_add(event_size)
            .saturating_add(name_length);
        if next > events.len() {
            break;
        }
        if let Some(filter) = filters.get(&event.wd) {
            match filter {
                None => return true,
                Some(expected) if name_length > 0 => {
                    let name = &events[offset + event_size..next];
                    let name = &name[..name
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(name.len())];
                    if OsStr::from_bytes(name) == expected {
                        return true;
                    }
                }
                Some(_) => {}
            }
        }
        offset = next;
    }
    false
}

pub(super) async fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    if desktop_prefers_kde()
        && let Some(config) = read_kde(policy).await
    {
        return config;
    }
    match read_gnome(policy).await {
        Ok(Some(config)) => return Ok(config),
        Ok(None) => {}
        Err(error) if error_is_timeout(error.as_ref()) => {
            if let Some(config) = read_kde(policy).await {
                return config;
            }
            return Err(error);
        }
        Err(error) => return Err(error),
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
const GNOME_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const KDE_CONFIG_READ_TIMEOUT: Duration = Duration::from_secs(5);

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
    read_gnome_with_timeout(policy, GSettings, GNOME_DISCOVERY_TIMEOUT).await
}

async fn read_gnome_with_timeout<S>(
    policy: SystemProxyInvalidBypassRulePolicy,
    settings: S,
    duration: Duration,
) -> Result<Option<SystemProxyConfig>, BoxError>
where
    S: Service<(String, String), Output = Option<String>>,
    S::Error: Into<BoxError>,
{
    timeout(duration, read_gnome_with(policy, settings))
        .await
        .map_err(|_elapsed| {
            io::Error::new(io::ErrorKind::TimedOut, "GNOME proxy discovery timed out")
        })?
}

fn error_is_timeout(mut error: &(dyn core::error::Error + 'static)) -> bool {
    loop {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
        {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
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
    let Some(mode) = trim_ascii_quotes_non_empty(&mode) else {
        return Ok(None);
    };
    match mode {
        "none" => Ok(Some(SystemProxyConfig::default())),
        "auto" => {
            let mut config = SystemProxyConfig {
                pac_uri: parse_uri(
                    &required_setting(&settings, "org.gnome.system.proxy", "autoconfig-url")
                        .await?,
                )?,
                bypass_before_pac: true,
                ..SystemProxyConfig::default()
            };
            set_gnome_bypass(&mut config, &settings, policy).await?;
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
            set_gnome_bypass(&mut config, &settings, policy).await?;
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
    let Some(host) = trim_ascii_quotes_non_empty(&host) else {
        return Ok(None);
    };
    let port = required_setting(settings, &schema, "port")
        .await?
        .parse::<u16>()
        .context("parse GNOME system proxy port")?;
    if port == 0 {
        return Ok(None);
    }
    let mut proxy = proxy_address(protocol, host, port)?;
    if kind == "http"
        && parse_gvariant_bool(
            setting(settings, &schema, "use-authentication")
                .await?
                .as_deref(),
        )
    {
        let username = required_setting(settings, &schema, "authentication-user").await?;
        let password = required_setting(settings, &schema, "authentication-password").await?;
        let username = username.trim_matches(['\'', '"']);
        let password = password.trim_matches(['\'', '"']);
        let basic = format!("{username}:{password}");
        proxy.credential = Some(ProxyCredential::Basic(
            Basic::try_from(basic.as_str()).context("parse GNOME HTTP proxy credentials")?,
        ));
    }
    Ok(Some(proxy))
}

async fn set_gnome_bypass<S>(
    config: &mut SystemProxyConfig,
    settings: &S,
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<(), BoxError>
where
    S: Service<(String, String), Output = Option<String>>,
    S::Error: Into<BoxError>,
{
    let ignore = required_setting(settings, "org.gnome.system.proxy", "ignore-hosts").await?;
    config.try_set_bypass_with_dialect(
        parse_gvariant_string_list(&ignore),
        policy,
        BypassRuleDialect::Glib,
    )
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
    let mut entries = HashMap::default();
    let mut found = false;
    for path in kde_paths() {
        match read_to_string_with_timeout(&path, KDE_CONFIG_READ_TIMEOUT).await {
            Ok(contents) => {
                found = true;
                merge_kde_entries(&contents, &mut entries);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Some(Err(error).context("read KDE system proxy configuration")),
        }
    }
    found.then(|| config_from_kde_entries(&entries, policy))
}

async fn read_to_string_with_timeout(path: &Path, duration: Duration) -> io::Result<String> {
    string_future_with_timeout(tokio::fs::read_to_string(path), duration).await
}

async fn string_future_with_timeout<F>(future: F, duration: Duration) -> io::Result<String>
where
    F: Future<Output = io::Result<String>>,
{
    timeout(duration, future).await.map_err(|_elapsed| {
        io::Error::new(io::ErrorKind::TimedOut, "KDE proxy config read timed out")
    })?
}

/// Return KConfig locations from lowest to highest precedence so merging can
/// apply later keys over earlier defaults while respecting immutable entries.
fn kde_paths() -> Vec<PathBuf> {
    kde_paths_from(
        env::var_os("XDG_CONFIG_DIRS"),
        env::var_os("XDG_CONFIG_HOME"),
        env::var_os("HOME"),
    )
}

fn kde_paths_from(
    system_dirs: Option<OsString>,
    config_home: Option<OsString>,
    home: Option<OsString>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let system_dirs = system_dirs
        .filter(|value| !value.is_empty())
        .map(|value| split_unix_paths(&value))
        .unwrap_or_else(|| vec![PathBuf::from("/etc/xdg")]);
    for dir in system_dirs
        .into_iter()
        .rev()
        .filter(|path| is_unix_absolute(path))
    {
        paths.push(join_unix_path(&dir, "kioslaverc"));
    }

    let explicit_config_home = config_home
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| is_unix_absolute(path));
    if explicit_config_home.is_none()
        && let Some(home) = home.as_ref()
    {
        let home = Path::new(home);
        paths.push(join_unix_path(home, ".kde/share/config/kioslaverc"));
        paths.push(join_unix_path(home, ".kde4/share/config/kioslaverc"));
    }
    if let Some(config_home) = explicit_config_home {
        paths.push(join_unix_path(&config_home, "kioslaverc"));
    } else if let Some(home) = home {
        paths.push(join_unix_path(Path::new(&home), ".config/kioslaverc"));
    }
    paths
}

#[cfg(target_family = "unix")]
fn split_unix_paths(value: &OsStr) -> Vec<PathBuf> {
    env::split_paths(value).collect()
}

#[cfg(all(test, not(target_family = "unix")))]
fn split_unix_paths(value: &OsStr) -> Vec<PathBuf> {
    // This module is compiled on non-Unix targets only for parser tests, whose
    // synthetic XDG path lists are UTF-8.
    value
        .to_string_lossy()
        .split(':')
        .map(PathBuf::from)
        .collect()
}

fn is_unix_absolute(path: &Path) -> bool {
    path.as_os_str().as_encoded_bytes().starts_with(b"/")
}

fn join_unix_path(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    if !path.is_empty() && !path.as_encoded_bytes().ends_with(b"/") {
        path.push("/");
    }
    path.push(suffix);
    path.into()
}

fn parse_gvariant_bool(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

#[cfg(test)]
fn parse_kde_config(
    contents: &str,
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let mut entries = HashMap::default();
    merge_kde_entries(contents, &mut entries);
    config_from_kde_entries(&entries, policy)
}

#[derive(Debug, Clone)]
struct KdeEntry {
    value: String,
    immutable: bool,
}

fn merge_kde_entries(contents: &str, entries: &mut HashMap<String, KdeEntry>) {
    let mut in_proxy_settings = false;
    let mut group_immutable = false;
    for line in contents.lines().map(str::trim) {
        if line.starts_with('[') {
            in_proxy_settings =
                line.starts_with("[Proxy Settings]") || line.starts_with("[Proxy Settings][");
            group_immutable = in_proxy_settings && line.contains("[$i]");
        } else if in_proxy_settings
            && !line.starts_with('#')
            && let Some((key, value)) = line.split_once('=')
        {
            let key = key.trim();
            let immutable = group_immutable || key.ends_with("[$i]");
            let key = key.strip_suffix("[$i]").unwrap_or(key).to_owned();
            if entries.get(&key).is_some_and(|entry| entry.immutable) {
                continue;
            }
            entries.insert(
                key,
                KdeEntry {
                    value: value.trim().to_owned(),
                    immutable,
                },
            );
        }
    }
}

fn config_from_kde_entries(
    entries: &HashMap<String, KdeEntry>,
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let value = |key: &str| entries.get(key).map(|entry| entry.value.as_str());
    let proxy_type = value("ProxyType")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    let mut config = SystemProxyConfig::default();
    match proxy_type {
        1 => {
            config.http = kde_endpoint(value("httpProxy"), Protocol::HTTP)?;
            config.https = kde_endpoint(value("httpsProxy"), Protocol::HTTP)?;
            config.socks5 = kde_endpoint(value("socksProxy"), Protocol::SOCKS5)?;
            if let Some(value) = value("NoProxyFor") {
                config.try_set_bypass_with_dialect(
                    parse_delimited_string_list(value),
                    policy,
                    BypassRuleDialect::Kde,
                )?;
            }
            config.reversed_bypass =
                value("ReversedException").is_some_and(|value| parse_gvariant_bool(Some(value)));
        }
        2 => {
            if let Some(value) = value("Proxy Config Script") {
                config.pac_uri = parse_kde_pac_uri(value)?;
            }
        }
        3 => config.auto_detect = true,
        // Type 4 delegates to environment variables, which Rama's separate
        // environment proxy layers own.
        _ => {}
    }
    Ok(config)
}

fn kde_endpoint(
    value: Option<&str>,
    default_protocol: Protocol,
) -> Result<Option<ProxyAddress>, BoxError> {
    let Some(value) = value.and_then(trim_ascii_quotes_non_empty) else {
        return Ok(None);
    };
    let mut value = value.trim_end_matches('/').to_owned();
    let mut parts = value.split_whitespace();
    if let (Some(host), Some(port), None) = (parts.next(), parts.next(), parts.next())
        && port.parse::<u16>().is_ok()
    {
        value = format!("{}:{port}", host.trim_end_matches('/'));
    }
    parse_proxy_endpoint(&value, default_protocol).map(Some)
}

fn parse_kde_pac_uri(value: &str) -> Result<Option<Uri>, BoxError> {
    let Some(value) = trim_ascii_quotes_non_empty(value) else {
        return Ok(None);
    };
    // KDE settings are discovered only on Unix targets, so interpret their
    // filesystem syntax as Unix syntax even when parser tests run on Windows.
    if value.starts_with('/') {
        parse_uri(&format!("file://{value}"))
    } else {
        parse_uri(value)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::{
        address::Host,
        client::{ProxyRoute, proxy::system::SystemProxyDecision},
    };
    use rama_core::service::service_fn;

    use super::*;

    #[cfg(target_os = "linux")]
    fn inotify_event(wd: i32, mask: u32, name: &str) -> Vec<u8> {
        let mut name = name.as_bytes().to_vec();
        name.push(0);
        let event = libc::inotify_event {
            wd,
            mask,
            cookie: 0,
            len: name.len() as u32,
        };
        let mut bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const event).cast::<u8>(),
                size_of::<libc::inotify_event>(),
            )
        }
        .to_vec();
        bytes.extend(name);
        bytes
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_watcher_ignores_unrelated_kde_files() {
        let filters = HashMap::from_iter([(7, Some(OsString::from("kioslaverc")))]);

        assert!(!inotify_events_changed(
            &inotify_event(7, libc::IN_CLOSE_WRITE, "unrelatedrc"),
            &filters,
        ));
        assert!(inotify_events_changed(
            &inotify_event(7, libc::IN_CLOSE_WRITE, "kioslaverc"),
            &filters,
        ));
        assert!(inotify_events_changed(
            &inotify_event(-1, libc::IN_Q_OVERFLOW, ""),
            &filters,
        ));
    }

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
            (("org.gnome.system.proxy", "ignore-hosts"), "[]"),
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
    async fn gnome_http_authentication_is_attached_and_inherited_by_https() {
        let values = HashMap::from_iter([
            (("org.gnome.system.proxy", "mode"), "'manual'"),
            (("org.gnome.system.proxy", "ignore-hosts"), "[]"),
            (("org.gnome.system.proxy.http", "host"), "'proxy.example'"),
            (("org.gnome.system.proxy.http", "port"), "8080"),
            (
                ("org.gnome.system.proxy.http", "use-authentication"),
                "true",
            ),
            (
                ("org.gnome.system.proxy.http", "authentication-user"),
                "'alice'",
            ),
            (
                ("org.gnome.system.proxy.http", "authentication-password"),
                "'s3cret'",
            ),
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

        let Some(ProxyCredential::Basic(basic)) = &config.http.as_ref().unwrap().credential else {
            panic!("GNOME HTTP proxy credentials were not loaded")
        };
        assert_eq!(basic.username(), "alice");
        assert_eq!(basic.password(), Some("s3cret"));
        assert_eq!(config.https, config.http);
    }

    #[tokio::test]
    async fn gnome_auto_mode_loads_bypass_rules_before_pac() {
        let values = HashMap::from_iter([
            (("org.gnome.system.proxy", "mode"), "'auto'"),
            (
                ("org.gnome.system.proxy", "autoconfig-url"),
                "https://config.example/proxy.pac",
            ),
            (
                ("org.gnome.system.proxy", "ignore-hosts"),
                "['internal.example']",
            ),
        ]);
        let config = read_gnome_with(
            SystemProxyInvalidBypassRulePolicy::Ignore,
            test_settings(values),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(config.bypass_before_pac);
        assert_eq!(config.bypass().collect::<Vec<_>>(), ["internal.example"]);
        assert!(matches!(
            config.decision(&"http://api.internal.example/".parse().unwrap()),
            SystemProxyDecision::Route(ProxyRoute::Direct)
        ));
    }

    #[tokio::test]
    async fn gnome_discovery_has_one_aggregate_deadline() {
        let settings = service_fn(|_key: (String, String)| async {
            std::future::pending::<Result<Option<String>, Infallible>>().await
        });
        let error = read_gnome_with_timeout(
            SystemProxyInvalidBypassRulePolicy::Ignore,
            settings,
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(error_is_timeout(error.as_ref()));
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

    #[tokio::test]
    async fn kde_file_read_has_a_deadline() {
        let error = string_future_with_timeout(
            std::future::pending::<io::Result<String>>(),
            Duration::from_millis(10),
        )
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
    fn kde_plain_domains_match_the_apex_and_descendants() {
        let config = parse_kde_config(
            "[Proxy Settings]\nProxyType=1\nhttpProxy=proxy.example 8080\nNoProxyFor=example.test\n",
            SystemProxyInvalidBypassRulePolicy::Ignore,
        )
        .unwrap();
        let protocol = Protocol::HTTP;

        assert!(config.bypasses(
            Some(&protocol),
            Host::try_from("example.test").unwrap().view(),
            Some(80),
        ));
        assert!(config.bypasses(
            Some(&protocol),
            Host::try_from("api.example.test").unwrap().view(),
            Some(80),
        ));
        assert!(!config.bypasses(
            Some(&protocol),
            Host::try_from("other.test").unwrap().view(),
            Some(80),
        ));
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
    fn kde_non_manual_modes_ignore_stale_exception_fields() {
        let pac = parse_kde_config(
            "[Proxy Settings]\nProxyType=2\nProxy Config Script=/tmp/proxy.pac\nNoProxyFor=bad/rule\nReversedException=true\n",
            SystemProxyInvalidBypassRulePolicy::Reject,
        )
        .unwrap();
        assert!(pac.bypass().next().is_none());
        assert!(!pac.reversed_bypass());

        let auto = parse_kde_config(
            "[Proxy Settings]\nProxyType=3\nNoProxyFor=bad/rule\n",
            SystemProxyInvalidBypassRulePolicy::Reject,
        )
        .unwrap();
        assert!(auto.auto_detect());
    }

    #[test]
    fn kde_wildcards_follow_the_selected_invalid_rule_policy() {
        let contents = "[Proxy Settings]\nProxyType=1\nhttpProxy=proxy.example 8080\nNoProxyFor=valid.example,*.unsupported.example\n";
        let config =
            parse_kde_config(contents, SystemProxyInvalidBypassRulePolicy::Ignore).unwrap();
        assert_eq!(config.bypass().collect::<Vec<_>>(), ["valid.example"]);
        parse_kde_config(contents, SystemProxyInvalidBypassRulePolicy::Reject).unwrap_err();
    }

    #[test]
    fn kde_layered_config_honors_precedence_and_immutability() {
        let mut entries = HashMap::default();
        merge_kde_entries(
            "[Proxy Settings]\nProxyType=1\nhttpProxy=system.example 8080\nNoProxyFor[$i]=system.example\n",
            &mut entries,
        );
        merge_kde_entries(
            "[Proxy Settings]\nhttpProxy=user.example 8081\nNoProxyFor=user.example\n",
            &mut entries,
        );
        let config =
            config_from_kde_entries(&entries, SystemProxyInvalidBypassRulePolicy::Ignore).unwrap();
        assert_eq!(
            config.http.as_ref().unwrap().to_string(),
            "http://user.example:8081"
        );
        assert_eq!(config.bypass().collect::<Vec<_>>(), ["system.example"]);

        let mut entries = HashMap::default();
        merge_kde_entries(
            "[Proxy Settings][$i]\nProxyType=1\nhttpProxy=locked.example 8080\n",
            &mut entries,
        );
        merge_kde_entries(
            "[Proxy Settings]\nProxyType=0\nhttpProxy=user.example 8081\n",
            &mut entries,
        );
        let config =
            config_from_kde_entries(&entries, SystemProxyInvalidBypassRulePolicy::Ignore).unwrap();
        assert_eq!(
            config.http.as_ref().unwrap().to_string(),
            "http://locked.example:8080"
        );
    }

    #[test]
    fn kde_paths_follow_xdg_precedence_without_cross_profile_fallback() {
        let system_dirs = OsString::from("/highest-system/:relative:/lowest-system");
        assert_eq!(
            kde_paths_from(
                Some(system_dirs),
                Some("/custom-profile/".into()),
                Some("/home/user".into()),
            ),
            [
                PathBuf::from("/lowest-system/kioslaverc"),
                PathBuf::from("/highest-system/kioslaverc"),
                PathBuf::from("/custom-profile/kioslaverc"),
            ]
        );

        assert_eq!(
            kde_paths_from(
                None,
                Some("relative-profile".into()),
                Some("/home/user".into()),
            ),
            [
                PathBuf::from("/etc/xdg/kioslaverc"),
                PathBuf::from("/home/user/.kde/share/config/kioslaverc"),
                PathBuf::from("/home/user/.kde4/share/config/kioslaverc"),
                PathBuf::from("/home/user/.config/kioslaverc"),
            ]
        );
    }

    #[test]
    fn kde_path_helpers_preserve_unix_syntax() {
        assert!(is_unix_absolute(Path::new("/profile")));
        assert!(!is_unix_absolute(Path::new("relative")));
        assert_eq!(
            join_unix_path(Path::new("/profile/"), "kioslaverc").as_os_str(),
            OsStr::new("/profile/kioslaverc"),
        );
        assert_eq!(
            join_unix_path(Path::new(""), "kioslaverc").as_os_str(),
            OsStr::new("kioslaverc"),
        );
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
            parse_gvariant_string_list(r"['b\u00fccher.example', 'caf\U000000e9.example']"),
            ["bücher.example", "café.example"]
        );
        assert_eq!(
            parse_delimited_string_list("[::1];[2001:db8::5]"),
            ["[::1]", "[2001:db8::5]"]
        );
        assert!(parse_gvariant_bool(Some("true")));
        assert!(!parse_gvariant_bool(Some("false")));
    }
}
