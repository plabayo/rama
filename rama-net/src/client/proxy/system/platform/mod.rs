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
#[cfg(not(test))]
use std::sync::OnceLock;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

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
use rama_utils::str::trim_ascii_quotes_non_empty;

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

#[derive(Debug, Default)]
pub(super) struct ConfigChangeMonitor {
    change_generation: AtomicU64,
    failure_generation: AtomicU64,
    failure: parking_lot::Mutex<Option<Arc<BoxError>>>,
}

impl ConfigChangeMonitor {
    #[cfg_attr(
        not(any(test, target_os = "macos", target_os = "windows", target_os = "linux")),
        expect(
            dead_code,
            reason = "native proxy change notifications are not available on this target"
        )
    )]
    pub(super) fn notify_change(&self) {
        self.change_generation.fetch_add(1, Ordering::Release);
    }

    #[cfg_attr(
        not(any(test, target_os = "macos", target_os = "windows", target_os = "linux")),
        expect(
            dead_code,
            reason = "native proxy watcher failures are not available on this target"
        )
    )]
    fn record_failure(&self, error: BoxError) {
        *self.failure.lock() = Some(Arc::new(error));
        self.failure_generation.fetch_add(1, Ordering::Release);
    }
}

#[derive(Debug)]
pub(super) struct PlatformConfigChangeTrigger {
    monitor: Arc<ConfigChangeMonitor>,
    seen_change_generation: AtomicU64,
    seen_failure_generation: AtomicU64,
}

impl PlatformConfigChangeTrigger {
    fn new(monitor: Arc<ConfigChangeMonitor>) -> Self {
        Self {
            seen_change_generation: AtomicU64::new(
                monitor.change_generation.load(Ordering::Acquire),
            ),
            seen_failure_generation: AtomicU64::new(0),
            monitor,
        }
    }

    pub(super) fn poll(&self) -> Result<bool, BoxError> {
        let failure_generation = self.monitor.failure_generation.load(Ordering::Acquire);
        if failure_generation
            != self
                .seen_failure_generation
                .swap(failure_generation, Ordering::AcqRel)
            && let Some(error) = self.monitor.failure.lock().clone()
        {
            return Err(Box::new(SharedConfigMonitorError(error)));
        }
        let change_generation = self.monitor.change_generation.load(Ordering::Acquire);
        Ok(change_generation
            != self
                .seen_change_generation
                .swap(change_generation, Ordering::AcqRel))
    }
}

#[derive(Debug, Clone)]
struct SharedConfigMonitorError(Arc<BoxError>);

impl std::fmt::Display for SharedConfigMonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SharedConfigMonitorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

pub(super) fn config_change_trigger() -> Arc<PlatformConfigChangeTrigger> {
    #[cfg(test)]
    return Arc::new(PlatformConfigChangeTrigger::new(Arc::new(
        ConfigChangeMonitor::default(),
    )));

    #[cfg(not(test))]
    Arc::new(PlatformConfigChangeTrigger::new(
        global_config_change_monitor(),
    ))
}

#[cfg(not(test))]
fn global_config_change_monitor() -> Arc<ConfigChangeMonitor> {
    static MONITOR: OnceLock<Arc<ConfigChangeMonitor>> = OnceLock::new();
    MONITOR
        .get_or_init(|| {
            let monitor = Arc::new(ConfigChangeMonitor::default());
            #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
            {
                let thread_monitor = monitor.clone();
                if let Err(error) = std::thread::Builder::new()
                    .name("rama-system-proxy-watch".to_owned())
                    .spawn(move || {
                        if let Err(error) = run_config_change_monitor(&thread_monitor) {
                            thread_monitor.record_failure(error);
                        }
                    })
                {
                    monitor.record_failure(rama_core::error::ErrorExt::context(
                        error,
                        "spawn native system proxy configuration watcher",
                    ));
                }
            }
            monitor
        })
        .clone()
}

#[cfg(all(not(test), target_os = "macos"))]
fn run_config_change_monitor(monitor: &ConfigChangeMonitor) -> Result<(), BoxError> {
    apple::run_config_change_monitor(monitor)
}

#[cfg(all(not(test), target_os = "windows"))]
fn run_config_change_monitor(monitor: &ConfigChangeMonitor) -> Result<(), BoxError> {
    windows::run_config_change_monitor(monitor)
}

#[cfg(all(not(test), target_os = "linux"))]
fn run_config_change_monitor(monitor: &ConfigChangeMonitor) -> Result<(), BoxError> {
    desktop_unix::run_config_change_monitor(monitor)
}

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
    let mut value = trim_ascii_quotes_non_empty(value)
        .ok_or_else(|| BoxError::from_static_str("system proxy endpoint is empty"))?
        .to_owned();
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
    trim_ascii_quotes_non_empty(value)
        .map(|value| Uri::from_str(value).context("parse system PAC URI"))
        .transpose()
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
        .filter_map(trim_ascii_quotes_non_empty)
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
fn parse_gvariant_string(value: &str) -> Option<String> {
    let value = value.trim();
    let value = match (value.as_bytes().first(), value.as_bytes().last()) {
        (Some(quote @ (b'\'' | b'"')), Some(last)) if quote == last => {
            value.get(1..value.len().saturating_sub(1))?
        }
        _ => value,
    };
    unescape_gvariant_string(value)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rama_core::error::{BoxError, BoxErrorExt as _};

    use super::{ConfigChangeMonitor, PlatformConfigChangeTrigger};

    #[test]
    fn platform_trigger_observes_each_generation_once() {
        let monitor = Arc::new(ConfigChangeMonitor::default());
        let trigger = PlatformConfigChangeTrigger::new(monitor.clone());

        assert!(!trigger.poll().unwrap());
        monitor.notify_change();
        assert!(trigger.poll().unwrap());
        assert!(!trigger.poll().unwrap());
        monitor.notify_change();
        monitor.notify_change();
        assert!(trigger.poll().unwrap());
        assert!(!trigger.poll().unwrap());
    }

    #[test]
    fn platform_trigger_reports_terminal_monitor_failure_once() {
        let monitor = Arc::new(ConfigChangeMonitor::default());
        let trigger = PlatformConfigChangeTrigger::new(monitor.clone());

        monitor.record_failure(BoxError::from_static_str("watcher stopped"));
        assert_eq!(trigger.poll().unwrap_err().to_string(), "watcher stopped");
        assert!(!trigger.poll().unwrap());
    }
}
