#[cfg(target_os = "windows")]
use std::io;
#[cfg(all(target_os = "windows", not(test)))]
use std::ptr;

#[cfg(all(target_os = "windows", not(test)))]
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0},
    System::{
        Registry::{
            HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET,
            REG_NOTIFY_CHANGE_NAME, RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW,
        },
        Threading::{CreateEventW, INFINITE, WaitForMultipleObjects},
    },
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, GlobalFree},
    Networking::WinHttp::{
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WinHttpGetIEProxyConfigForCurrentUser,
    },
};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryHive {
    CurrentUser,
    LocalMachine,
}

const REGISTRY_WATCH_SPECS: &[(RegistryHive, &str)] = &[
    (
        RegistryHive::CurrentUser,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    ),
    (
        RegistryHive::LocalMachine,
        "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    ),
    (
        RegistryHive::LocalMachine,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    ),
];

#[cfg(all(target_os = "windows", not(test)))]
pub(super) fn run_config_change_monitor(monitor: &ConfigChangeMonitor) -> Result<(), BoxError> {
    let watches = REGISTRY_WATCH_SPECS
        .iter()
        .map(|(hive, path)| RegistryWatch::open(*hive, path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if watches.is_empty() {
        return Ok(());
    }
    for watch in &watches {
        watch.arm()?;
    }
    let handles = watches.iter().map(|watch| watch.event).collect::<Vec<_>>();
    loop {
        // SAFETY: `handles` is non-empty and contains live event handles owned
        // by `watches`; its backing allocation cannot move during the wait.
        let result =
            unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, INFINITE) };
        let Some(index) = result
            .checked_sub(WAIT_OBJECT_0)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < watches.len())
        else {
            return Err(io::Error::last_os_error().into());
        };
        rearm_then_publish(|| watches[index].arm(), || monitor.notify_change())?;
    }
}

fn rearm_then_publish<E>(
    rearm: impl FnOnce() -> Result<(), E>,
    publish: impl FnOnce(),
) -> Result<(), E> {
    rearm()?;
    publish();
    Ok(())
}

#[cfg(all(target_os = "windows", not(test)))]
impl RegistryWatch {
    fn open(hive: RegistryHive, path: &str) -> io::Result<Option<Self>> {
        let path = format!("{path}\0").encode_utf16().collect::<Vec<_>>();
        let root = match hive {
            RegistryHive::CurrentUser => HKEY_CURRENT_USER,
            RegistryHive::LocalMachine => HKEY_LOCAL_MACHINE,
        };
        let mut key = ptr::null_mut();
        // SAFETY: `root` is a predefined live hive handle, `path` is
        // NUL-terminated UTF-16, and `key` is a valid out-pointer.
        let result = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_NOTIFY, &raw mut key) };
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        // SAFETY: null security/name pointers request the documented defaults;
        // the returned handle is checked before use.
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event.is_null() {
            // SAFETY: `key` was initialized by the successful open call and
            // has not otherwise been closed.
            unsafe { RegCloseKey(key) };
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { key, event }))
    }

    fn arm(&self) -> io::Result<()> {
        // SAFETY: both handles are live and owned by `self`; asynchronous
        // notification is requested into the event handle.
        let result = unsafe {
            RegNotifyChangeKeyValue(
                self.key,
                1,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                self.event,
                1,
            )
        };
        if result == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result as i32))
        }
    }
}

#[cfg(all(target_os = "windows", not(test)))]
struct RegistryWatch {
    key: HKEY,
    event: HANDLE,
}

#[cfg(all(target_os = "windows", not(test)))]
// SAFETY: registry-key and event HANDLE values are process-wide kernel
// handles and may be waited on, armed, and closed from another thread.
unsafe impl Send for RegistryWatch {}

#[cfg(all(target_os = "windows", not(test)))]
impl Drop for RegistryWatch {
    fn drop(&mut self) {
        // SAFETY: both handles are uniquely owned by `self` and are closed
        // exactly once from this Drop implementation.
        unsafe {
            RegCloseKey(self.key);
            CloseHandle(self.event);
        }
    }
}

#[cfg(target_os = "windows")]
pub(super) fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let mut native = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    // SAFETY: `native` is initialized and passed as a valid writable
    // out-pointer; WinHTTP fills it or reports failure.
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&raw mut native) } == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            Ok(SystemProxyConfig::default())
        } else {
            Err(error.into())
        };
    }

    // SAFETY: on success WinHTTP returns null or GlobalAlloc-owned,
    // NUL-terminated strings in each of these fields.
    let pac = unsafe { take_wide_string(native.lpszAutoConfigUrl) };
    // SAFETY: same ownership and termination guarantee as above; every field
    // is independent and consumed exactly once.
    let proxy = unsafe { take_wide_string(native.lpszProxy) };
    // SAFETY: same ownership and termination guarantee as above; every field
    // is independent and consumed exactly once.
    let bypass = unsafe { take_wide_string(native.lpszProxyBypass) };

    config_from_native(
        proxy.as_deref(),
        pac.as_deref(),
        bypass.as_deref(),
        native.fAutoDetect != 0,
        policy,
    )
}

fn config_from_native(
    proxy: Option<&str>,
    pac: Option<&str>,
    bypass: Option<&str>,
    auto_detect: bool,
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let mut config = proxy.map(parse_proxy).transpose()?.unwrap_or_default();
    config.auto_detect = auto_detect;
    config.pac_uri = pac.map(parse_uri).transpose()?.flatten();
    if let Some(bypass) = bypass {
        config.try_set_bypass_with_dialect(
            parse_delimited_string_list(bypass),
            policy,
            BypassRuleDialect::FlatGlob,
        )?;
    }
    Ok(config)
}

#[cfg(target_os = "windows")]
/// Convert and release one string returned by
/// `WinHttpGetIEProxyConfigForCurrentUser`.
///
/// # Safety
///
/// `pointer` must be null or point to a readable, NUL-terminated UTF-16 string
/// allocated with `GlobalAlloc`, and ownership must be transferred exactly
/// once to this function.
unsafe fn take_wide_string(pointer: windows_sys::core::PWSTR) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0;
    loop {
        // SAFETY: the caller guarantees a readable NUL-terminated sequence;
        // all preceding units were non-NUL, so advancing by `length` is valid.
        let current = unsafe { pointer.add(length) };
        // SAFETY: `current` is within the caller-guaranteed UTF-16 sequence.
        if unsafe { *current } == 0 {
            break;
        }
        length += 1;
    }
    // SAFETY: the scan established that exactly `length` initialized u16 units
    // precede the terminator.
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) });
    // SAFETY: ownership was transferred to this function and WinHTTP uses
    // GlobalAlloc for the returned buffer.
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
            "socks" => {
                return Err(BoxError::from_static_str(
                    "WinINET `socks=` configures SOCKS4, which Rama does not support",
                ));
            }
            "socks5" => config.socks5 = Some(parse_proxy_endpoint(endpoint, Protocol::SOCKS5)?),
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
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn watches_user_machine_and_machine_policy_settings() {
        assert_eq!(REGISTRY_WATCH_SPECS.len(), 3);
        assert!(REGISTRY_WATCH_SPECS.iter().any(|(hive, path)| {
            *hive == RegistryHive::CurrentUser && path.ends_with("Internet Settings")
        }));
        assert!(REGISTRY_WATCH_SPECS.iter().any(|(hive, path)| {
            *hive == RegistryHive::LocalMachine && path.contains("Policies")
        }));
        assert!(REGISTRY_WATCH_SPECS.iter().any(|(hive, path)| {
            *hive == RegistryHive::LocalMachine && !path.contains("Policies")
        }));
    }

    #[test]
    fn registry_watch_is_rearmed_before_change_is_published() {
        let calls = RefCell::new(Vec::new());
        rearm_then_publish(
            || {
                calls.borrow_mut().push("rearm");
                Ok::<_, ()>(())
            },
            || calls.borrow_mut().push("publish"),
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["rearm", "publish"]);

        let published = std::cell::Cell::new(false);
        assert!(rearm_then_publish(|| Err::<(), _>(()), || published.set(true)).is_err());
        assert!(!published.get());
    }

    #[test]
    fn protocol_mapping_and_bare_proxy() {
        let config = parse_proxy("http=web:8080;https=secure:8443;socks5=socks:1080").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://secure:8443");
        assert_eq!(config.socks5.unwrap().to_string(), "socks5://socks:1080");

        let config = parse_proxy("proxy.example:3128").unwrap();
        assert_eq!(config.http, config.https);

        let config = parse_proxy("http=web:8080 https=secure:8443 socks5=socks:1080").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://secure:8443");
        assert_eq!(config.socks5.unwrap().to_string(), "socks5://socks:1080");

        let config = parse_proxy("http=web:8080 default:3128").unwrap();
        assert_eq!(config.http.unwrap().to_string(), "http://web:8080");
        assert_eq!(config.https.unwrap().to_string(), "http://default:3128");
        assert!(parse_proxy("").unwrap().is_empty());
        parse_proxy("socks=legacy:1080").unwrap_err();

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

    #[test]
    fn native_auto_discovery_and_pac_signals_round_trip() {
        let config = config_from_native(
            None,
            Some("https://config.example/proxy.pac"),
            None,
            true,
            SystemProxyInvalidBypassRulePolicy::Ignore,
        )
        .unwrap();
        assert!(config.auto_detect());
        assert_eq!(
            config.pac_uri().unwrap().to_string(),
            "https://config.example/proxy.pac"
        );
    }
}
