#![cfg_attr(test, allow(dead_code))]

#[cfg(target_os = "macos")]
use std::{ffi::c_void, ptr};

use core_foundation::{
    array::CFArray,
    base::{CFType, CFTypeRef, TCFType},
    dictionary::{CFDictionary, CFDictionaryRef},
    number::CFNumber,
    string::CFString,
};
#[cfg(target_os = "macos")]
use core_foundation::{
    array::CFArrayRef,
    base::{Boolean, CFIndex, CFRelease, kCFAllocatorDefault},
    runloop::{CFRunLoop, CFRunLoopSource, CFRunLoopSourceRef, kCFRunLoopDefaultMode},
    string::CFStringRef,
};
use rama_core::error::ErrorExt as _;

use super::*;

#[link(name = "CFNetwork", kind = "framework")]
unsafe extern "C" {
    /// CFProxySupport.h: no preconditions; returns null or a dictionary the
    /// caller must release (Copy rule), whose `ExceptionsList`
    /// (`kCFNetworkProxiesExceptionsList`) value is a "CFArray of CFStrings".
    fn CFNetworkCopySystemProxySettings() -> CFDictionaryRef;
}

#[link(name = "SystemConfiguration", kind = "framework")]
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn SCDynamicStoreCreate(
        allocator: *const c_void,
        name: CFStringRef,
        callback: SCDynamicStoreCallBack,
        context: *mut SCDynamicStoreContext,
    ) -> SCDynamicStoreRef;
    fn SCDynamicStoreSetNotificationKeys(
        store: SCDynamicStoreRef,
        keys: CFArrayRef,
        patterns: CFArrayRef,
    ) -> Boolean;
    fn SCDynamicStoreCreateRunLoopSource(
        allocator: *const c_void,
        store: SCDynamicStoreRef,
        order: CFIndex,
    ) -> CFRunLoopSourceRef;
}

#[cfg(target_os = "macos")]
type SCDynamicStoreRef = *mut c_void;
#[cfg(target_os = "macos")]
type SCDynamicStoreCallBack =
    Option<unsafe extern "C" fn(SCDynamicStoreRef, CFArrayRef, *mut c_void)>;

/// Mirrors `SCDynamicStoreContext` from SystemConfiguration/SCDynamicStore.h.
#[repr(C)]
#[cfg(target_os = "macos")]
struct SCDynamicStoreContext {
    version: CFIndex,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const c_void) -> CFStringRef>,
}

#[cfg(target_os = "macos")]
pub(super) fn run_config_change_monitor(monitor: &ConfigChangeMonitor) -> Result<(), BoxError> {
    let mut context = SCDynamicStoreContext {
        version: 0,
        info: std::ptr::from_ref(monitor).cast_mut().cast(),
        retain: None,
        release: None,
        copy_description: None,
    };
    let name = CFString::new("rama system proxy watcher");
    // SAFETY: reading an extern static that CFBase.h declares `const`, so no
    // write can race this read.
    let allocator = unsafe { kCFAllocatorDefault };
    // SAFETY: SCDynamicStore.h `SCDynamicStoreCreate`: `allocator` and `name`
    // are a valid allocator and a live CFString, `&raw mut context` is a live,
    // aligned context read during the call, and the result follows the Create
    // rule. `system_proxy_config_changed` contract: its callout is delivered
    // only by the run-loop source of `store`, which is scheduled on this
    // thread's run loop solely during `CFRunLoop::run_current()` below, while
    // `monitor` (the `info` pointee, shared-only) is still borrowed. Nothing
    // between `add_source` and `remove_source` can unwind: `CFRunLoopRun`
    // returns normally and the callout is a non-unwinding `extern "C"` fn.
    let store = unsafe {
        SCDynamicStoreCreate(
            allocator,
            name.as_concrete_TypeRef(),
            Some(system_proxy_config_changed),
            &raw mut context,
        )
    };
    if store.is_null() {
        return Err(BoxError::from_static_str(
            "create Apple system proxy configuration watcher",
        ));
    }

    let proxy_key = CFString::new("State:/Network/Global/Proxies");
    let keys = CFArray::from_CFTypes(&[proxy_key]);
    // SAFETY: SCDynamicStore.h `SCDynamicStoreSetNotificationKeys`: `store`
    // is the non-null store created above and still owned here, `keys` is a
    // live CFArray of CFStrings, and `patterns` is nullable.
    if unsafe { SCDynamicStoreSetNotificationKeys(store, keys.as_concrete_TypeRef(), ptr::null()) }
        == 0
    {
        // SAFETY: `CFRelease` gives up one owned reference to a non-null CF
        // object: `store` is our +1 reference (Create rule), unused after.
        unsafe { CFRelease(store.cast()) };
        return Err(BoxError::from_static_str(
            "register Apple system proxy configuration notification",
        ));
    }
    // SAFETY: SCDynamicStore.h `SCDynamicStoreCreateRunLoopSource`: valid
    // allocator, `store` still owned here; the result follows the Create rule.
    let source = unsafe { SCDynamicStoreCreateRunLoopSource(allocator, store, 0) };
    if source.is_null() {
        // SAFETY: `CFRelease` gives up one owned reference to a non-null CF
        // object: `store` is our +1 reference (Create rule), unused after.
        unsafe { CFRelease(store.cast()) };
        return Err(BoxError::from_static_str(
            "create Apple system proxy configuration run-loop source",
        ));
    }
    // SAFETY: `wrap_under_create_rule` takes over one owned reference to a
    // valid CFRunLoopSource: `source` is non-null (checked) and +1 (Create rule).
    let source = unsafe { CFRunLoopSource::wrap_under_create_rule(source) };
    let run_loop = CFRunLoop::get_current();
    // SAFETY: reading an extern static that CFRunLoop.h declares `const`, so
    // no write can race this read.
    let default_mode = unsafe { kCFRunLoopDefaultMode };
    run_loop.add_source(&source, default_mode);
    CFRunLoop::run_current();
    run_loop.remove_source(&source, default_mode);
    drop(source);
    // SAFETY: `CFRelease` gives up one owned reference to a non-null CF
    // object: `store` is our +1 reference (Create rule), unused after, and the
    // callout can no longer fire since its source left the run loop.
    unsafe { CFRelease(store.cast()) };
    Err(BoxError::from_static_str(
        "Apple system proxy configuration run loop stopped",
    ))
}

#[cfg(target_os = "macos")]
/// # Safety
///
/// The caller must ensure `info` is null or points to a live, aligned
/// `ConfigChangeMonitor` that is not mutably aliased for the duration of the
/// call.
unsafe extern "C" fn system_proxy_config_changed(
    _store: SCDynamicStoreRef,
    _keys: CFArrayRef,
    info: *mut c_void,
) {
    if !info.is_null() {
        // SAFETY: creating `&ConfigChangeMonitor` needs a non-null, aligned
        // pointer to a live, not mutably aliased value for the borrow: this
        // fn's precondition plus the null check; the borrow ends in this call.
        let monitor = unsafe { &*info.cast::<ConfigChangeMonitor>() };
        monitor.notify_change();
    }
}

pub(super) fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    // SAFETY: no preconditions; see the declaration for the return contract.
    let raw = unsafe { CFNetworkCopySystemProxySettings() };
    if raw.is_null() {
        return Ok(SystemProxyConfig::default());
    }
    // SAFETY: `wrap_under_create_rule` takes over one owned reference to a
    // valid CFDictionary: `raw` is non-null (checked) and +1 (Copy rule). The
    // `CFString`/`CFType` parameters are sound for any CF dictionary contents:
    // keys are only used as lookup input, and values are only exposed as
    // `CFType` and then type-checked by `downcast`.
    let settings: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw) };
    // SAFETY: `parse_settings` contract: CFProxySupport.h documents the
    // `ExceptionsList` array as holding CFStrings, kept alive by `settings`.
    unsafe { parse_settings(&settings, policy) }
}

/// # Safety
///
/// The caller must ensure that a `CFArray` stored under `ExceptionsList` in
/// `settings` holds only valid CF object references for the duration of the
/// call (`CFArray::from_copyable` can safely build arrays of arbitrary pointers).
unsafe fn parse_settings(
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
        // SAFETY: `string_array` contract: this fn's `ExceptionsList` precondition.
        unsafe { string_array(settings, "ExceptionsList") },
        policy,
        BypassRuleDialect::FlatGlob,
    )?;
    config.bypass_before_pac = true;
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

/// # Safety
///
/// The caller must ensure that a `CFArray` stored under `key` in `settings`
/// holds only valid CF object references for the duration of the call.
unsafe fn string_array(settings: &CFDictionary<CFString, CFType>, key: &str) -> Vec<String> {
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
            // SAFETY: `wrap_under_get_rule` needs a valid CF object; it retains
            // it. `value` is a non-null element of `array`, a CF object by this
            // fn's precondition, kept alive by `array` during the retain.
            unsafe { CFType::wrap_under_get_rule(value as CFTypeRef) }
                .downcast::<CFString>()
                .map(|value| value.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        address::Host,
        client::{ProxyRoute, proxy::system::SystemProxyDecision},
    };
    use std::assert_matches;

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
        // SAFETY: `parse_settings` contract: the only arrays here come from
        // `CFArray::from_CFTypes`, so they hold live CF objects.
        let config =
            unsafe { parse_settings(&http_only, SystemProxyInvalidBypassRulePolicy::Ignore) }
                .unwrap();
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
        // SAFETY: `parse_settings` contract: the only arrays here come from
        // `CFArray::from_CFTypes`, so they hold live CF objects.
        let config =
            unsafe { parse_settings(&both, SystemProxyInvalidBypassRulePolicy::Ignore) }.unwrap();
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
            // SAFETY: `parse_settings` contract: the only arrays here come from
            // `CFArray::from_CFTypes`, so they hold live CF objects.
            let config =
                unsafe { parse_settings(&settings, SystemProxyInvalidBypassRulePolicy::Ignore) }
                    .unwrap();
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
    fn exception_list_bypasses_before_pac_evaluation() {
        let exceptions = CFArray::from_CFTypes(&[CFString::new("internal.example")]);
        let settings = settings(vec![
            ("ProxyAutoConfigEnable", CFNumber::from(1_i32).as_CFType()),
            (
                "ProxyAutoConfigURLString",
                CFString::new("https://config.example/proxy.pac").as_CFType(),
            ),
            ("ExceptionsList", exceptions.as_CFType()),
        ]);
        // SAFETY: `parse_settings` contract: the only arrays here come from
        // `CFArray::from_CFTypes`, so they hold live CF objects.
        let config =
            unsafe { parse_settings(&settings, SystemProxyInvalidBypassRulePolicy::Ignore) }
                .unwrap();

        assert!(config.bypass_before_pac);
        assert_matches!(
            config.decision(&"http://internal.example/".parse().unwrap()),
            SystemProxyDecision::Route(ProxyRoute::Direct),
        );
        assert_matches!(
            config.decision(&"http://external.example/".parse().unwrap()),
            SystemProxyDecision::Pac(_),
        );
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
            // SAFETY: `parse_settings` contract: `entries` holds no array.
            unsafe {
                parse_settings(
                    &settings(entries),
                    SystemProxyInvalidBypassRulePolicy::Ignore,
                )
            }
            .unwrap_err();
        }

        // SAFETY: `parse_settings` contract: the dictionary holds no array.
        let config = unsafe {
            parse_settings(
                &settings(vec![(
                    "ProxyAutoDiscoveryEnable",
                    CFNumber::from(1_i32).as_CFType(),
                )]),
                SystemProxyInvalidBypassRulePolicy::Ignore,
            )
        }
        .unwrap();
        assert!(config.auto_detect());
        assert!(!config.is_empty());
    }
}
