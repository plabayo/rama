use jni::{
    jni_sig, jni_str,
    objects::{JObject, JObjectArray, JString, JValue},
    refs::Reference as _,
};

use super::*;

pub(super) fn read(
    policy: SystemProxyInvalidBypassRulePolicy,
) -> Result<SystemProxyConfig, BoxError> {
    let initial_context =
        std::panic::catch_unwind(ndk_context::android_context).map_err(|panic| {
            drop(panic);
            BoxError::from_static_str("Android context is not initialized")
        })?;
    let vm = unsafe { jni::JavaVM::from_raw(initial_context.vm().cast()) };
    vm.attach_current_thread(|env| -> Result<SystemProxyConfig, BoxError> {
        // ndk-context may replace and release its Activity reference during
        // lifecycle changes. Re-read it only after this thread is attached,
        // then retain our own global reference for the complete snapshot read.
        // A release racing this narrow acquisition window is inherent to
        // ndk-context's raw-pointer API; embedders should initialize it with an
        // Application context when possible.
        let context = std::panic::catch_unwind(ndk_context::android_context).map_err(|panic| {
            drop(panic);
            BoxError::from_static_str("Android context is not initialized")
        })?;
        let borrowed_context = unsafe { JObject::global_kind_from_raw(context.context().cast()) };
        let context = env.new_global_ref(&borrowed_context)?;
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
            let mut exclusions = Vec::new();
            for property in ["http.nonProxyHosts", "https.nonProxyHosts"] {
                if let Some(value) = system_property(env, property)? {
                    exclusions.extend(parse_java_non_proxy_hosts(&value));
                }
            }
            config.try_set_bypass_with_dialect(exclusions, policy, BypassRuleDialect::FlatGlob)?;
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
        if manager.is_null() {
            return Ok(SystemProxyConfig::default());
        }
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

        // Android's PAC mode also exposes the localhost proxy used by the
        // platform PAC evaluator. Preserve it as the fixed fallback when no
        // application PAC resolver is installed or returns no routes.
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
                let value = exclusions.get_element(env, index)?;
                if !value.is_null() {
                    values.push(value.try_to_string(env)?);
                }
            }
            config.try_set_bypass_with_dialect(values, policy, BypassRuleDialect::FlatGlob)?;
        }
        Ok(config)
    })
}

fn system_property(env: &mut jni::Env<'_>, name: &str) -> Result<Option<String>, BoxError> {
    let name = env.new_string(name)?;
    let value = env
        .call_static_method(
            jni_str!("java/lang/System"),
            jni_str!("getProperty"),
            jni_sig!("(Ljava/lang/String;)Ljava/lang/String;"),
            &[JValue::Object(&name)],
        )?
        .l()?;
    if value.is_null() {
        return Ok(None);
    }
    env.cast_local::<JString<'_>>(value)
        .and_then(|value| value.try_to_string(env))
        .map(Some)
        .map_err(Into::into)
}

fn parse_java_non_proxy_hosts(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split('|')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::parse_java_non_proxy_hosts;

    #[test]
    fn java_non_proxy_hosts_are_pipe_delimited() {
        assert_eq!(
            parse_java_non_proxy_hosts("localhost|*.example.com||10.*").collect::<Vec<_>>(),
            ["localhost", "*.example.com", "10.*"]
        );
    }
}
