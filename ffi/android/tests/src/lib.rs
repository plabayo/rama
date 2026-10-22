//! On-device Android test suites for rama.
//!
//! The Java entry point `org.ramaproxy.tests.RamaAndroidTests` loads this
//! library in an Android runtime started with `app_process`, so suites reach
//! the Android framework through JNI like an app would. Each suite is a module
//! exposing a [`harness::Test`] list, registered in [`SUITES`].
//!
//! Run with `just test-android [filter]`, see `ffi/android/tests/README.md`.

use std::ffi::c_void;

use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JClass, JString},
    sys::{JNI_VERSION_1_6, JavaVM, jint},
};

mod harness;
mod platform_verifier;

/// Every suite, by name. A filter selects tests whose `suite::test` name
/// contains it.
static SUITES: &[(&str, &[harness::Test])] = &[("platform_verifier", platform_verifier::TESTS)];

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: *mut JavaVM, _reserved: *mut c_void) -> jint {
    // SAFETY: the runtime passes the process JavaVM, valid for the process
    // lifetime. There is no Android Context outside an app; rama's Android
    // code only needs the VM.
    unsafe { ndk_context::initialize_android_context(vm.cast(), std::ptr::null_mut()) };
    JNI_VERSION_1_6
}

/// Run the tests matching `filter`, returning the number that failed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ramaproxy_tests_RamaAndroidTests_run<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    filter: JString<'caller>,
) -> jint {
    let filter = env
        .with_env(|env| -> jni::errors::Result<String> {
            if filter.is_null() {
                Ok(String::new())
            } else {
                filter.try_to_string(env)
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>();
    // A thread of its own, attached on demand, as rama's verification threads are.
    std::thread::spawn(move || harness::run(SUITES, &filter))
        .join()
        .unwrap_or(1)
}
