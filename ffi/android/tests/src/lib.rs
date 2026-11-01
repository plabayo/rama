//! On-device Android test suites for rama.
//!
//! The Java entry point `org.ramaproxy.tests.RamaAndroidTests` loads this
//! library in an Android runtime started with `app_process`, so suites reach
//! the Android framework through JNI. This does not install an app's Network
//! Security Config provider; NSC requires APK instrumentation. Each suite is a module
//! exposing a [`harness::Test`] list, registered in [`SUITES`].
//!
//! Run with `just test-android [filter]`, see `ffi/android/tests/README.md`.

use std::ffi::c_void;

use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::{JClass, JString},
    sys::{JNI_ERR, JNI_VERSION_1_6, JavaVM, jint},
};

mod harness;
mod nsc;
mod platform_verifier;
mod revocation;
mod tls;

/// Every suite, by name. A filter selects tests whose `suite::test` name
/// contains it.
static SUITES: &[(&str, &[harness::Test])] = &[
    ("platform_verifier", platform_verifier::TESTS),
    ("tls", tls::TESTS),
    ("revocation", revocation::TESTS),
];

/// Library load hook: records the `JavaVM` for rama's Android code.
///
/// # Safety
///
/// The caller must pass as `vm` the `JavaVM` loading this library, as the JNI
/// `JNI_OnLoad` contract does, and call this at most once per process, before
/// any other function of this library runs. `vm` must stay valid for the rest
/// of the process.
// Unique symbol: `JNI_OnLoad` is the JNI-specified per-library load hook; the
// VM resolves it in this library only, and no other code linked into this
// cdylib defines it.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn JNI_OnLoad(vm: *mut JavaVM, _reserved: *mut c_void) -> jint {
    if vm.is_null() {
        return JNI_ERR;
    }
    // SAFETY: `initialize_android_context` requires valid pointers and a
    // single call before other use. `vm` is the non-null loading VM, valid for
    // the process (this function's contract). The context is null: JNI
    // defines a null `jobject` as the null reference, there is no Android
    // `Context` outside an app, and the suites here only use the VM. The
    // contract makes this the one call, made before any other function of
    // this library.
    unsafe { ndk_context::initialize_android_context(vm.cast(), std::ptr::null_mut()) };
    JNI_VERSION_1_6
}

/// Run the tests matching `filter`, returning the number that failed.
// Unique symbol: the JNI-mangled name of `RamaAndroidTests.run`, defined once
// in this cdylib; the signature is the JNI native-method ABI (`EnvUnowned`,
// `JClass` and `JString` are jni's `repr(transparent)` JNI types).
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

/// APK-only regression tests with the application NSC provider installed.
// Unique symbol: as for `..._run`, for `RamaAndroidTests.runNetworkSecurityConfig`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ramaproxy_tests_RamaAndroidTests_runNetworkSecurityConfig(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jint {
    std::thread::spawn(|| harness::run(&[("nsc", nsc::TESTS)], ""))
        .join()
        .unwrap_or(1)
}
