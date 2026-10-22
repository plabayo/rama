//! Exercise the real macOS hardened runtime, without a signing certificate.
//! Only a temporary copy of this test executable is ad-hoc signed.
#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(feature = "js-interpreter")]
#[path = "support/representative.rs"]
mod representative;

const CHILD: &str = "RAMA_PAC_HARDENED_TEST_CHILD";

#[test]
fn hardened_runtime_without_executable_memory_entitlements() {
    if std::env::var_os(CHILD).is_some() {
        // Check kernel state in the running process, not just codesign output.
        unsafe extern "C" {
            fn csops(pid: i32, ops: u32, address: *mut std::ffi::c_void, size: usize) -> i32;
        }
        let mut status = 0_u32;
        // SAFETY: CS_OPS_STATUS (0) writes one u32 to this live local value.
        assert_eq!(
            unsafe {
                csops(
                    std::process::id().try_into().unwrap(),
                    0,
                    std::ptr::from_mut(&mut status).cast(),
                    std::mem::size_of_val(&status),
                )
            },
            0
        );
        assert_ne!(status & 0x0001_0000, 0, "CS_RUNTIME must be set");

        let error = rama_js::JsRuntime::warm_up().unwrap_err();
        assert_eq!(error.kind(), rama_js::JsErrorKind::Setup);
        assert!(
            error
                .message()
                .contains("com.apple.security.cs.allow-unsigned-executable-memory")
        );
        #[cfg(feature = "js-interpreter")]
        {
            let blueprint =
                rama_js::JsRuntime::builder().with_backend(rama_js::JsBackend::Interpreter);
            #[cfg(feature = "js-disk-cache")]
            blueprint
                .warm_up_with_disk_cache(std::env::var_os(CHILD).unwrap(), "compiled")
                .unwrap();
            #[cfg(not(feature = "js-disk-cache"))]
            blueprint.warm_up().unwrap();
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            executor.block_on(async {
                let resolver = rama_pac::PacResolver::builder()
                    .with_backend(rama_js::JsBackend::Interpreter)
                    .build_static(representative::SCRIPT)
                    .unwrap();
                for (url, expected) in representative::CASES {
                    assert_eq!(
                        resolver
                            .find_proxy(&url.parse().unwrap())
                            .await
                            .unwrap()
                            .to_string(),
                        expected
                    );
                }
            });
            let mut runtime = rama_js::JsRuntime::builder()
                .with_backend(rama_js::JsBackend::Interpreter)
                .without_loop_iteration_limit()
                .with_execution_time_limit(std::time::Duration::from_millis(100))
                .build()
                .unwrap();
            let error = runtime.exec("while (true) {}").unwrap_err();
            assert_eq!(error.kind(), rama_js::JsErrorKind::LimitExceeded);
            assert!(runtime.is_poisoned());
        }
        return;
    }

    let temp = rama_utils::fs::tempdir().unwrap();
    let executable = temp.path().join("hardened-pac-test");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    // No --entitlements or --preserve-metadata: the new signature has no
    // allow-jit, unsigned-executable-memory, disable-library-validation, etc.
    let signed = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--timestamp=none",
        ])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let entitlements = Command::new("/usr/bin/codesign")
        .args(["--display", "--entitlements", ":-"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(entitlements.status.success());
    assert!(
        !String::from_utf8_lossy(&entitlements.stdout).contains("<key>"),
        "unexpected entitlements"
    );

    // Each invocation is a fresh process; with js-disk-cache the second also
    // exercises loading cached bytecode under hardened runtime enforcement.
    for _ in 0..2 {
        let mut child = Command::new(&executable)
            .args([
                "--exact",
                "hardened_runtime_without_executable_memory_entitlements",
                "--nocapture",
            ])
            .env(CHILD, temp.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut timed_out = false;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                timed_out = true;
                child.kill().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let child = child.wait_with_output().unwrap();
        assert!(
            !timed_out && child.status.success(),
            "hardened child failed (timeout={timed_out}): {child:?}"
        );
        assert!(
            String::from_utf8_lossy(&child.stdout).contains("1 passed"),
            "child did not run the test: {child:?}"
        );
    }
}
