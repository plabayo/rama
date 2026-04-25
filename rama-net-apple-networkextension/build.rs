fn main() {
    use std::{env, path::PathBuf};

    // Build scripts compile for the host, not the target. Use CARGO_CFG_TARGET_OS
    // to check the actual cross-compilation target. SecKeychain.h / cssmapple.h
    // (needed for System Keychain bindings) are macOS-only and unavailable on iOS.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env var"));

    println!("cargo:rerun-if-changed=wrapper.h");

    let sdk_path = env::var("SDKROOT")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let output = std::process::Command::new("xcrun")
                .args(["--sdk", "macosx", "--show-sdk-path"])
                .output()
                .expect("query macOS SDK path with xcrun");
            assert!(output.status.success(), "xcrun --show-sdk-path failed");
            String::from_utf8(output.stdout)
                .expect("decode xcrun SDK path as UTF-8")
                .trim()
                .to_owned()
        });

    bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-isysroot{sdk_path}"))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .formatter(bindgen::Formatter::Rustfmt)
        // CoreFoundation — only CFRelease is needed (system_keychain cleanup).
        .allowlist_function("CFRelease")
        .allowlist_var("kCFAllocatorDefault")
        // System Keychain (legacy file-based; the only keychain accessible from a sysext).
        .allowlist_function("SecKeychainOpen")
        .allowlist_function("SecKeychainFindGenericPassword")
        .allowlist_function("SecKeychainAddGenericPassword")
        .allowlist_function("SecKeychainItemDelete")
        .allowlist_function("SecKeychainItemFreeContent")
        .allowlist_function("SecKeychainItemModifyAttributesAndData")
        .allowlist_type("SecKeychainRef")
        .allowlist_type("SecKeychainItemRef")
        .allowlist_type("SecKeychainAttribute")
        .allowlist_type("SecKeychainAttributeList")
        .generate()
        .expect("generate security bindings")
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write security bindings");
}
