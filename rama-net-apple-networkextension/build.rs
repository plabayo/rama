use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env var"));

    if env::var("CARGO_CFG_TARGET_VENDOR").ok().as_deref() != Some("apple") {
        fs::write(out_dir.join("bindings.rs"), "// non-apple stub\n")
            .expect("write non-apple security bindings stub");
        return;
    }

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
        .allowlist_function("CFDataCreate")
        .allowlist_function("CFDataGetBytePtr")
        .allowlist_function("CFDataGetLength")
        .allowlist_function("CFDictionaryCreateMutable")
        .allowlist_function("CFDictionarySetValue")
        .allowlist_function("CFErrorCopyDescription")
        .allowlist_function("CFErrorGetCode")
        .allowlist_function("CFNumberCreate")
        .allowlist_function("CFRelease")
        .allowlist_function("CFRetain")
        .allowlist_function("CFStringCreateWithCString")
        .allowlist_function("CFStringGetCString")
        .allowlist_function("CFStringGetLength")
        .allowlist_function("CFStringGetMaximumSizeForEncoding")
        .allowlist_function("SecAccessControlCreateWithFlags")
        .allowlist_function("SecItemCopyMatching")
        .allowlist_function("SecKeyCopyPublicKey")
        .allowlist_function("SecKeyCreateDecryptedData")
        .allowlist_function("SecKeyCreateEncryptedData")
        .allowlist_function("SecKeyCreateRandomKey")
        .allowlist_var("kCFAllocatorDefault")
        .allowlist_var("kCFBooleanTrue")
        .allowlist_var("kCFNumberSInt32Type")
        .allowlist_var("kCFStringEncodingUTF8")
        .allowlist_var("kCFTypeDictionaryKeyCallBacks")
        .allowlist_var("kCFTypeDictionaryValueCallBacks")
        .allowlist_var("kSecAttrAccessControl")
        .allowlist_var("kSecAttrAccessGroup")
        .allowlist_var("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly")
        .allowlist_var("kSecAttrAccessibleWhenUnlockedThisDeviceOnly")
        .allowlist_var("kSecAttrApplicationTag")
        .allowlist_var("kSecAttrIsPermanent")
        .allowlist_var("kSecAttrKeyClass")
        .allowlist_var("kSecAttrKeyClassPrivate")
        .allowlist_var("kSecAttrKeySizeInBits")
        .allowlist_var("kSecAttrKeyType")
        .allowlist_var("kSecAttrKeyTypeECSECPrimeRandom")
        .allowlist_var("kSecAttrTokenID")
        .allowlist_var("kSecAttrTokenIDSecureEnclave")
        .allowlist_var("kSecClass")
        .allowlist_var("kSecClassKey")
        .allowlist_var("kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM")
        .allowlist_var("kSecPrivateKeyAttrs")
        .allowlist_var("kSecReturnRef")
        .allowlist_var("kSecUseDataProtectionKeychain")
        .allowlist_type("CF.*Ref")
        .allowlist_type("SecAccessControlRef")
        .allowlist_type("SecKeyRef")
        .generate()
        .expect("generate security bindings")
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write security bindings");
}
