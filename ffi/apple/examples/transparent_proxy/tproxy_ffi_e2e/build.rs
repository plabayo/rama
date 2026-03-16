use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let transparent_proxy_dir = manifest_dir
        .parent()
        .expect("transparent_proxy example dir")
        .to_path_buf();
    let apple_ffi_dir = transparent_proxy_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("apple ffi dir")
        .join("RamaAppleNetworkExtension");
    let header = apple_ffi_dir.join("Sources/RamaAppleNEFFI/include/rama_apple_ne_ffi.h");

    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-env-changed=RAMA_TPROXY_EXAMPLE_LIB_DIR");

    let lib_dir = env::var_os("RAMA_TPROXY_EXAMPLE_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| transparent_proxy_dir.join("tproxy_rs/target/debug"));

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=rama_tproxy_example");

    let bindings = bindgen::Builder::default()
        .header(header.display().to_string())
        .allowlist_function("rama_.*")
        .allowlist_type("Rama.*")
        .allowlist_var("RAMA_.*")
        .generate_comments(true)
        .derive_default(true)
        .layout_tests(false)
        .generate()
        .expect("generate ffi bindings");

    let out = PathBuf::from(env::var("OUT_DIR").expect("out dir")).join("bindings.rs");
    bindings.write_to_file(out).expect("write bindings");
}
