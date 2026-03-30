use std::{env, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/client/linux/resolv_wrapper.h");

    let target_os = env::var("CARGO_CFG_TARGET_OS").ok();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").ok();
    let uses_res_nquery = matches!(
        (target_os.as_deref(), target_env.as_deref()),
        (Some("linux"), Some("gnu")) | (Some("freebsd" | "openbsd" | "netbsd"), _)
    );

    if !uses_res_nquery {
        return;
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("resolv_bindings.rs");

    let bindings = bindgen::Builder::default()
        .header("src/client/linux/resolv_wrapper.h")
        .allowlist_type("__res_state")
        .generate_comments(true)
        .derive_default(true)
        .layout_tests(false)
        .generate()
        .expect("generate libresolv bindings");

    bindings
        .write_to_file(out_path)
        .expect("write libresolv bindings");
}
