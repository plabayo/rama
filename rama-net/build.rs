fn main() {
    println!("cargo:rerun-if-changed=src/process/macos.c");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    // Cross-target documentation only needs the Rust declarations. The docs.rs
    // Linux host has no Apple SDK with which to compile the libproc shim.
    if std::env::var_os("DOCS_RS").is_some()
        && std::env::var("HOST").ok() != std::env::var("TARGET").ok()
    {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
        && std::env::var_os("CARGO_FEATURE_STD").is_some()
    {
        // Let the SDK define libproc's socket-info layout, as in Rama's Apple
        // NetworkExtension process shim. Rust only receives our small record.
        cc::Build::new()
            .file("src/process/macos.c")
            .compile("rama_net_process");
        println!("cargo:rustc-link-lib=proc");
    }
}
