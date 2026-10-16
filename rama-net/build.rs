fn main() {
    println!("cargo:rerun-if-changed=src/process/macos.c");
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
