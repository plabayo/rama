use std::env;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=resolv_wrapper_tests.c");
    println!("cargo::rerun-if-changed=../../src/client/linux/resolv_wrapper.c");
    println!("cargo::rerun-if-changed=../../src/client/linux/resolv_wrapper.h");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("gnu")
    {
        return;
    }
    println!("cargo::rerun-if-env-changed=RAMA_DEV_DENY_C_WARNINGS");
    cc::Build::new()
        .include("../../src/client/linux")
        .file("resolv_wrapper_tests.c")
        .warnings_into_errors(env::var("RAMA_DEV_DENY_C_WARNINGS").as_deref() == Ok("1"))
        .cargo_warnings(false)
        .compile("rama_dns_resolv_tests");
    // Declare the fixture's resolver dependency independently of rama-dns.
    println!("cargo::rustc-link-lib=resolv");
}
