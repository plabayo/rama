fn main() -> Result<(), Box<dyn std::error::Error>> {
    emit_nightly_cfg();
    build_apple_oslog_shim()
}

#[rustversion::nightly]
fn emit_nightly_cfg() {
    println!("cargo:rustc-cfg=nightly_error_messages");
}

#[rustversion::not(nightly)]
fn emit_nightly_cfg() {}

#[cfg(target_vendor = "apple")]
fn build_apple_oslog_shim() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_VENDOR").ok().as_deref() != Some("apple") {
        return Ok(());
    }

    const SHIM: &str = "src/telemetry/tracing/apple/oslog/shim.c";
    const HEADER: &str = "src/telemetry/tracing/apple/oslog/shim.h";

    println!("cargo:rerun-if-changed={SHIM}");
    println!("cargo:rerun-if-changed={HEADER}");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");

    cc::Build::new().file(SHIM).compile("rama_apple_oslog");
    Ok(())
}

#[cfg(not(target_vendor = "apple"))]
fn build_apple_oslog_shim() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_VENDOR").ok().as_deref() == Some("apple") {
        return Err("building rama for an Apple target requires an Apple host toolchain".into());
    }
    Ok(())
}
