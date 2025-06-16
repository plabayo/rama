use std::env;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(nightly)");

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let output = Command::new(rustc)
        .arg("--version")
        .output()
        .expect("Failed to execute rustc");

    let version = String::from_utf8(output.stdout).expect("rustc output not valid UTF-8");

    if version.contains("nightly") {
        println!("cargo:rustc-cfg=nightly");
    }
}
