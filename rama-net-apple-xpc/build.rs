#![expect(
    clippy::expect_used,
    reason = "build script: panicking on env/codegen failure aborts the build, which is the desired behavior"
)]

use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env var"));

    println!("cargo:rerun-if-changed=docsrs_bindings.rs");
    println!("cargo:rerun-if-env-changed=RAMA_UPDATE_DOCSRS_BINDINGS");
    if env::var_os("DOCS_RS").is_some()
        && env::var("HOST").expect("HOST env var") != env::var("TARGET").expect("TARGET env var")
    {
        fs::copy("docsrs_bindings.rs", out_dir.join("bindings.rs"))
            .expect("copy docs.rs xpc bindings");
        return;
    }

    if env::var("CARGO_CFG_TARGET_VENDOR").ok().as_deref() != Some("apple") {
        fs::write(out_dir.join("bindings.rs"), "// non-apple stub\n")
            .expect("write non-apple xpc bindings stub");
        return;
    }

    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-fblocks")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .formatter(bindgen::Formatter::Rustfmt)
        .allowlist_function("_Block_.*")
        .allowlist_function("dispatch_queue_create")
        .allowlist_function("xpc_.*")
        .allowlist_var("_NSConcreteStackBlock")
        .allowlist_var("XPC_.*")
        .allowlist_var("_xpc_.*")
        .allowlist_type("dispatch_queue_t")
        .allowlist_type("uuid_t")
        .allowlist_type("xpc_.*")
        .generate()
        .expect("generate xpc bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write xpc bindings");

    if env::var_os("RAMA_UPDATE_DOCSRS_BINDINGS").is_some() {
        bindings
            .write_to_file("docsrs_bindings.rs")
            .expect("write docs.rs xpc bindings");
    }
}
