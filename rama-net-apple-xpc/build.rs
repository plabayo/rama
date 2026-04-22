use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env var"));

    if env::var("CARGO_CFG_TARGET_VENDOR").ok().as_deref() != Some("apple") {
        fs::write(out_dir.join("bindings.rs"), "// non-apple stub\n")
            .expect("write non-apple xpc bindings stub");
        return;
    }

    println!("cargo:rerun-if-changed=wrapper.h");

    bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-fblocks")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .formatter(bindgen::Formatter::Rustfmt)
        .allowlist_function("dispatch_queue_create")
        .allowlist_function("xpc_.*")
        .allowlist_var("XPC_.*")
        .allowlist_var("_xpc_.*")
        .allowlist_type("dispatch_queue_t")
        .allowlist_type("uuid_t")
        .allowlist_type("xpc_.*")
        .generate()
        .expect("generate xpc bindings")
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write xpc bindings");
}
