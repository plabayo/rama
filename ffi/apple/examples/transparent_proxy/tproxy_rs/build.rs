fn main() {
    println!("cargo:rerun-if-changed=src/oslog_private.c");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        cc::Build::new()
            .file("src/oslog_private.c")
            .compile("rama_oslog_private");
    }
}
