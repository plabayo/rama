fn main() {
    println!("cargo:rerun-if-changed=src/oslog.c");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        cc::Build::new().file("src/oslog.c").compile("rama_oslog");
    }
}
