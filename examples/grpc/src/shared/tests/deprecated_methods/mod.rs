use std::{fs, path::PathBuf};

rama::http::grpc::include_proto!("deprecated_test");

#[test]
fn test() {
    let path = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("deprecated_test.rs");
    let s = fs::read_to_string(path)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(s.contains("#[deprecated] pub async fn deprecated("));
    assert!(!s.contains("#[deprecated] pub async fn not_deprecated("));
}
