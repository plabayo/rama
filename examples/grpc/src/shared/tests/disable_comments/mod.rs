use std::{fs, path::PathBuf};

rama::http::grpc::include_proto!("disable_comments");

#[test]
fn test() {
    let path = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("disable_comments.rs");
    let s = fs::read_to_string(&path).unwrap();
    assert!(
        !s.contains("This comment will be removed."),
        "file: {path:?}"
    );
    let mut count = 0_usize;
    let mut index = 0_usize;
    while let Some(found) = s[index..].find("This comment will not be removed.") {
        index += found + 1;
        count += 1;
    }
    assert_eq!(count, 4 + 3 + 3); // message: 4, client: 3, server: 3
}
