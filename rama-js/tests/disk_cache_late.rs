#![cfg(feature = "disk-cache")]

use rama_js::{JsErrorKind, JsRuntime};

#[test]
fn disk_cache_must_be_selected_before_plain_initialization()
-> Result<(), Box<dyn std::error::Error>> {
    JsRuntime::warm_up()?;

    let root = tempfile::tempdir()?;
    let error = JsRuntime::warm_up_with_disk_cache(root.path().join("compiled")).unwrap_err();
    assert_eq!(error.kind(), JsErrorKind::Setup);
    assert!(error.message().contains("already initialized"));
    Ok(())
}
