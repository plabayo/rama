#![cfg(feature = "disk-cache")]

use std::fs;
use std::path::Path;

use rama_js::{JsErrorKind, JsRuntime};

#[test]
fn disk_cache_is_materialized_and_process_wide() -> Result<(), Box<dyn std::error::Error>> {
    let error = JsRuntime::warm_up_with_disk_cache("relative-cache").unwrap_err();
    assert_eq!(error.kind(), JsErrorKind::Setup);
    assert!(error.message().contains("must be absolute"));

    let root = tempfile::tempdir()?;
    let cache_dir = root.path().join("compiled");
    JsRuntime::warm_up_with_disk_cache(&cache_dir)?;
    JsRuntime::warm_up_with_disk_cache(&cache_dir)?;
    assert!(contains_nonempty_file(&cache_dir)?);

    let other_cache_dir = root.path().join("other");
    let error = JsRuntime::warm_up_with_disk_cache(other_cache_dir).unwrap_err();
    assert_eq!(error.kind(), JsErrorKind::Setup);
    assert!(error.message().contains("already initialized"));
    Ok(())
}

fn contains_nonempty_file(path: &Path) -> std::io::Result<bool> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if (metadata.is_dir() && contains_nonempty_file(&entry.path())?)
            || (metadata.is_file() && metadata.len() > 0)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
