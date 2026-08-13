#![cfg(feature = "disk-cache")]

use std::fs;
use std::path::Path;

use rama_js::{JsErrorKind, JsRuntime};

#[test]
fn disk_cache_is_materialized_and_process_wide() -> Result<(), Box<dyn std::error::Error>> {
    let error = JsRuntime::warm_up_with_disk_cache("relative-root", "compiled").unwrap_err();
    assert_eq!(error.kind(), JsErrorKind::Setup);
    assert!(error.message().contains("root must be absolute"));

    let root = tempfile::tempdir()?;
    let error = JsRuntime::warm_up_with_disk_cache(root.path(), "../escape").unwrap_err();
    assert_eq!(error.kind(), JsErrorKind::Setup);
    assert!(error.message().contains("parent-directory"));

    #[cfg(unix)]
    {
        let outside = tempfile::tempdir()?;
        std::os::unix::fs::symlink(outside.path(), root.path().join("link"))?;
        let error = JsRuntime::warm_up_with_disk_cache(root.path(), "link/compiled").unwrap_err();
        assert_eq!(error.kind(), JsErrorKind::Setup);
        assert!(error.message().contains("escapes"));
    }

    let cache_dir = root.path().join("compiled");
    JsRuntime::warm_up_with_disk_cache(root.path(), "compiled")?;
    JsRuntime::warm_up_with_disk_cache(root.path(), "compiled")?;
    assert!(contains_nonempty_file(&cache_dir)?);

    let error = JsRuntime::warm_up_with_disk_cache(root.path(), "other").unwrap_err();
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
