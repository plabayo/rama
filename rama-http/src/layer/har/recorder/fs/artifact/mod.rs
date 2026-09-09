use std::{
    fs::File as StdFile,
    path::{Path, PathBuf},
};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_utils::fs::{CreatedFilePermissions, OpenOptionsSync, TempPath, TempPathCleanup};
use tokio::fs::File;
use uuid::Uuid;

// An abandoned blocking result closes its file before scheduling path cleanup.
struct CreatedArtifact {
    file: StdFile,
    path: TempPath,
}

pub(super) async fn create_temp_file(
    dir: PathBuf,
    kind: &'static str,
    temp_cleanup: TempPathCleanup,
) -> Result<(TempPath, File), BoxError> {
    create(move || create_temp_file_sync(&dir, kind, temp_cleanup)).await
}

async fn create(
    creator: impl FnOnce() -> Result<(TempPath, StdFile), BoxError> + Send + 'static,
) -> Result<(TempPath, File), BoxError> {
    // Tokio's blocking file creation can finish after its caller is cancelled.
    // Create the cleanup guard in that same operation so the resulting file
    // remains owned even when nobody receives the blocking task's result.
    let artifact = tokio::task::spawn_blocking(move || {
        let (path, file) = creator()?;
        Ok::<_, BoxError>(CreatedArtifact { file, path })
    })
    .await
    .context("join private HAR artifact creation")??;
    Ok((artifact.path, File::from_std(artifact.file)))
}

pub(super) fn create_temp_file_sync(
    dir: &Path,
    kind: &'static str,
    temp_cleanup: TempPathCleanup,
) -> Result<(TempPath, StdFile), BoxError> {
    let file_name = format!(".rama-har-{kind}-{}", Uuid::new_v4().as_simple());
    let path = dir.join(&file_name);
    let file = OpenOptionsSync::new()
        .write(true)
        .create_new(true)
        .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
        .jail(dir)
        .open(file_name)
        .context("create private HAR artifact")?;
    // Destructuring callers drop the file before its path guard.
    Ok((TempPath::new(path, temp_cleanup), file))
}

#[cfg(test)]
mod tests;
