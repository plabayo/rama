//! Copy sealed segments without stopping or reconfiguring the recorder.

use std::{fs, io, path::Path};

/// What a best-effort copy of a live recording captured.
#[derive(Debug, Default, serde::Serialize)]
#[non_exhaustive]
pub struct ExportReport {
    /// Basenames of complete segments copied to the destination.
    pub segments: Vec<String>,
    /// Bytes copied, excluding the manifest.
    pub bytes: u64,
    /// Segments evicted between listing the directory and opening the file.
    pub evicted: Vec<String>,
    /// Active files omitted because their contents are still changing.
    pub active_segments: usize,
}

/// Copy completed dial9 segments into a new diagnostics subdirectory.
///
/// The destination must not exist. This synchronous operation performs disk
/// I/O; call it on a blocking worker, not a runtime worker or recorder callback.
/// It neither claims nor deletes source segments and can be repeated into new
/// destinations. Files evicted before they can be opened are reported.
///
/// Active segments and thread-local buffered events are not a snapshot of the
/// present instant. Finalize the recorder first when the tail is required.
/// A live export may be empty. The returned report and `manifest.json` describe
/// exactly what was copied. Other I/O errors are returned; a partial destination
/// is retained for inspection and has no completed manifest.
///
/// Copies the standard rotating writer's `trace.N.bin` and `trace.N.bin.gz`
/// files. Applications using profiling sources must also collect any external
/// symbol artifacts their source requires.
pub fn export_completed_segments(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> io::Result<ExportReport> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    let mut entries = fs::read_dir(source)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    fs::create_dir(destination)?;
    let mut report = ExportReport::default();
    for entry in entries {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with("trace.") && name.ends_with(".bin.active") {
            report.active_segments += 1;
            continue;
        }
        let Some(index) = name.strip_prefix("trace.").and_then(|tail| {
            tail.strip_suffix(".bin")
                .or_else(|| tail.strip_suffix(".bin.gz"))
        }) else {
            continue;
        };
        if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let input = (|| {
            if !entry.file_type()?.is_file() {
                return Ok(None);
            }
            fs::File::open(entry.path()).map(Some)
        })();
        let mut input = match input {
            Ok(Some(file)) => file,
            Ok(None) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                report.evicted.push(name);
                continue;
            }
            Err(error) => return Err(error),
        };
        let mut output = fs::File::create_new(destination.join(&name))?;
        report.bytes = report
            .bytes
            .saturating_add(io::copy(&mut input, &mut output)?);
        report.segments.push(name);
    }
    let manifest = fs::File::create_new(destination.join("manifest.json"))?;
    serde_json::to_writer_pretty(manifest, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_exports_copy_sealed_files_without_claiming_or_overwriting() {
        let root = rama_utils::fs::tempdir().unwrap();
        let source = root.path().join("recording");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("trace.0.bin"), b"sealed").unwrap();
        fs::write(source.join("trace.1.bin.active"), b"changing").unwrap();
        fs::write(source.join("unrelated.bin"), b"unrelated").unwrap();
        for name in ["first", "second"] {
            let destination = root.path().join(name);
            let report = export_completed_segments(&source, &destination).unwrap();
            assert_eq!(report.segments, ["trace.0.bin"]);
            assert_eq!(report.bytes, 6);
            assert_eq!(report.active_segments, 1);
            assert_eq!(
                fs::read(destination.join("trace.0.bin")).unwrap(),
                b"sealed"
            );
            assert!(!destination.join("trace.1.bin.active").exists());
            export_completed_segments(&source, &destination).unwrap_err();
        }
        assert!(source.join("trace.0.bin").exists());
    }
}
