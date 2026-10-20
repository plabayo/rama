use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{self, BufWriter, Read as _, Write as _},
    path::PathBuf,
};

use rama::{
    error::{BoxError, BoxErrorExt as _},
    tls::boring::core::rand::rand_bytes,
    ua::profile::format::{
        archive::{
            ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter,
            load_recorded_profile_archive_snapshot,
        },
        compressed::{CompressedProfileArchiveWriter, try_load_compressed_profiles},
    },
    utils::{
        fs::{CreatedFilePermissions, OpenOptionsSync, TempDir},
        octets::kib,
    },
};

use super::CountedProfileSource;
use crate::cmd::ua::{CompactProfilesCommand, ExportProfilesCommand};

/// Bounds the compressed bytes written to the staged file.
struct BoundedFile {
    file: File,
    remaining: usize,
}

impl io::Write for BoundedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other(
                "compressed profile archive byte limit exceeded",
            ));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

enum StagedOutput {
    Json(File),
    Compressed(CompressedProfileArchiveWriter<BoundedFile>),
}

impl io::Write for StagedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Json(file) => file.write(bytes),
            Self::Compressed(writer) => writer.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Json(file) => file.flush(),
            Self::Compressed(writer) => writer.flush(),
        }
    }
}

struct StagedExport {
    writer: ProfileArchiveWriter<BufWriter<StagedOutput>>,
    staging: TempDir,
    output: PathBuf,
    replace: bool,
    embed: bool,
}

impl StagedExport {
    /// With `embed`, `limits.bytes` bounds the compressed file while the
    /// decompressed archive stays within the default archive byte limit.
    fn create(
        output: PathBuf,
        replace: bool,
        embed: bool,
        authorized: bool,
        day: u32,
        horizon: u32,
        limits: ProfileArchiveLimits,
    ) -> Result<Self, BoxError> {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(".".as_ref());
        let mut nonce = [0; 16];
        rand_bytes(&mut nonce)?;
        let mut name = String::from(".rama-profiles-");
        for byte in nonce {
            write!(name, "{byte:02x}")?;
        }
        let staging = TempDir::create(parent.join(name))?;
        let file = OpenOptionsSync::new()
            .write(true)
            .create_new(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .jail(staging.path())
            .open("profiles.json")?;
        let (file, archive_limits) = if embed {
            let file = CompressedProfileArchiveWriter::new(BoundedFile {
                file,
                remaining: limits.bytes,
            })?;
            let archive_limits = ProfileArchiveLimits {
                bytes: ProfileArchiveLimits::default().bytes,
                ..limits
            };
            (StagedOutput::Compressed(file), archive_limits)
        } else {
            (StagedOutput::Json(file), limits)
        };
        let writer = ProfileArchiveWriter::new(
            BufWriter::with_capacity(kib(16), file),
            authorized,
            day,
            horizon,
            archive_limits,
        )?;
        let writer = if embed {
            writer.evidence_only()
        } else {
            writer
        };
        Ok(Self {
            writer,
            staging,
            output,
            replace,
            embed,
        })
    }

    fn write(mut self, entry: ProfileArchiveEntry) -> Result<Self, BoxError> {
        self.writer = self.writer.write_profile(entry)?;
        Ok(self)
    }

    fn finish(self) -> Result<(), BoxError> {
        let file = match self
            .writer
            .finish()?
            .into_inner()
            .map_err(|error| error.into_error())?
        {
            StagedOutput::Json(file) => file,
            StagedOutput::Compressed(writer) => writer.finish()?.file,
        };
        file.sync_all()?;
        drop(file);
        let source = self.staging.path().join("profiles.json");
        if self.embed {
            try_load_compressed_profiles(&fs::read(&source)?)?;
        }
        if self.replace {
            fs::rename(source, &self.output)?;
        } else {
            fs::hard_link(source, &self.output)?;
        }
        Ok(())
    }
}

pub(crate) async fn export_counted_profiles(
    command: ExportProfilesCommand,
) -> Result<(), BoxError> {
    let limits = ProfileArchiveLimits {
        bytes: command.max_output_bytes,
        profiles: command.max_profiles,
        ..ProfileArchiveLimits::default()
    };
    if command.max_profiles == 0 || command.max_output_bytes == 0 {
        return Err(BoxError::from_static_str(
            "profile export limits must be positive",
        ));
    }
    let mut source =
        CountedProfileSource::open(command.authorized, command.days, command.max_profiles).await?;
    let day = source.day();
    if command.import_legacy {
        super::legacy::import_from_environment(command.authorized).await?;
    }
    let mut staged = tokio::task::spawn_blocking(move || {
        StagedExport::create(
            command.output,
            command.replace,
            command.embed,
            command.authorized,
            day,
            command.days,
            limits,
        )
    })
    .await??;
    while let Some(entry) = source.next().await? {
        staged = tokio::task::spawn_blocking(move || staged.write(entry)).await??;
    }
    tokio::task::spawn_blocking(move || staged.finish()).await??;
    if source.skipped() > 0 || source.limited() {
        writeln!(
            io::stderr(),
            "Profile export: {} over-limit profiles skipped; read budget {}.",
            source.skipped(),
            if source.limited() {
                "reached"
            } else {
                "not reached"
            }
        )?;
    }
    if source.truncated() > 0 {
        writeln!(
            io::stderr(),
            "Profile export: {} profiles kept only the scopes seen in the most runs and days; {} stored scopes left out.",
            source.truncated(),
            source.dropped_scopes(),
        )?;
    }
    Ok(())
}

/// Rewrite an existing archive file as a compressed evidence-only archive.
pub(crate) fn compact_profile_archive(command: CompactProfilesCommand) -> Result<(), BoxError> {
    if command.max_input_bytes == 0 || command.max_output_bytes == 0 {
        return Err(BoxError::from_static_str(
            "profile compaction limits must be positive",
        ));
    }
    let mut bytes = Vec::new();
    File::open(&command.input)?
        .take(command.max_input_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > command.max_input_bytes {
        return Err(BoxError::from_static_str(
            "profile input byte limit exceeded",
        ));
    }
    let entries = load_recorded_profile_archive_snapshot(
        &bytes,
        ProfileArchiveLimits {
            bytes: command.max_input_bytes,
            ..ProfileArchiveLimits::default()
        },
    )?;
    drop(bytes);
    let first = entries
        .first()
        .ok_or_else(|| BoxError::from_static_str("profile archive has no profiles"))?;
    let authorized = entries
        .iter()
        .flat_map(|entry| entry.analysis.scopes.iter())
        .next()
        .is_some_and(|scope| scope.context.authorized);
    let mut staged = StagedExport::create(
        command.output,
        command.replace,
        true,
        authorized,
        first.analysis.current_day,
        first.analysis.horizon,
        ProfileArchiveLimits {
            bytes: command.max_output_bytes,
            ..ProfileArchiveLimits::default()
        },
    )?;
    for entry in entries {
        staged = staged.write(ProfileArchiveEntry {
            evidence: entry.evidence,
            sampler_seed: entry.sampler_seed,
        })?;
    }
    staged.finish()
}

#[cfg(test)]
mod tests;
