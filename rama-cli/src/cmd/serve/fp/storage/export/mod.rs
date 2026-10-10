use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use rama::{
    error::{BoxError, BoxErrorExt as _},
    tls::boring::core::rand::rand_bytes,
    ua::profile::{ProfileAnalysisLimits, ProfileArchiveEntry, ProfileEvidence},
    utils::{
        fs::{CreatedFilePermissions, OpenOptionsSync, TempDir},
        octets::kib,
    },
};

use super::CountedProfileSource;
use crate::cmd::ua::ExportProfilesCommand;

struct LimitedWriter {
    file: File,
    remaining: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("profile export byte limit exceeded"));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct StagedExport {
    writer: BufWriter<LimitedWriter>,
    staging: TempDir,
    output: PathBuf,
    replace: bool,
    profiles: usize,
}

impl StagedExport {
    fn create(
        output: PathBuf,
        replace: bool,
        maximum: usize,
        day: u32,
        horizon: u32,
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
        let mut writer = BufWriter::with_capacity(
            kib(16),
            LimitedWriter {
                file,
                remaining: maximum,
            },
        );
        write!(
            writer,
            "{{\"format_version\":1,\"generated_day\":{day},\"horizon\":{horizon},\"profiles\":["
        )?;
        Ok(Self {
            writer,
            staging,
            output,
            replace,
            profiles: 0,
        })
    }

    fn write(
        mut self,
        evidence: ProfileEvidence,
        seed: [u8; 32],
        authorized: bool,
        day: u32,
        horizon: u32,
        limits: ProfileAnalysisLimits,
    ) -> Result<Self, BoxError> {
        let compiled = ProfileArchiveEntry {
            evidence,
            sampler_seed: seed,
        }
        .analyze(authorized, day, horizon, limits)?;
        if self.profiles != 0 {
            self.writer.write_all(b",")?;
        }
        serde_json::to_writer(&mut self.writer, &compiled)?;
        self.profiles += 1;
        Ok(self)
    }

    fn finish(mut self) -> Result<(), BoxError> {
        self.writer.write_all(b"]}\n")?;
        self.writer.flush()?;
        self.writer.get_ref().file.sync_all()?;
        let source = self.staging.path().join("profiles.json");
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
    let limits = ProfileAnalysisLimits::default();
    let mut source =
        CountedProfileSource::open(command.authorized, command.days, command.max_profiles).await?;
    let day = source.day();
    if command.max_profiles == 0 || command.max_output_bytes == 0 {
        return Err(BoxError::from_static_str(
            "profile export limits must be positive",
        ));
    }
    let mut staged = tokio::task::spawn_blocking(move || {
        StagedExport::create(
            command.output,
            command.replace,
            command.max_output_bytes,
            day,
            command.days,
        )
    })
    .await??;
    while let Some(ProfileArchiveEntry {
        evidence,
        sampler_seed: seed,
    }) = source.next().await?
    {
        if staged.profiles >= command.max_profiles {
            return Err(BoxError::from_static_str(
                "profile export count limit exceeded",
            ));
        }
        staged = tokio::task::spawn_blocking(move || {
            staged.write(
                evidence,
                seed,
                command.authorized,
                day,
                command.days,
                limits,
            )
        })
        .await??;
    }
    tokio::task::spawn_blocking(move || staged.finish()).await?
}

#[cfg(test)]
mod tests;
