use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{self, BufWriter, Write as _},
    path::PathBuf,
};

use rama::{
    error::{BoxError, BoxErrorExt as _},
    tls::boring::core::rand::rand_bytes,
    ua::profile::{ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter},
    utils::{
        fs::{CreatedFilePermissions, OpenOptionsSync, TempDir},
        octets::kib,
    },
};

use super::CountedProfileSource;
use crate::cmd::ua::ExportProfilesCommand;

struct StagedExport {
    writer: ProfileArchiveWriter<BufWriter<File>>,
    staging: TempDir,
    output: PathBuf,
    replace: bool,
}

impl StagedExport {
    fn create(
        output: PathBuf,
        replace: bool,
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
        let writer = ProfileArchiveWriter::new(
            BufWriter::with_capacity(kib(16), file),
            authorized,
            day,
            horizon,
            limits,
        )?;
        Ok(Self {
            writer,
            staging,
            output,
            replace,
        })
    }

    fn write(mut self, entry: ProfileArchiveEntry) -> Result<Self, BoxError> {
        self.writer = self.writer.write_profile(entry)?;
        Ok(self)
    }

    fn finish(self) -> Result<(), BoxError> {
        let file = self
            .writer
            .finish()?
            .into_inner()
            .map_err(|error| error.into_error())?;
        file.sync_all()?;
        drop(file);
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
    Ok(())
}

#[cfg(test)]
mod tests;
