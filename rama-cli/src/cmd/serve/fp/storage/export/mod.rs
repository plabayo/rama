use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{self, BufWriter, Read as _, Write as _},
    path::{Path, PathBuf},
};

use rama::{
    error::{BoxError, BoxErrorExt as _},
    tls::boring::core::rand::rand_bytes,
    ua::profile::{
        analysis::profile::{AnalyzedProfile, ProfileAnalysisLimits},
        format::{
            archive::{
                ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter,
                load_recorded_profile_archive_snapshot,
            },
            canonical::CanonicalDomain,
            compiled::{
                decode_compiled_profiles, encode_compiled_profiles, is_compiled_profile_set,
            },
        },
    },
    utils::{
        fs::{CreatedFilePermissions, OpenOptionsSync, TempDir},
        octets::kib,
    },
};

use super::CountedProfileSource;
use crate::cmd::ua::{CompactProfilesCommand, ExportProfilesCommand};

/// A private directory next to the destination, so publishing is a rename.
fn stage(output: &Path) -> Result<(TempDir, File), BoxError> {
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
    Ok((staging, file))
}

/// Move the staged file into place; without `replace` an existing file is kept.
fn publish(staging: &TempDir, output: &Path, replace: bool) -> Result<(), BoxError> {
    let source = staging.path().join("profiles.json");
    if replace {
        core::cfg_select! {
            windows => {
                // Windows scanners can briefly hold the destination without delete
                // sharing. Retry only that transient error, keeping staging intact.
                for attempt in 0..=10 {
                    match fs::rename(&source, output) {
                        Ok(()) => break,
                        Err(error)
                            if attempt < 10 && error.kind() == io::ErrorKind::PermissionDenied =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            _ => {
                fs::rename(source, output)?;
            }
        }
    } else {
        fs::hard_link(source, output)?;
    }
    Ok(())
}

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
        let (staging, file) = stage(&output)?;
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

    fn write(mut self, mut entry: ProfileArchiveEntry) -> Result<Self, BoxError> {
        // Storage selects scopes by observation priority; archives use canonical IDs.
        entry
            .evidence
            .scopes
            .sort_unstable_by_key(|scope| scope.scope.id);
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
        publish(&self.staging, &self.output, self.replace)
    }
}

/// Whether a profile holds only imported legacy fields, which selection cannot draw.
fn legacy_only(domains: impl IntoIterator<Item = CanonicalDomain>) -> bool {
    let mut legacy = false;
    for domain in domains {
        match domain {
            CanonicalDomain::LegacyField => legacy = true,
            CanonicalDomain::Joint => return false,
            _ => {}
        }
    }
    legacy
}

/// Whether the operator left this profile out by its exact User-Agent.
fn excluded(user_agents: &[Box<str>], profile: &AnalyzedProfile) -> bool {
    profile
        .key
        .user_agent
        .as_deref()
        .is_some_and(|user_agent| user_agents.iter().any(|excluded| **excluded == *user_agent))
}

/// Report how many profiles the exclusions removed, so a stale exclusion is visible.
fn report_exclusions(user_agents: &[Box<str>], excluded: usize) -> io::Result<()> {
    if user_agents.is_empty() {
        return Ok(());
    }
    writeln!(
        io::stderr(),
        "Profile export: {excluded} of {} excluded User-Agents found and left out.",
        user_agents.len(),
    )
}

/// Publish analyzed profiles as the compiled set that rama-ua embeds.
fn publish_compiled(
    output: &Path,
    replace: bool,
    max_output_bytes: usize,
    profiles: &[AnalyzedProfile],
) -> Result<(), BoxError> {
    let encoded = encode_compiled_profiles(profiles)?;
    if encoded.len() > max_output_bytes {
        return Err(BoxError::from_static_str(
            "compiled profile set byte limit exceeded",
        ));
    }
    decode_compiled_profiles(&encoded)?;
    let (staging, mut file) = stage(output)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    publish(&staging, output, replace)
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
    let include_legacy = command.include_legacy;
    let mut legacy = 0usize;
    let mut excluded_count = 0usize;
    if command.embed {
        let (authorized, horizon) = (command.authorized, command.days);
        let mut profiles = Vec::new();
        while let Some(entry) = source.next().await? {
            if !include_legacy && legacy_only(entry.evidence.scopes.iter().map(|s| s.window.domain))
            {
                legacy += 1;
                continue;
            }
            let analyzed = tokio::task::spawn_blocking(move || {
                entry.analyze(authorized, day, horizon, ProfileAnalysisLimits::default())
            })
            .await??;
            if excluded(&command.exclude_user_agents, &analyzed.analysis) {
                excluded_count += 1;
                continue;
            }
            profiles.push(analyzed.analysis);
        }
        report_exclusions(&command.exclude_user_agents, excluded_count)?;
        let (output, replace, max) = (command.output, command.replace, command.max_output_bytes);
        tokio::task::spawn_blocking(move || publish_compiled(&output, replace, max, &profiles))
            .await??;
    } else {
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
            if !include_legacy && legacy_only(entry.evidence.scopes.iter().map(|s| s.window.domain))
            {
                legacy += 1;
                continue;
            }
            staged = tokio::task::spawn_blocking(move || staged.write(entry)).await??;
        }
        tokio::task::spawn_blocking(move || staged.finish()).await??;
    }
    if legacy > 0 {
        writeln!(
            io::stderr(),
            "Profile export: {legacy} legacy-only profiles left out; --include-legacy keeps them.",
        )?;
    }
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

/// Compile an existing archive file into the set that rama-ua embeds.
pub(crate) fn compact_profile_archive(command: &CompactProfilesCommand) -> Result<(), BoxError> {
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
    let analyzed: Vec<_> = if is_compiled_profile_set(&bytes) {
        decode_compiled_profiles(&bytes)?
    } else {
        load_recorded_profile_archive_snapshot(
            &bytes,
            ProfileArchiveLimits {
                bytes: command.max_input_bytes,
                ..ProfileArchiveLimits::default()
            },
        )?
        .into_iter()
        .map(|entry| entry.analysis)
        .collect()
    };
    drop(bytes);
    let profiles: Vec<_> = analyzed
        .into_iter()
        .filter(|profile| {
            command.include_legacy
                || !legacy_only(profile.scopes.iter().map(|scope| scope.observations.domain))
        })
        .collect();
    let kept = profiles.len();
    let profiles: Vec<_> = profiles
        .into_iter()
        .filter(|profile| !excluded(&command.exclude_user_agents, profile))
        .collect();
    report_exclusions(&command.exclude_user_agents, kept - profiles.len())?;
    publish_compiled(
        &command.output,
        command.replace,
        command.max_output_bytes,
        &profiles,
    )
}

#[cfg(test)]
mod tests;
