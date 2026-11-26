use std::{
    collections::BTreeMap,
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
        fs::{CreatedFilePermissions, OpenOptions, TempDir},
        octets::{kib, mib},
    },
};

use super::{
    CountedProfileSource, ReadBudget,
    profile_source::{ReadTally, SourcedProfile},
};
use crate::{
    cmd::ua::{CompactProfilesCommand, ExportProfilesCommand},
    utils::terminal::display_text,
};

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
    let staging = TempDir::create_sync(parent.join(name))?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
        .jail(staging.path())
        .open_sync("profiles.json")?;
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
fn report_exclusions(
    out: &mut impl io::Write,
    user_agents: &[Box<str>],
    excluded: usize,
) -> io::Result<()> {
    if user_agents.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "Profile export: {excluded} of {} excluded User-Agents found and left out.",
        user_agents.len(),
    )
}

/// Profiles the export read and then left out itself.
#[derive(Debug, Default)]
struct ExportLeftOut {
    legacy_only: Vec<Box<str>>,
    excluded: Vec<Box<str>>,
}

/// List the profiles behind a reason line when the operator asked for them.
fn list_profiles<'a>(
    out: &mut impl io::Write,
    verbose: bool,
    labels: impl IntoIterator<Item = &'a Box<str>>,
) -> io::Result<()> {
    if verbose {
        for label in labels {
            writeln!(out, "  {}", display_text(label))?;
        }
    }
    Ok(())
}

/// The cumulative analysis work bound an export reads under.
fn read_budget(command: &ExportProfilesCommand) -> ReadBudget {
    if command.embed {
        ReadBudget::Embedded
    } else {
        ReadBudget::Archive
    }
}

/// Account for every profile in the export window, so a smaller set says why.
fn report_export(
    out: &mut impl io::Write,
    command: &ExportProfilesCommand,
    read: &ReadTally,
    left_out: &ExportLeftOut,
) -> io::Result<()> {
    let verbose = command.verbose;
    let exported = read.read - left_out.legacy_only.len() - left_out.excluded.len();
    // Profiles past the count bound are neither counted nor read.
    let more = if read.over_count { "+" } else { "" };
    writeln!(
        out,
        "Profile export: {}{more} profiles in the {}-day window; {exported} exported, {}{more} left out.",
        read.listed,
        command.days,
        read.listed - exported,
    )?;
    if read.over_count {
        writeln!(
            out,
            "Profile export: profiles past --max-profiles {} left unread; raise --max-profiles to read them.",
            command.max_profiles,
        )?;
    }
    if !read.over_work_bound.is_empty()
        && let Some(bound) = read_budget(command).maximum_work()
    {
        writeln!(
            out,
            "Profile export: {} left out unread; the analysis work bound of {} MiB was reached.",
            read.over_work_bound.len(),
            bound / mib(1),
        )?;
        list_profiles(out, verbose, &read.over_work_bound)?;
    }
    if !read.over_profile_bound.is_empty() {
        let mut reasons = BTreeMap::<_, usize>::new();
        for (reason, _) in &read.over_profile_bound {
            *reasons.entry(*reason).or_default() += 1;
        }
        let mut line = format!(
            "Profile export: {} left out over a per-profile bound:",
            read.over_profile_bound.len()
        );
        for (index, (reason, count)) in reasons.into_iter().enumerate() {
            let separator = if index == 0 { " " } else { ", " };
            write!(line, "{separator}{reason} ({count})").map_err(io::Error::other)?;
        }
        writeln!(out, "{line}.")?;
        list_profiles(
            out,
            verbose,
            read.over_profile_bound.iter().map(|(_, label)| label),
        )?;
    }
    if !read.left_window.is_empty() {
        writeln!(
            out,
            "Profile export: {} left the window while the export ran.",
            read.left_window.len(),
        )?;
        list_profiles(out, verbose, &read.left_window)?;
    }
    if !left_out.legacy_only.is_empty() {
        writeln!(
            out,
            "Profile export: {} legacy-only profiles left out; --include-legacy keeps them.",
            left_out.legacy_only.len(),
        )?;
        list_profiles(out, verbose, &left_out.legacy_only)?;
    }
    report_exclusions(out, &command.exclude_user_agents, left_out.excluded.len())?;
    list_profiles(out, verbose, &left_out.excluded)?;
    if read.truncated > 0 {
        writeln!(
            out,
            "Profile export: {} profiles over their scope bound kept every flow, then the scopes seen in the most runs and days; {} scopes ({} stored) left out.",
            read.truncated, read.dropped_scopes, read.dropped_stored_scopes,
        )?;
    }
    if read.superseded_scopes > 0 {
        writeln!(
            out,
            "Profile export: {} stored scopes of {} profiles left out for a newer capture revision.",
            read.superseded_scopes, read.superseded_profiles,
        )?;
    }
    Ok(())
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
    // An archive must load under the loader's work bound; an embedded set bounds the analyses it retains.
    let mut source = CountedProfileSource::open(
        command.authorized,
        command.days,
        command.max_profiles,
        read_budget(&command),
    )
    .await?;
    let day = source.day();
    if command.import_legacy {
        super::legacy::import_from_environment(command.authorized).await?;
    }
    let include_legacy = command.include_legacy;
    let mut left_out = ExportLeftOut::default();
    if command.embed {
        let (authorized, horizon) = (command.authorized, command.days);
        let mut profiles = Vec::new();
        while let Some(SourcedProfile { label, entry }) = source.next().await? {
            if !include_legacy && legacy_only(entry.evidence.scopes.iter().map(|s| s.window.domain))
            {
                left_out.legacy_only.push(label);
                continue;
            }
            let analyzed = tokio::task::spawn_blocking(move || {
                entry.analyze(authorized, day, horizon, ProfileAnalysisLimits::default())
            })
            .await??;
            if excluded(&command.exclude_user_agents, &analyzed.analysis) {
                left_out.excluded.push(label);
                continue;
            }
            profiles.push(analyzed.analysis);
        }
        let (output, replace, max) = (
            command.output.clone(),
            command.replace,
            command.max_output_bytes,
        );
        tokio::task::spawn_blocking(move || publish_compiled(&output, replace, max, &profiles))
            .await??;
    } else {
        let (output, replace, authorized, days) = (
            command.output.clone(),
            command.replace,
            command.authorized,
            command.days,
        );
        let mut staged = tokio::task::spawn_blocking(move || {
            StagedExport::create(output, replace, authorized, day, days, limits)
        })
        .await??;
        while let Some(SourcedProfile { label, entry }) = source.next().await? {
            if !include_legacy && legacy_only(entry.evidence.scopes.iter().map(|s| s.window.domain))
            {
                left_out.legacy_only.push(label);
                continue;
            }
            staged = tokio::task::spawn_blocking(move || staged.write(entry)).await??;
        }
        tokio::task::spawn_blocking(move || staged.finish()).await??;
    }
    report_export(&mut io::stderr(), &command, source.tally(), &left_out)?;
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
    report_exclusions(
        &mut io::stderr(),
        &command.exclude_user_agents,
        kept - profiles.len(),
    )?;
    publish_compiled(
        &command.output,
        command.replace,
        command.max_output_bytes,
        &profiles,
    )
}

#[cfg(test)]
mod tests;
