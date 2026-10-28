//! Bounded file and database loading for the profile viewer.

use super::display::{Row, push_row};
use crate::{cmd::serve::fp::CountedProfileSource, utils::terminal::display_text};
use rama::{
    error::{BoxError, BoxErrorExt as _},
    ua::profile::{
        analysis::profile::ProfileAnalysisLimits,
        format::{
            archive::{ProfileArchiveLimits, load_profile_archive_snapshot},
            compiled::{is_compiled_profile_set, try_load_compiled_profiles},
            compressed::{decompress_profile_archive, is_compressed_profile_archive},
            input::{try_load_embedded_profiles, try_load_profiles_json},
        },
        model::ua::UserAgentProfile,
    },
    utils::octets::mib,
};
use std::{fmt::Write as _, fs::File, io::Read as _, path::PathBuf};

/// Loaded summaries and the description of their file or database partition.
pub(super) struct Overview {
    pub(super) rows: Vec<Row>,
    pub(super) label: String,
}

pub(super) async fn load(
    path: Option<PathBuf>,
    authorized: bool,
    days: u32,
) -> Result<Overview, BoxError> {
    let mut source_label = path.as_ref().map_or_else(
        || {
            format!(
                "fingerprint database / {} / {} days",
                if authorized { "authorized" } else { "public" },
                days
            )
        },
        |path| display_text(&path.to_string_lossy()),
    );
    let rows = if let Some(path) = path {
        tokio::task::spawn_blocking(move || file_rows(path, authorized)).await??
    } else {
        let mut source =
            CountedProfileSource::open(authorized, days, ProfileArchiveLimits::default().profiles)
                .await?;
        let mut rows = Vec::new();
        let mut remaining = mib(64);
        let day = source.day();
        while let Some(entry) = source.next().await? {
            let row = tokio::task::spawn_blocking(move || {
                let entry =
                    entry.analyze(authorized, day, days, ProfileAnalysisLimits::default())?;
                Row::from_profile(&UserAgentProfile::from_captured(entry.analysis))
            })
            .await??;
            push_row(&mut rows, &mut remaining, row)?;
        }
        if source.truncated() > 0 {
            write!(
                source_label,
                " / {} profiles limited to their best-supported scopes",
                source.truncated(),
            )?;
        }
        if source.skipped() > 0 || source.limited() {
            write!(
                source_label,
                " / {} over-limit profiles skipped{}",
                source.skipped(),
                if source.limited() {
                    " / read budget reached"
                } else {
                    ""
                }
            )?;
        }
        rows
    };
    Ok(Overview {
        rows,
        label: source_label,
    })
}

/// Decoded captures of the profiles compiled into this build.
pub(super) fn embedded_json() -> Result<Vec<u8>, BoxError> {
    let profiles: Vec<_> = try_load_embedded_profiles()?
        .filter_map(|profile| profile.captured)
        .collect();
    super::inspect::profiles_json(profiles.iter().map(|profile| &**profile))
}

/// The profiles compiled into this build, as `rama send --emulate` uses them by default.
pub(super) fn embedded() -> Result<Overview, BoxError> {
    let mut rows = Vec::new();
    let mut remaining = mib(64);
    for profile in try_load_embedded_profiles()? {
        push_row(&mut rows, &mut remaining, Row::from_profile(&profile)?)?;
    }
    Ok(Overview {
        rows,
        label: "embedded profiles".to_owned(),
    })
}

pub(super) fn read_profile_file(path: PathBuf) -> Result<Vec<u8>, BoxError> {
    let limits = ProfileArchiveLimits::default();
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limits.bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limits.bytes {
        return Err(BoxError::from_static_str(
            "profile input byte limit exceeded",
        ));
    }
    if is_compressed_profile_archive(&bytes) {
        return decompress_profile_archive(&bytes, limits.bytes);
    }
    Ok(bytes)
}

fn file_rows(path: PathBuf, authorized: bool) -> Result<Vec<Row>, BoxError> {
    let limits = ProfileArchiveLimits::default();
    let bytes = read_profile_file(path)?;
    let profiles = if is_compiled_profile_set(&bytes) {
        try_load_compiled_profiles(&bytes)?
    } else if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
        load_profile_archive_snapshot(&bytes, authorized, limits)?
            .into_vec()
            .into_iter()
            .map(|entry| UserAgentProfile::from_captured(entry.analysis))
            .collect()
    } else {
        try_load_profiles_json(&bytes)?
    };
    let mut rows = Vec::new();
    let mut remaining = mib(64);
    for profile in profiles {
        push_row(&mut rows, &mut remaining, Row::from_profile(&profile)?)?;
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{ua::profile::format::input::UserAgentProfileInput, utils::fs::TempDir};
    #[test]
    fn viewer_loads_partial_profiles_and_escapes_terminal_controls() {
        let directory = TempDir::new().unwrap();
        let file = directory.path().join("profiles.json");
        std::fs::write(
            &file,
            serde_json::to_vec(&[UserAgentProfileInput::new("library/1.2\u{1b}[31m")]).unwrap(),
        )
        .unwrap();
        let rows = file_rows(file.clone(), false).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].label.contains('\u{1b}'));
        assert!(!rows[0].details.contains('\u{1b}'));
        assert!(rows[0].details.contains("none observed"));
        assert!(
            rows[0]
                .details
                .contains("original sample counts and freshness are unknown")
        );
        std::fs::write(&file, br#"[{"uastr":"library","h1_settings":"invalid"}]"#).unwrap();
        file_rows(file, false).unwrap_err();
    }

    #[test]
    fn viewer_lists_every_embedded_profile() {
        let overview = embedded().unwrap();
        assert_eq!(overview.label, "embedded profiles");
        assert_eq!(
            overview.rows.len(),
            try_load_embedded_profiles().unwrap().count()
        );
        assert!(!overview.rows.is_empty());
    }
}
