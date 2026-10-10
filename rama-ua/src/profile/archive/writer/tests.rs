use super::*;
use crate::profile::{ProfileEvidence, ProfileKey, load_profile_archive_snapshot};
use rama_utils::octets::kib;

fn entry(client: &str) -> ProfileArchiveEntry {
    ProfileArchiveEntry {
        evidence: ProfileEvidence {
            format_version: 1,
            profile: ProfileKey::new(client).canonical(kib(16)).unwrap(),
            scopes: Box::default(),
        },
        sampler_seed: [3; 32],
    }
}

fn write(limits: ProfileArchiveLimits) -> Result<Vec<u8>, BoxError> {
    ProfileArchiveWriter::new(Vec::new(), false, 100, 14, limits)?
        .write_profile(entry("library"))?
        .finish()
}

#[test]
fn streaming_archives_bound_complete_output_and_round_trip() {
    let limits = ProfileArchiveLimits::default();
    let output = write(limits).unwrap();
    let loaded = load_profile_archive_snapshot(&output, false, limits).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].analysis.key.client.as_ref(), "library");
    assert_eq!(loaded[0].analysis.current_day, 100);
    assert_eq!(
        write(ProfileArchiveLimits {
            bytes: output.len(),
            ..limits
        })
        .unwrap(),
        output
    );
    write(ProfileArchiveLimits {
        bytes: output.len() - 1,
        ..limits
    })
    .unwrap_err();
    write(ProfileArchiveLimits {
        profiles: 0,
        ..limits
    })
    .unwrap_err();
}

#[test]
fn streaming_archives_reject_duplicate_identity_and_invalid_evidence() {
    let limits = ProfileArchiveLimits::default();
    ProfileArchiveWriter::new(Vec::new(), false, 100, 14, limits)
        .unwrap()
        .write_profile(entry("library"))
        .unwrap()
        .write_profile(entry("library"))
        .unwrap_err();
    let mut invalid = entry("invalid");
    invalid.evidence.profile.id.0[0] ^= 1;
    ProfileArchiveWriter::new(Vec::new(), false, 100, 14, limits)
        .unwrap()
        .write_profile(invalid)
        .unwrap_err();
}

#[test]
fn archive_analysis_work_is_shared_between_profiles() {
    let first = entry("first");
    let second = entry("second");
    let work = first.evidence.profile.bytes.len() + second.evidence.profile.bytes.len();
    let limits = ProfileArchiveLimits {
        maximum_work: work,
        ..ProfileArchiveLimits::default()
    };
    let output = ProfileArchiveWriter::new(Vec::new(), false, 100, 14, limits)
        .unwrap()
        .write_profile(first.clone())
        .unwrap()
        .write_profile(second.clone())
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(
        load_profile_archive_snapshot(&output, false, limits)
            .unwrap()
            .len(),
        2
    );
    let limited = ProfileArchiveLimits {
        maximum_work: work - 1,
        ..limits
    };
    ProfileArchiveWriter::new(Vec::new(), false, 100, 14, limited)
        .unwrap()
        .write_profile(first)
        .unwrap()
        .write_profile(second)
        .unwrap_err();
    load_profile_archive_snapshot(&output, false, limited).unwrap_err();
}
