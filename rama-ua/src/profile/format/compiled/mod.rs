//! Precompiled profile sets: analyzed profiles in a compact binary form.
//!
//! This is the form in which profiles are embedded. Loading decompresses and
//! decodes the analysis computed at export time; nothing is reanalyzed or rehashed,
//! so only data produced by Rama's own export belongs in this format. Archives
//! keep the evidence and are reanalyzed whenever they are loaded.

use std::io::{Read as _, Write as _};

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _};
use rama_utils::octets::mib;
use serde::{Deserialize, Serialize};

use crate::profile::{
    analysis::profile::{AnalyzedProfile, PROFILE_CLASSIFIER_REVISION},
    format::canonical::ProfileDataError,
    model::ua::UserAgentProfile,
};

const MAGIC: [u8; 8] = *b"RAMAUAC\x01";
// Fixed single-threaded parameters keep the output reproducible. The long window
// lets identical captures shared by several profiles compress to back-references.
const LEVEL: i32 = 19;
const WINDOW_LOG: u32 = 27;

/// Upper bound on a decoded profile set.
pub const COMPILED_PROFILE_SET_BYTES: usize = mib(512);

#[derive(Serialize, Deserialize)]
struct CompiledProfileSet<P> {
    classifier_revision: u16,
    profiles: P,
}

/// Whether `bytes` start like a precompiled profile set.
#[must_use]
pub fn is_compiled_profile_set(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC)
}

/// Encode analyzed profiles, for example from `rama ua export --embed`.
pub fn encode_compiled_profiles(profiles: &[AnalyzedProfile]) -> Result<Vec<u8>, BoxError> {
    if profiles.is_empty() {
        return Err(ProfileDataError::Incomplete("compiled profile set profiles").into());
    }
    if let Some(profile) = profiles
        .iter()
        .find(|profile| profile.classifier_revision != PROFILE_CLASSIFIER_REVISION)
    {
        return Err(
            BoxError::from_static_str("compiled profile classifier revision")
                .context_field("revision", profile.classifier_revision),
        );
    }
    let encoded = postcard::to_allocvec(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles,
    })
    .context("encode compiled profile set")?;
    if encoded.len() > COMPILED_PROFILE_SET_BYTES {
        return Err(ProfileDataError::LimitExceeded("compiled profile set bytes").into());
    }
    let mut output = MAGIC.to_vec();
    let mut encoder = zstd::Encoder::new(&mut output, LEVEL)?;
    encoder.window_log(WINDOW_LOG)?;
    encoder.long_distance_matching(true)?;
    encoder.include_checksum(true)?;
    encoder.write_all(&encoded)?;
    encoder.finish()?;
    Ok(output)
}

/// Decode a precompiled profile set produced by [`encode_compiled_profiles`].
pub fn decode_compiled_profiles(bytes: &[u8]) -> Result<Vec<AnalyzedProfile>, BoxError> {
    let frame = bytes
        .strip_prefix(&MAGIC)
        .ok_or(ProfileDataError::Invalid("compiled profile set magic"))?;
    let mut decoder = zstd::Decoder::with_buffer(frame).context("init compiled profile decoder")?;
    decoder
        .window_log_max(WINDOW_LOG)
        .context("init compiled profile decoder")?;
    let mut encoded = Vec::new();
    decoder
        .take(COMPILED_PROFILE_SET_BYTES as u64 + 1)
        .read_to_end(&mut encoded)
        .context("decompress compiled profile set")?;
    if encoded.len() > COMPILED_PROFILE_SET_BYTES {
        return Err(ProfileDataError::LimitExceeded("compiled profile set bytes").into());
    }
    let set: CompiledProfileSet<Vec<AnalyzedProfile>> =
        postcard::from_bytes(&encoded).context("decode compiled profile set")?;
    // Another classifier revision draws differently; stale data must be regenerated.
    if set.classifier_revision != PROFILE_CLASSIFIER_REVISION {
        return Err(
            BoxError::from_static_str("compiled profile classifier revision")
                .context_field("revision", set.classifier_revision),
        );
    }
    if set.profiles.is_empty() {
        return Err(ProfileDataError::Incomplete("compiled profile set profiles").into());
    }
    Ok(set.profiles)
}

/// Decode a precompiled profile set into emulation profiles.
pub fn try_load_compiled_profiles(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    Ok(decode_compiled_profiles(bytes)?
        .into_iter()
        .map(UserAgentProfile::from_captured)
        .collect())
}

#[cfg(test)]
mod tests;
