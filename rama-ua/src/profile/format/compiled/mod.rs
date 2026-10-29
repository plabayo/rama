//! Precompiled profile sets: analyzed profiles in a compact binary form.
//!
//! This is the form in which profiles are embedded. Loading decompresses and
//! decodes the analysis computed at export time; nothing is reanalyzed or rehashed,
//! so only data produced by Rama's own export belongs in this format. Archives
//! keep the evidence and are reanalyzed whenever they are loaded.
//!
//! A value whose bytes already exist elsewhere in the set, such as a component
//! capture also held by a joint capture, is stored once. Loaded values share
//! those bytes instead of each owning a copy.

use std::{collections::hash_map::Entry, io::Write as _};

use ahash::{HashMap, HashSet};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
};
use rama_utils::octets::mib;
use serde::{Deserialize, Serialize};

use self::compact::{CompiledProfile, compile_profile, load_profile};
use crate::profile::{
    analysis::profile::{AnalyzedProfile, PROFILE_CLASSIFIER_REVISION},
    capture::joint::joint_slot_values,
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
    model::ua::UserAgentProfile,
};

const MAGIC: &[u8; 7] = b"RAMAUAC";
/// Bumped whenever the encoding changes; sets in another version must be re-exported.
const FORMAT_VERSION: u8 = 2;
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
    bytes.starts_with(MAGIC)
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
    let profiles = without_repeated_values(
        profiles
            .iter()
            .map(compile_profile)
            .collect::<Result<_, _>>()?,
    );
    let encoded = postcard::to_allocvec(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: &profiles,
    })
    .context("encode compiled profile set")?;
    if encoded.len() > COMPILED_PROFILE_SET_BYTES {
        return Err(ProfileDataError::LimitExceeded("compiled profile set bytes").into());
    }
    let mut output = MAGIC.to_vec();
    output.push(FORMAT_VERSION);
    let mut encoder = zstd::Encoder::new(&mut output, LEVEL)?;
    encoder.window_log(WINDOW_LOG)?;
    encoder.long_distance_matching(true)?;
    encoder.include_checksum(true)?;
    // Decoders size their output from this instead of keeping a streaming window.
    encoder.set_pledged_src_size(Some(encoded.len() as u64))?;
    encoder.write_all(&encoded)?;
    encoder.finish()?;
    Ok(output)
}

/// Decode a precompiled profile set produced by [`encode_compiled_profiles`].
pub fn decode_compiled_profiles(bytes: &[u8]) -> Result<Vec<AnalyzedProfile>, BoxError> {
    let (&version, frame) = bytes
        .strip_prefix(MAGIC)
        .and_then(<[u8]>::split_first)
        .ok_or(ProfileDataError::Invalid("compiled profile set magic"))?;
    if version != FORMAT_VERSION {
        return Err(
            BoxError::from_static_str("unsupported compiled profile set format version")
                .context_field("version", version)
                .context_field("supported", FORMAT_VERSION),
        );
    }
    // One pass into an exactly sized buffer: a streaming decoder would also keep
    // the long window, roughly doubling peak memory on small machines.
    let size = zstd::zstd_safe::get_frame_content_size(frame)
        .ok()
        .flatten()
        .ok_or(ProfileDataError::Invalid(
            "compiled profile set content size",
        ))?;
    if size > COMPILED_PROFILE_SET_BYTES as u64 {
        return Err(ProfileDataError::LimitExceeded("compiled profile set bytes").into());
    }
    let mut encoded = Vec::with_capacity(size as usize);
    zstd::bulk::Decompressor::new()
        .context("init compiled profile decoder")?
        .decompress_to_buffer(frame, &mut encoded)
        .context("decompress compiled profile set")?;
    if encoded.len() as u64 != size {
        return Err(ProfileDataError::Invalid("compiled profile set content size").into());
    }
    let mut set: CompiledProfileSet<Vec<CompiledProfile>> =
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
    restore_repeated_values(&mut set.profiles)?;
    set.profiles.into_iter().map(load_profile).collect()
}

/// Canonical joint captures with the slots they hold, sharing the joint's buffer.
fn joint_slots(profile: &CompiledProfile) -> impl Iterator<Item = CanonicalValue> + '_ {
    profile
        .analysis
        .scopes
        .iter()
        .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
        .flat_map(|scope| scope.observations.variants.iter())
        .filter_map(|variant| variant.value.as_canonical())
        .filter(|value| !value.bytes.is_empty())
        .filter_map(|value| joint_slot_values(value).ok())
        .flatten()
}

/// Keep each distinct value's bytes once; a repeat keeps only its id.
fn without_repeated_values(mut profiles: Vec<CompiledProfile>) -> Vec<CompiledProfile> {
    let mut available: HashSet<ValueId> = profiles
        .iter()
        .flat_map(joint_slots)
        .map(|slot| slot.id)
        .collect();
    for profile in &mut profiles {
        for value in profile.values_mut() {
            if !available.insert(value.id) {
                value.bytes = Bytes::new();
            }
        }
    }
    profiles
}

/// Give every repeated value the bytes of the value or joint slot it repeats.
fn restore_repeated_values(profiles: &mut [CompiledProfile]) -> Result<(), BoxError> {
    let mut stored: HashMap<ValueId, Bytes> = HashMap::default();
    for profile in profiles.iter_mut() {
        for value in profile.values_mut() {
            if !value.bytes.is_empty() {
                store_value(&mut stored, value.id, value.bytes.clone())?;
            }
        }
    }
    for profile in profiles.iter() {
        for slot in joint_slots(profile) {
            // A stored component keeps its own buffer; repeats share the joint's.
            store_value(&mut stored, slot.id, slot.bytes)?;
        }
    }
    for profile in profiles.iter_mut() {
        for value in profile.values_mut() {
            if value.bytes.is_empty() {
                value.bytes = stored.get(&value.id).cloned().ok_or_else(|| {
                    BoxError::from(ProfileDataError::Invalid(
                        "compiled profile set value reference",
                    ))
                })?;
            }
        }
    }
    Ok(())
}

/// Keep the first bytes stored for `id`; one id never names two different values.
fn store_value(
    stored: &mut HashMap<ValueId, Bytes>,
    id: ValueId,
    bytes: Bytes,
) -> Result<(), BoxError> {
    match stored.entry(id) {
        Entry::Occupied(entry) if *entry.get() != bytes => {
            Err(ProfileDataError::Invalid("compiled profile set conflicting value").into())
        }
        Entry::Occupied(_) => Ok(()),
        Entry::Vacant(entry) => {
            entry.insert(bytes);
            Ok(())
        }
    }
}

/// Decode a precompiled profile set into emulation profiles.
pub fn try_load_compiled_profiles(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    Ok(decode_compiled_profiles(bytes)?
        .into_iter()
        .map(UserAgentProfile::from_captured)
        .collect())
}

mod compact;

#[cfg(test)]
mod tests;
