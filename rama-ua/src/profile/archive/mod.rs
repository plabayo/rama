//! Portable retained evidence. Stored analysis is diagnostic; imports reanalyze
//! the evidence under the caller's authorization partition and freshness window.

use ahash::{HashSet, HashSetExt as _};
use std::{fmt, marker::PhantomData};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_utils::octets::mib;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};

use super::{
    AnalyzedProfile, ProfileAnalysisLimits, ProfileDataError, ProfileEvidence,
    analyze_profile_evidence,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileArchiveEntry {
    pub evidence: ProfileEvidence,
    pub sampler_seed: [u8; 32],
}

/// A compiled entry retains the evidence needed to reproduce its analysis.
#[derive(Debug, Serialize)]
pub struct CompiledProfileArchiveEntry {
    pub analysis: AnalyzedProfile,
    pub evidence: ProfileEvidence,
    pub sampler_seed: [u8; 32],
}

impl ProfileArchiveEntry {
    pub fn analyze(
        self,
        authorized: bool,
        current_day: u32,
        horizon: u32,
        limits: ProfileAnalysisLimits,
    ) -> Result<CompiledProfileArchiveEntry, ProfileDataError> {
        let analysis = analyze_profile_evidence(
            &self.evidence,
            authorized,
            self.sampler_seed,
            current_day,
            horizon,
            limits,
        )?;
        Ok(CompiledProfileArchiveEntry {
            analysis,
            evidence: self.evidence,
            sampler_seed: self.sampler_seed,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProfileArchiveLimits {
    pub bytes: usize,
    pub profiles: usize,
    /// Cumulative retained bytes and normalized order visits across entries.
    pub maximum_work: usize,
    pub profile: ProfileAnalysisLimits,
}

impl Default for ProfileArchiveLimits {
    fn default() -> Self {
        Self {
            bytes: mib(64),
            profiles: 4096,
            maximum_work: mib(512),
            profile: ProfileAnalysisLimits::default(),
        }
    }
}

/// Load a complete versioned archive. No entry is returned after a validation
/// failure, and serialized derived rules never grant capabilities on import.
pub fn load_profile_archive(
    bytes: &[u8],
    authorized: bool,
    current_day: u32,
    horizon: u32,
    limits: ProfileArchiveLimits,
) -> Result<Box<[CompiledProfileArchiveEntry]>, BoxError> {
    let archive = parse_archive(bytes, limits)?;
    compile_entries(archive.profiles, authorized, current_day, horizon, limits)
}

/// Reproduce an exported snapshot at its recorded day and horizon. This keeps
/// offline and embedded profiles stable; live freshness checks use
/// [`load_profile_archive`] with an independently supplied current day.
pub fn load_profile_archive_snapshot(
    bytes: &[u8],
    authorized: bool,
    limits: ProfileArchiveLimits,
) -> Result<Box<[CompiledProfileArchiveEntry]>, BoxError> {
    let archive = parse_archive(bytes, limits)?;
    let day = archive
        .generated_day
        .ok_or(ProfileDataError::Incomplete("archive generation day"))?;
    let horizon = archive
        .horizon
        .ok_or(ProfileDataError::Incomplete("archive horizon"))?;
    limits.profile.window.retention.first_day(day, horizon)?;
    compile_entries(archive.profiles, authorized, day, horizon, limits)
}

struct ParsedProfileArchive {
    profiles: Vec<ProfileArchiveEntry>,
    generated_day: Option<u32>,
    horizon: Option<u32>,
}

fn parse_archive(
    bytes: &[u8],
    limits: ProfileArchiveLimits,
) -> Result<ParsedProfileArchive, BoxError> {
    if bytes.len() > limits.bytes {
        return Err(ProfileDataError::LimitExceeded("profile archive bytes").into());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let archive = ArchiveSeed {
        maximum: limits.profiles,
    }
    .deserialize(&mut deserializer)
    .context("deserialize profile archive")?;
    deserializer
        .end()
        .context("trailing profile archive data")?;
    Ok(archive)
}

fn compile_entries(
    entries: Vec<ProfileArchiveEntry>,
    authorized: bool,
    current_day: u32,
    horizon: u32,
    limits: ProfileArchiveLimits,
) -> Result<Box<[CompiledProfileArchiveEntry]>, BoxError> {
    let mut seen = HashSet::new();
    let mut remaining_work = limits.maximum_work;
    entries
        .into_iter()
        .map(|entry| {
            if !seen.insert(entry.evidence.profile.id) {
                return Err(ProfileDataError::Invalid("duplicate archive profile").into());
            }
            let entry = entry.analyze(
                authorized,
                current_day,
                horizon,
                ProfileAnalysisLimits {
                    maximum_work: limits.profile.maximum_work.min(remaining_work),
                    ..limits.profile
                },
            )?;
            remaining_work = remaining_work
                .checked_sub(entry.analysis.work_units)
                .ok_or(ProfileDataError::LimitExceeded("archive analysis work"))?;
            Ok(entry)
        })
        .collect()
}

struct ArchiveSeed {
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for ArchiveSeed {
    type Value = ParsedProfileArchive;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for ArchiveSeed {
    type Value = ParsedProfileArchive;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a versioned profile archive")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut version = None;
        let mut profiles = None;
        let mut generated_day = None;
        let mut horizon = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "format_version" => {
                    if version.is_some() {
                        return Err(de::Error::duplicate_field("format_version"));
                    }
                    let value = map.next_value::<u16>()?;
                    if value != 1 {
                        return Err(de::Error::custom("unsupported profile archive version"));
                    }
                    version = Some(value);
                }
                "generated_day" => {
                    if generated_day.is_some() {
                        return Err(de::Error::duplicate_field("generated_day"));
                    }
                    generated_day = Some(map.next_value::<u32>()?);
                }
                "horizon" => {
                    if horizon.is_some() {
                        return Err(de::Error::duplicate_field("horizon"));
                    }
                    horizon = Some(map.next_value::<u32>()?);
                }
                "profiles" => {
                    if profiles.is_some() {
                        return Err(de::Error::duplicate_field("profiles"));
                    }
                    profiles = Some(map.next_value_seed(EntriesSeed::<ProfileArchiveEntry> {
                        maximum: self.maximum,
                        marker: PhantomData,
                    })?);
                }
                _ => {
                    map.next_value::<de::IgnoredAny>()?;
                }
            }
        }
        version.ok_or_else(|| de::Error::missing_field("format_version"))?;
        Ok(ParsedProfileArchive {
            profiles: profiles.ok_or_else(|| de::Error::missing_field("profiles"))?,
            generated_day,
            horizon,
        })
    }
}
struct EntriesSeed<T> {
    maximum: usize,
    marker: PhantomData<T>,
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for EntriesSeed<T> {
    type Value = Vec<T>;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for EntriesSeed<T> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded profile entries")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut profiles = Vec::new();
        while profiles.len() < self.maximum {
            let Some(profile) = sequence.next_element()? else {
                return Ok(profiles);
            };
            profiles.push(profile);
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::custom("profile archive count limit exceeded"));
        }
        Ok(profiles)
    }
}

pub(super) fn read_bounded_profile_rows<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    maximum: usize,
) -> Result<Vec<T>, BoxError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let rows = EntriesSeed::<T> {
        maximum,
        marker: PhantomData,
    }
    .deserialize(&mut deserializer)
    .context("deserialize bounded profile rows")?;
    deserializer.end().context("trailing profile row data")?;
    Ok(rows)
}

#[cfg(test)]
mod tests;

mod writer;
pub use writer::ProfileArchiveWriter;
