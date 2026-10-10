//! Streaming archive output shared by database and offline capture exports.

use std::io::{self, Write};

use ahash::{HashSet, HashSetExt as _};
use rama_core::error::BoxError;

use super::{ProfileArchiveEntry, ProfileArchiveLimits};
use crate::profile::{ProfileAnalysisLimits, ProfileDataError, ValueId};

#[derive(Debug)]
struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("profile archive byte limit exceeded"));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writes one validated profile at a time. Each operation consumes the writer,
/// so failed output cannot subsequently be finished. Callers stage the output
/// and publish it only after `finish` succeeds.
#[derive(Debug)]
pub struct ProfileArchiveWriter<W> {
    writer: LimitedWriter<W>,
    authorized: bool,
    day: u32,
    horizon: u32,
    limits: ProfileArchiveLimits,
    profiles: HashSet<ValueId>,
    remaining_work: usize,
}

impl<W: Write> ProfileArchiveWriter<W> {
    pub fn new(
        writer: W,
        authorized: bool,
        day: u32,
        horizon: u32,
        limits: ProfileArchiveLimits,
    ) -> Result<Self, BoxError> {
        limits.profile.window.retention.first_day(day, horizon)?;
        let mut writer = LimitedWriter {
            inner: writer,
            remaining: limits.bytes,
        };
        write!(
            writer,
            "{{\"format_version\":1,\"generated_day\":{day},\"horizon\":{horizon},\"profiles\":["
        )?;
        Ok(Self {
            writer,
            authorized,
            day,
            horizon,
            limits,
            profiles: HashSet::new(),
            remaining_work: limits.maximum_work,
        })
    }

    pub fn write_profile(mut self, entry: ProfileArchiveEntry) -> Result<Self, BoxError> {
        if self.profiles.len() >= self.limits.profiles {
            return Err(ProfileDataError::LimitExceeded("archive profiles").into());
        }
        let id = entry.evidence.profile.id;
        if self.profiles.contains(&id) {
            return Err(ProfileDataError::Invalid("duplicate archive profile").into());
        }
        let compiled = entry.analyze(
            self.authorized,
            self.day,
            self.horizon,
            ProfileAnalysisLimits {
                maximum_work: self.limits.profile.maximum_work.min(self.remaining_work),
                ..self.limits.profile
            },
        )?;
        self.remaining_work = self
            .remaining_work
            .checked_sub(compiled.analysis.work_units)
            .ok_or(ProfileDataError::LimitExceeded("archive analysis work"))?;
        if !self.profiles.is_empty() {
            self.writer.write_all(b",")?;
        }
        serde_json::to_writer(&mut self.writer, &compiled)?;
        self.profiles.insert(id);
        Ok(self)
    }

    pub fn finish(mut self) -> Result<W, BoxError> {
        self.writer.write_all(b"]}\n")?;
        self.writer.flush()?;
        Ok(self.writer.inner)
    }
}

#[cfg(test)]
mod tests;
