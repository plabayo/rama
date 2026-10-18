//! Link initial QPACK insertions to an existing capture-safe request recipe.
//!
//! The request identity names a canonical request joint, not raw header bytes.
//! Resolving it requires the same profile and connection context. This record
//! never retains a URI, credential value or a copy of the initial header block.

use rama_http::{
    Method,
    proto::h3::observation::{
        InsertionFieldMatch, ObservedEncoderBindings, ObservedInsertionBinding,
    },
};
use serde::Serialize;

use super::{H3ClientSequenceCapture, H3SequenceCaptureLimits};
use crate::profile::capture::headers::HeaderCapturePolicy;
use crate::profile::format::canonical::{
    CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError, ValueId,
};
use rama_http::proto::h3::observation::ObservedEncoderInstruction;

/// Bounds for one reference and its native field associations.
#[derive(Debug, Clone, Copy)]
pub struct H3BootstrapLimits {
    pub fields: usize,
    pub instructions: usize,
    pub bytes: usize,
}

impl Default for H3BootstrapLimits {
    fn default() -> Self {
        let sequence = H3SequenceCaptureLimits::default();
        Self {
            fields: HeaderCapturePolicy::default().fields.saturating_add(5),
            instructions: sequence.instructions,
            bytes: sequence.bytes,
        }
    }
}

/// An immutable association with the first request's reusable header recipe.
/// Field positions include pseudo-headers before regular headers, as on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct H3BootstrapCapture {
    pub request: ValueId,
    pub method: Method,
    pub fields: usize,
    pub bindings: ObservedEncoderBindings,
}

impl H3BootstrapCapture {
    pub fn canonical(&self, limits: H3BootstrapLimits) -> Result<CanonicalValue, ProfileDataError> {
        self.encode(limits, false)
    }

    /// Keep the exact recipe identity: a different first request cannot silently
    /// supply a connection's insertions, even if its header shape is similar.
    pub fn structural(
        &self,
        limits: H3BootstrapLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.encode(limits, true)
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        limits: H3BootstrapLimits,
    ) -> Result<Self, ProfileDataError> {
        Self::decode(value, limits, false)
    }

    pub(in crate::profile) fn decode(
        value: &CanonicalValue,
        limits: H3BootstrapLimits,
        structural: bool,
    ) -> Result<Self, ProfileDataError> {
        let domain = domain(structural);
        value.verify(domain, limits.bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, domain)?;
        let request = ValueId(
            reader
                .bytes(size_of::<ValueId>())?
                .try_into()
                .map_err(|_error| ProfileDataError::Invalid("H3 bootstrap request identity"))?,
        );
        let method = Method::from_bytes(reader.bytes(limits.bytes)?)
            .map_err(|_error| ProfileDataError::Invalid("H3 bootstrap method"))?;
        let fields = reader.count(limits.fields)?;
        let stream_id = reader.u64()?;
        let mut insertions = Vec::new();
        for _ in 0..reader.count(limits.instructions)? {
            let instruction_index = reader.count(limits.instructions)?;
            let insertion_index = reader.u64()?;
            let field = match reader.u8()? {
                0 => InsertionFieldMatch::Unique {
                    field_index: reader.count(fields)?,
                },
                1 => InsertionFieldMatch::Absent,
                2 => InsertionFieldMatch::Ambiguous,
                3 => InsertionFieldMatch::Evicted,
                4 => InsertionFieldMatch::Unavailable,
                _ => return Err(ProfileDataError::Invalid("H3 bootstrap field association")),
            };
            insertions.push(ObservedInsertionBinding {
                instruction_index,
                insertion_index,
                field,
            });
        }
        reader.finish()?;
        let capture = Self {
            request,
            method,
            fields,
            bindings: ObservedEncoderBindings {
                stream_id,
                insertions,
                complete: true,
            },
        };
        if capture.encode(limits, structural)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical H3 bootstrap"));
        }
        Ok(capture)
    }

    /// Bind every retained insertion to its actual encoder instruction. This
    /// establishes sequence coherence, not permission to reuse request values.
    pub fn validate_sequence(
        &self,
        sequence: &H3ClientSequenceCapture,
    ) -> Result<(), ProfileDataError> {
        let mut bindings = self.bindings.insertions.iter();
        let mut insertion_index = 0;
        for (instruction_index, instruction) in sequence.encoder_instructions.iter().enumerate() {
            if matches!(instruction, ObservedEncoderInstruction::Capacity { .. }) {
                continue;
            }
            let binding = bindings
                .next()
                .ok_or(ProfileDataError::Incomplete("H3 bootstrap instructions"))?;
            if binding.instruction_index != instruction_index
                || binding.insertion_index != insertion_index
            {
                return Err(ProfileDataError::Invalid(
                    "H3 bootstrap instruction identity",
                ));
            }
            insertion_index += 1;
        }
        if bindings.next().is_some() {
            return Err(ProfileDataError::Invalid("H3 bootstrap extra associations"));
        }
        Ok(())
    }

    fn encode(
        &self,
        limits: H3BootstrapLimits,
        structural: bool,
    ) -> Result<CanonicalValue, ProfileDataError> {
        let bindings = &self.bindings;
        if !bindings.complete {
            return Err(ProfileDataError::Incomplete("H3 bootstrap associations"));
        }
        if self.fields == 0
            || self.fields > limits.fields
            || bindings.insertions.len() > limits.instructions
        {
            return Err(ProfileDataError::LimitExceeded("H3 bootstrap elements"));
        }
        if bindings.stream_id >= 1 << 62 || bindings.stream_id & 3 != 0 {
            return Err(ProfileDataError::Invalid("H3 bootstrap request stream"));
        }
        let mut writer = CanonicalWriter::new(domain(structural), limits.bytes)?;
        writer.bytes(&self.request.0)?;
        writer.bytes(self.method.as_str().as_bytes())?;
        writer.u64(self.fields as u64)?;
        writer.u64(bindings.stream_id)?;
        writer.u64(bindings.insertions.len() as u64)?;
        let mut previous = None;
        for binding in &bindings.insertions {
            if binding.instruction_index >= limits.instructions
                || binding.insertion_index >= 1 << 62
                || previous.is_some_and(|(instruction, insertion)| {
                    binding.instruction_index <= instruction || binding.insertion_index <= insertion
                })
            {
                return Err(ProfileDataError::Invalid("H3 bootstrap insertion order"));
            }
            previous = Some((binding.instruction_index, binding.insertion_index));
            writer.u64(binding.instruction_index as u64)?;
            writer.u64(binding.insertion_index)?;
            match binding.field {
                InsertionFieldMatch::Unique { field_index } => {
                    if field_index >= self.fields {
                        return Err(ProfileDataError::Invalid("H3 bootstrap field position"));
                    }
                    writer.u8(0)?;
                    writer.u64(field_index as u64)?;
                }
                InsertionFieldMatch::Absent => writer.u8(1)?,
                InsertionFieldMatch::Ambiguous => writer.u8(2)?,
                InsertionFieldMatch::Evicted => writer.u8(3)?,
                InsertionFieldMatch::Unavailable => writer.u8(4)?,
            }
        }
        Ok(writer.finish())
    }
}

fn domain(structural: bool) -> CanonicalDomain {
    if structural {
        CanonicalDomain::H3BootstrapStructure
    } else {
        CanonicalDomain::H3Bootstrap
    }
}

#[cfg(test)]
mod tests;
