//! Request pseudo-header ordering without retained request values.

use rama_http::{
    Method, Version,
    proto::{
        h2::{PseudoHeader, PseudoHeaderOrder},
        h3::observation::ObservedFieldRepresentation,
    },
};
use serde::Serialize;

use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::{
            decode_representation, encode_representation, validate_representation,
            validate_static_binding,
        },
    },
    format::canonical::{
        CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError,
    },
};

/// All pseudo-header values are supplied by the request. QPACK metadata describes
/// this request's wire representation; dynamic references require its table context.
#[derive(Debug, Clone, Serialize)]
pub struct PseudoHeaderOccurrence {
    pub name: PseudoHeader,
    pub representation: Option<ObservedFieldRepresentation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PseudoHeaderCapture {
    pub completeness: ProfileCaptureCompleteness,
    pub version: Version,
    pub fields: Box<[PseudoHeaderOccurrence]>,
}

fn tag(name: PseudoHeader) -> u8 {
    match name {
        PseudoHeader::Method => 0,
        PseudoHeader::Scheme => 1,
        PseudoHeader::Authority => 2,
        PseudoHeader::Path => 3,
        PseudoHeader::Protocol => 4,
        PseudoHeader::Status => 5,
    }
}

fn invalid() -> ProfileDataError {
    ProfileDataError::Invalid("request pseudo-header shape")
}

impl PseudoHeaderCapture {
    /// Input is the validated request's exact order, with any H3 field metadata
    /// sliced from the same immutable request observation.
    pub fn capture(
        completeness: ProfileCaptureCompleteness,
        version: Version,
        order: &PseudoHeaderOrder,
        representations: Option<&[ObservedFieldRepresentation]>,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        completeness.require_complete("pseudo-header observation")?;
        if order.len() > 5 || order.len() > maximum_bytes {
            return Err(ProfileDataError::LimitExceeded("pseudo-header fields"));
        }
        if representations.is_some_and(|fields| fields.len() != order.len()) {
            return Err(ProfileDataError::Incomplete(
                "pseudo-header representations",
            ));
        }
        let capture = Self {
            completeness,
            version,
            fields: order
                .iter()
                .enumerate()
                .map(|(index, name)| PseudoHeaderOccurrence {
                    name,
                    representation: representations.map(|fields| fields[index]),
                })
                .collect(),
        };
        capture.canonical(maximum_bytes)?;
        Ok(capture)
    }

    /// Check method-dependent shapes against the flow rather than treating an
    /// observed CONNECT order as interchangeable with ordinary requests.
    pub fn validate_method(&self, method: &Method) -> Result<(), ProfileDataError> {
        let mut mask = 0u8;
        for field in &self.fields {
            mask |= 1 << tag(field.name);
            if field.name == PseudoHeader::Method
                && let Some(metadata) = field.representation
            {
                validate_static_binding(
                    field.name.as_bytes(),
                    Some(method.as_str().as_bytes()),
                    metadata,
                )?;
            }
        }
        let valid = if *method == Method::CONNECT {
            matches!(mask, 0b00101 | 0b11111)
        } else {
            matches!(mask, 0b01011 | 0b01111)
        };
        if !valid {
            return Err(ProfileDataError::Invalid("pseudo-header method shape"));
        }
        Ok(())
    }

    pub fn canonical(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        self.encode(maximum_bytes, false)
    }

    /// Compression choices and dynamic table indices do not multiply structural
    /// buckets. The complete sampled order still retains them for reanalysis.
    pub fn structural(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        self.encode(maximum_bytes, true)
    }

    fn encode(
        &self,
        maximum_bytes: usize,
        structural: bool,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.completeness
            .require_complete("pseudo-header observation")?;
        let version = match self.version {
            Version::HTTP_2 => 2,
            Version::HTTP_3 => 3,
            _ => return Err(ProfileDataError::Invalid("pseudo-header HTTP version")),
        };
        if self.fields.len() > 5 || self.fields.len() > maximum_bytes {
            return Err(ProfileDataError::LimitExceeded("pseudo-header fields"));
        }
        let mut mask = 0u8;
        for field in &self.fields {
            let bit = 1 << tag(field.name);
            if field.name == PseudoHeader::Status || mask & bit != 0 {
                return Err(invalid());
            }
            mask |= bit;
            if let Some(representation) = field.representation {
                validate_representation(self.version, representation)?;
                validate_static_binding(field.name.as_bytes(), None, representation)?;
            }
        }
        // A regular request has method/scheme/path (authority can be supplied by
        // Host); CONNECT has method/authority. Extended CONNECT has all five.
        if !matches!(mask, 0b01011 | 0b01111 | 0b00101 | 0b11111) {
            return Err(invalid());
        }
        let mut fields: Vec<_> = self.fields.iter().collect();
        if structural {
            fields.sort_unstable_by_key(|field| tag(field.name));
        }
        let mut writer = CanonicalWriter::new(
            if structural {
                CanonicalDomain::PseudoHeaderStructure
            } else {
                CanonicalDomain::PseudoHeaders
            },
            maximum_bytes,
        )?;
        writer.u8(version)?;
        writer.u8(self.completeness.tag())?;
        writer.u64(fields.len() as u64)?;
        for field in fields {
            writer.u8(tag(field.name))?;
            encode_representation(
                &mut writer,
                if structural {
                    None
                } else {
                    field.representation
                },
            )?;
        }
        Ok(writer.finish())
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        Self::decode(value, maximum_bytes, false)
    }

    pub(in crate::profile) fn decode(
        value: &CanonicalValue,
        maximum_bytes: usize,
        structural: bool,
    ) -> Result<Self, ProfileDataError> {
        let domain = if structural {
            CanonicalDomain::PseudoHeaderStructure
        } else {
            CanonicalDomain::PseudoHeaders
        };
        value.verify(domain, maximum_bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, domain)?;
        let version = match reader.u8()? {
            2 => Version::HTTP_2,
            3 => Version::HTTP_3,
            _ => return Err(ProfileDataError::Invalid("pseudo-header HTTP version")),
        };
        let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
        completeness.require_complete("pseudo-header observation")?;
        let count = reader.count(5)?;
        let mut fields = Vec::new();
        for _ in 0..count {
            let name = match reader.u8()? {
                0 => PseudoHeader::Method,
                1 => PseudoHeader::Scheme,
                2 => PseudoHeader::Authority,
                3 => PseudoHeader::Path,
                4 => PseudoHeader::Protocol,
                _ => return Err(invalid()),
            };
            fields.push(PseudoHeaderOccurrence {
                name,
                representation: decode_representation(&mut reader)?,
            });
        }
        reader.finish()?;
        let capture = Self {
            completeness,
            version,
            fields: fields.into(),
        };
        if capture.encode(maximum_bytes, structural)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid(
                "noncanonical pseudo-header capture",
            ));
        }
        Ok(capture)
    }
}

#[cfg(test)]
mod tests;
