//! Borrowed insertion recipes for the caller-owned initial field section.

use crate::profile::{
    capture::{
        headers::{HeaderCapture, HeaderCapturePolicy},
        http3::{H3ClientSequenceCapture, bootstrap::H3BootstrapCapture},
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        pseudo_headers::PseudoHeaderCapture,
    },
    format::canonical::{CanonicalValue, ProfileDataError, ValueId},
};
use rama_http::{
    Method, Version,
    proto::h3::{
        observation::{
            FieldRepresentation, InsertionFieldMatch, ObservedEncoderInstruction,
            ObservedFieldRepresentation,
        },
        qpack::{
            encoding::{InsertionNameEncoding, InsertionPreferences, InsertionScope},
            static_table,
        },
    },
};

/// One capacity and ordered literal/static-name insertions use native policy.
pub(super) fn capacity(
    bootstrap: &H3BootstrapCapture,
    sequence: &H3ClientSequenceCapture,
) -> Option<u64> {
    if !bootstrap.bindings.complete || bootstrap.bindings.stream_id != 0 {
        return None;
    }
    let [ObservedEncoderInstruction::Capacity { capacity }, tail @ ..] =
        sequence.encoder_instructions.as_ref()
    else {
        return None;
    };
    if *capacity == 0
        || *capacity >= 1 << 62
        || tail.is_empty()
        || bootstrap.validate_sequence(sequence).is_err()
    {
        return None;
    }
    let mut previous = None;
    for binding in &bootstrap.bindings.insertions {
        let InsertionFieldMatch::Unique { field_index } = binding.field else {
            return None;
        };
        if field_index >= bootstrap.fields
            || previous.is_some_and(|previous| field_index <= previous)
        {
            return None;
        }
        previous = Some(field_index);
    }
    for instruction in tail {
        match instruction {
            ObservedEncoderInstruction::InsertLiteral { name_bytes, .. } if *name_bytes != 0 => {}
            ObservedEncoderInstruction::InsertNameReference {
                is_static: true,
                index,
                ..
            } if usize::try_from(*index)
                .ok()
                .and_then(static_table::get)
                .is_some() => {}
            _ => return None,
        }
    }
    Some(*capacity)
}

pub(super) struct Insertions<'a> {
    bootstrap: &'a H3BootstrapCapture,
    sequence: &'a H3ClientSequenceCapture,
}

impl<'a> Insertions<'a> {
    pub(super) fn new(
        bootstrap: &'a H3BootstrapCapture,
        sequence: &'a H3ClientSequenceCapture,
        request: ValueId,
        method: &Method,
    ) -> Result<Self, ProfileDataError> {
        if capacity(bootstrap, sequence).is_none() {
            return Err(ProfileDataError::Unsupported(
                "captured QPACK initial insertions",
            ));
        }
        if request != bootstrap.request || *method != bootstrap.method {
            return Err(ProfileDataError::Invalid(
                "captured QPACK initial request identity",
            ));
        }
        Ok(Self {
            bootstrap,
            sequence,
        })
    }

    /// Check source associations before transport I/O, without supplying values.
    pub(super) fn validate_request(
        &self,
        request: &CanonicalValue,
    ) -> Result<(), ProfileDataError> {
        let limits = JointCaptureLimits::default();
        let joint = JointCapture::from_canonical(request, limits)?;
        let mut regular = None;
        let mut pseudo = None;
        for slot in &joint.slots {
            match slot.kind {
                CapturedSlotKind::Headers => {
                    let captured = HeaderCapture::from_canonical(
                        &slot.value,
                        &HeaderCapturePolicy::default(),
                    )?;
                    if captured.version != Version::HTTP_3 {
                        return Err(ProfileDataError::Invalid("initial QPACK request protocol"));
                    }
                    let offset = self
                        .fields()
                        .checked_sub(captured.fields.len())
                        .ok_or(ProfileDataError::Invalid("initial QPACK field count"))?;
                    for (index, field) in captured.fields.iter().enumerate() {
                        let insertion = self.for_field(
                            offset + index,
                            field.name.as_str().as_bytes(),
                            field.representation.as_ref(),
                        )?;
                        if insertion.is_some() && field.sensitive {
                            return Err(ProfileDataError::Unsupported(
                                "sensitive initial QPACK insertion",
                            ));
                        }
                    }
                    regular = Some(captured.fields.len());
                }
                CapturedSlotKind::PseudoHeaders => {
                    let captured =
                        PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes)?;
                    if captured.version != Version::HTTP_3 {
                        return Err(ProfileDataError::Invalid(
                            "initial QPACK pseudo-header protocol",
                        ));
                    }
                    captured.validate_method(&self.bootstrap.method)?;
                    for (index, field) in captured.fields.iter().enumerate() {
                        self.for_field(
                            index,
                            field.name.as_bytes(),
                            field.representation.as_ref(),
                        )?;
                    }
                    pseudo = Some(captured.fields.len());
                }
                _ => {}
            }
        }
        if regular
            .zip(pseudo)
            .and_then(|(regular, pseudo)| regular.checked_add(pseudo))
            != Some(self.fields())
        {
            return Err(ProfileDataError::Invalid("initial QPACK field count"));
        }
        Ok(())
    }

    pub(super) fn fields(&self) -> usize {
        self.bootstrap.fields
    }

    pub(super) fn for_field(
        &self,
        field_index: usize,
        name: &[u8],
        representation: Option<&ObservedFieldRepresentation>,
    ) -> Result<Option<InsertionPreferences>, ProfileDataError> {
        if field_index >= self.bootstrap.fields {
            return Err(ProfileDataError::Invalid(
                "captured QPACK initial field position",
            ));
        }
        if !representation.is_some_and(|field| {
            matches!(
                field.representation,
                FieldRepresentation::StaticIndex
                    | FieldRepresentation::LiteralName
                    | FieldRepresentation::LiteralStaticName
            )
        }) {
            return Err(ProfileDataError::Unsupported(
                "dynamic or missing initial QPACK field representation",
            ));
        }
        let bindings = &self.bootstrap.bindings.insertions;
        let Ok(index) =
            bindings.binary_search_by_key(&field_index, |binding| match binding.field {
                InsertionFieldMatch::Unique { field_index } => field_index,
                _ => usize::MAX,
            })
        else {
            return Ok(None);
        };
        let binding = &bindings[index];
        if representation.is_some_and(|field| field.never_index) {
            return Err(ProfileDataError::Unsupported(
                "sensitive initial QPACK insertion",
            ));
        }
        let preferences = match self
            .sequence
            .encoder_instructions
            .get(binding.instruction_index)
        {
            Some(ObservedEncoderInstruction::InsertLiteral {
                name_bytes,
                name_huffman,
                value_huffman,
                ..
            }) if *name_bytes == name.len() => InsertionPreferences {
                scope: InsertionScope::InitialSection,
                name_encoding: InsertionNameEncoding::Literal,
                name_huffman: Some(*name_huffman),
                value_huffman: Some(*value_huffman),
            },
            Some(ObservedEncoderInstruction::InsertNameReference {
                is_static: true,
                index,
                value_huffman,
                ..
            }) if usize::try_from(*index)
                .ok()
                .and_then(static_table::get)
                .is_some_and(|(expected, _)| expected == name) =>
            {
                InsertionPreferences {
                    scope: InsertionScope::InitialSection,
                    name_encoding: InsertionNameEncoding::StaticName(*index),
                    name_huffman: None,
                    value_huffman: Some(*value_huffman),
                }
            }
            _ => {
                return Err(ProfileDataError::Invalid(
                    "captured QPACK insertion name binding",
                ));
            }
        };
        Ok(Some(preferences))
    }
}
