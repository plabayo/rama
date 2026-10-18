//! Transactional insertion planning for explicitly constrained dynamic references.
//!
//! Only the opt-in field-Base policy enters this path. Entries borrow current
//! fields until commit; the ordinary encoder keeps its original allocation path.

use super::insertion::{self, Insertion};
use super::{EncodeField, Encoder, FieldEncoding, InitialSection, QpackError, STREAM_CLASS_MASK};
use rama_http_types::proto::h3::qpack::{
    encoding::{InsertionPreferences, Representation},
    static_table,
};

fn after_base(representation: Representation) -> bool {
    matches!(
        representation,
        Representation::DynamicIndexAfterBase | Representation::LiteralDynamicNameAfterBase
    )
}

fn name_only(representation: Representation) -> bool {
    matches!(
        representation,
        Representation::LiteralDynamicName
            | Representation::LiteralDynamicNameBeforeBase
            | Representation::LiteralDynamicNameAfterBase
    )
}

pub(super) struct Plan<'a> {
    insertions: insertion::Plan<'a>,
    encodings: Vec<FieldEncoding>,
    base: u64,
}

impl<'a> Plan<'a> {
    pub(super) fn prepare<'preferences, N: AsRef<[u8]>, V: AsRef<[u8]>>(
        encoder: &Encoder,
        stream_id: u64,
        input: &'a [(EncodeField<'preferences, N, V>, FieldEncoding)],
    ) -> Result<Self, QpackError> {
        let mut insertions = Vec::new();
        let mut encodings = vec![FieldEncoding::LiteralName; input.len()];
        let mut base = 0;
        let was_blocking = encoder.is_stream_blocking(stream_id);
        let may_block =
            was_blocking || encoder.blocking_streams < encoder.config.max_blocked_streams;
        let cancelled = encoder.cancelled_through[(stream_id & STREAM_CLASS_MASK) as usize]
            .is_some_and(|cancelled| stream_id <= cancelled);
        let may_track = encoder.initial_section != InitialSection::Deferred
            && encoder.section_count < encoder.config.max_outstanding_sections
            && !cancelled;
        let start = encoder.table.insert_count();

        // Explicit insertions keep their supplied order, including initial-section
        // Bootstrap insertions. Referencing them later must respect the same Base.
        for (field, _) in input {
            if let Some(preferences) = field.preferences.and_then(|p| encoder.active_insertion(p)) {
                if field.never_index {
                    return Err(QpackError::EncodeFieldSectionLimit(
                        "explicit insertion unavailable for field Base policy",
                    ));
                }
                insertions.push(Insertion::prepare(
                    encoder,
                    field.name.as_ref(),
                    field.value.as_ref(),
                    preferences,
                )?);
            }
        }

        let mut references = 0usize;
        let mut protected = encoder.known_received_count;
        // Pre-Base references establish a lower bound. Post-Base references are
        // resolved afterward, independently of their emitted header positions.
        for post in [false, true] {
            for (ordinal, (field, _)) in input.iter().enumerate() {
                let preferences = field.preferences.copied().unwrap_or_default();
                let representation = preferences.representation;
                if after_base(representation) != post {
                    continue;
                }
                let name = field.name.as_ref();
                let value = field.value.as_ref();
                if !post {
                    match representation {
                        Representation::LiteralName => continue,
                        Representation::LiteralStaticName(index) => {
                            encodings[ordinal] = FieldEncoding::LiteralStaticName(index);
                            continue;
                        }
                        Representation::Automatic => {
                            if !field.never_index
                                && let Some(index) = static_table::find(name, value)
                            {
                                encodings[ordinal] = FieldEncoding::StaticIndex(index as u64);
                            } else if let Some(index) = static_table::find_name(name) {
                                encodings[ordinal] = FieldEncoding::LiteralStaticName(index as u64);
                            }
                            continue;
                        }
                        Representation::DynamicIndex | Representation::LiteralDynamicName => {
                            return Err(QpackError::EncodeFieldSectionLimit(
                                "field Base policy requires an explicit reference position",
                            ));
                        }
                        _ => (),
                    }
                }
                if field.never_index || !may_track {
                    return Err(QpackError::EncodeFieldSectionLimit(
                        "required dynamic reference unavailable",
                    ));
                }
                references = references
                    .checked_add(1)
                    .filter(|count| {
                        *count
                            <= encoder
                                .config
                                .max_outstanding_references
                                .saturating_sub(encoder.reference_count)
                    })
                    .ok_or(QpackError::StreamResourceLimit(
                        "field Base reference budget",
                    ))?;
                let only_name = name_only(representation);
                let wanted = (!only_name).then_some(value);
                let planned = insertions
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, insertion)| insertion.matches(name, wanted))
                    .map(|(index, _)| {
                        start
                            .checked_add(index as u64)
                            .ok_or(QpackError::EncodeFieldSectionLimit(
                                "field Base insertion count overflow",
                            ))
                    })
                    .transpose()?
                    .filter(|abs| {
                        (*abs < encoder.known_received_count || may_block)
                            && (!post || *abs >= base)
                    });
                let existing = if only_name {
                    encoder.table.find_name(name)
                } else {
                    encoder.table.find(name, value)
                }
                .filter(|abs| {
                    (*abs < encoder.known_received_count || may_block) && (!post || *abs >= base)
                });
                let abs = if let Some(abs) = planned.or(existing) {
                    if abs < start {
                        protected = protected.min(abs);
                    }
                    abs
                } else {
                    // A caller's explicitly ordered insertion cannot silently be
                    // duplicated to evade an incompatible post-Base position.
                    if post
                        && field
                            .preferences
                            .and_then(|p| encoder.active_insertion(p))
                            .is_some()
                    {
                        return Err(QpackError::EncodeFieldSectionLimit(
                            "explicit insertion order conflicts with field Base",
                        ));
                    }
                    if !may_block {
                        return Err(QpackError::StreamResourceLimit(
                            "field Base requires blocked-stream credit",
                        ));
                    }
                    let abs = start.checked_add(insertions.len() as u64).ok_or(
                        QpackError::EncodeFieldSectionLimit("field Base insertion count overflow"),
                    )?;
                    let insertion = Insertion::prepare(
                        encoder,
                        name,
                        if only_name { b"" } else { value },
                        InsertionPreferences::default(),
                    )?;
                    insertions.push(insertion);
                    abs
                };
                if !post {
                    base = base.max(
                        abs.checked_add(1)
                            .ok_or(QpackError::EncodeFieldSectionLimit("field Base overflow"))?,
                    );
                }
                encodings[ordinal] = if only_name {
                    FieldEncoding::LiteralDynamicName(abs)
                } else {
                    FieldEncoding::DynamicIndex(abs)
                };
            }
        }

        Ok(Self {
            insertions: insertion::Plan::prepare_batch(encoder, insertions, protected)?,
            encodings,
            base,
        })
    }

    pub(super) fn apply(
        self,
        encoder: &mut Encoder,
    ) -> Result<(Vec<FieldEncoding>, u64), QpackError> {
        self.insertions.apply(encoder)?;
        Ok((self.encodings, self.base))
    }
}
