//! Translate captured QPACK choices into native field and section preferences.
//!
//! Relative-only references can use the Required Insert Count as their Base.
//! Post-base evidence selects the native pre-insertion Base. Missing metadata
//! leaves the caller's native choice intact; table contents are always fresh.

use rama_http::proto::h3::{
    observation::{FieldRepresentation, ObservedFieldRepresentation},
    qpack::{FieldSectionBase, encoding::FieldPreferences},
};

use crate::profile::format::canonical::ProfileDataError;

pub(super) fn observe_base<'a>(
    choice: &mut Option<FieldSectionBase>,
    fields: impl IntoIterator<Item = &'a ObservedFieldRepresentation>,
) {
    for field in fields {
        match field.representation {
            FieldRepresentation::DynamicPostBaseIndex
            | FieldRepresentation::LiteralPostBaseName => {
                *choice = Some(FieldSectionBase::BeforeSection);
            }
            FieldRepresentation::DynamicIndex | FieldRepresentation::LiteralDynamicName
                if choice.is_none() =>
            {
                *choice = Some(FieldSectionBase::RequiredInsertCount);
            }
            _ => (),
        }
    }
}

/// Dynamic indexes are translated by the native codec, never copied into a fresh table.
pub(super) fn field_preferences(
    field: &ObservedFieldRepresentation,
) -> Result<FieldPreferences, ProfileDataError> {
    FieldPreferences::from_observed(field)
        .ok_or(ProfileDataError::Invalid("QPACK field preferences"))
}

pub(super) fn optional_preferences(
    field: Option<&ObservedFieldRepresentation>,
) -> Result<FieldPreferences, ProfileDataError> {
    field
        .map(field_preferences)
        .transpose()
        .map(Option::unwrap_or_default)
}
