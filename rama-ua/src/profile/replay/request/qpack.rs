//! Translate captured QPACK choices into native field and section preferences.
//!
//! Dynamic reference families select the native per-field Base planner.
//! Missing metadata
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
    if fields.into_iter().any(|field| {
        matches!(
            field.representation,
            FieldRepresentation::DynamicIndex
                | FieldRepresentation::DynamicPostBaseIndex
                | FieldRepresentation::LiteralDynamicName
                | FieldRepresentation::LiteralPostBaseName
        )
    }) {
        *choice = Some(FieldSectionBase::FromFieldPreferences);
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
