//! Decode and validate each overwrite field without discarding its neighbours.

use super::*;
use rama::ua::profile::ProfileDataError;
use serde_json::{Map, Value};

pub(super) struct DecodedFields {
    pub row: UserAgentProfileInput,
    pub invalid: usize,
    pub oversize: usize,
}

pub(super) fn decode_fields(
    values: &[Option<String>],
    key: &str,
    limits: StoreLimits,
) -> Result<DecodedFields, ProfileDataError> {
    if values.len() != FIELDS.len() {
        return Err(ProfileDataError::Invalid("legacy source field count"));
    }
    let mut decoded = DecodedFields {
        row: UserAgentProfileInput::new(key),
        invalid: 0,
        oversize: 0,
    };
    for (&name, text) in FIELDS.iter().zip(values) {
        let Some(text) = text else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            decoded.invalid += 1;
            continue;
        };
        if value.is_null() {
            continue;
        }
        let mut field = Map::new();
        field.insert("uastr".into(), Value::String(key.into()));
        field.insert(name.into(), value);
        let candidate = serde_json::from_value::<UserAgentProfileInput>(Value::Object(field))
            .map_err(|_error| ProfileDataError::Invalid("legacy field JSON"))
            .and_then(|field| {
                let mut candidate = decoded.row.clone();
                candidate
                    .merge_missing(field)
                    .map_err(|_error| ProfileDataError::Invalid("legacy field identity"))?;
                LegacyFieldCapture::prepare_row(&candidate, false, limits.capture)?;
                Ok(candidate)
            });
        match candidate {
            Ok(row) => decoded.row = row,
            Err(ProfileDataError::LimitExceeded(_)) => decoded.oversize += 1,
            Err(_) => decoded.invalid += 1,
        }
    }
    Ok(decoded)
}
