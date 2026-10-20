use std::mem;

use rama_core::{
    extensions::{Extension, Extensions},
    telemetry::tracing,
};
use rama_http::{
    HeaderMap, HeaderName,
    header::{Entry, USER_AGENT},
    headers::ClientHint,
};

use crate::{
    HttpAgent, UserAgent,
    profile::replay::request::{
        LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport,
    },
};

#[cfg(feature = "tls")]
use crate::TlsAgent;

/// Request extension that keeps the caller's own `User-Agent` value while the
/// rest of the request is emulated.
///
/// Without a caller value the profile's value is sent. A kept value that
/// differs from the profile is reported as [`LoweredProfileItem::CallerUserAgent`].
#[derive(Debug, Clone, Copy, Default, Extension)]
#[extension(tags(ua))]
#[non_exhaustive]
pub struct PreserveHeaderUserAgent;

impl PreserveHeaderUserAgent {
    /// Create a new [`PreserveHeaderUserAgent`].
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Request extension that keeps the caller's own client hint values
/// (such as `Sec-CH-UA`) while the rest of the request is emulated.
///
/// Profile hints the caller did not send keep the profile's value. A kept value
/// that differs from the profile is reported as [`LoweredProfileItem::CallerClientHints`].
#[derive(Debug, Clone, Copy, Default, Extension)]
#[extension(tags(ua))]
#[non_exhaustive]
pub struct PreserveClientHints;

impl PreserveClientHints {
    /// Create a new [`PreserveClientHints`].
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// The caller asked for its own HTTP behaviour via [`HttpAgent::Preserve`].
pub(super) fn keeps_http(extensions: &Extensions) -> bool {
    extensions
        .get_ref::<UserAgent>()
        .and_then(UserAgent::http_agent)
        == Some(HttpAgent::Preserve)
}

/// The caller asked for its own TLS configuration via [`TlsAgent::Preserve`].
#[cfg(feature = "tls")]
pub(super) fn keeps_tls(extensions: &Extensions) -> bool {
    extensions
        .get_ref::<UserAgent>()
        .and_then(UserAgent::tls_agent)
        == Some(TlsAgent::Preserve)
}

/// Record a kept caller item once, so connection and request stages do not repeat it.
pub(super) fn report_kept(report: &mut ProfilePreservationReport, item: LoweredProfileItem) {
    let difference = ProfilePreservationDifference::LoweredProfileItem { item };
    if !report.differences.contains(&difference) {
        report.push(difference);
    }
}

/// Put caller values back where replay replaced them with profile values, for
/// the headers the caller asked to keep.
pub(super) fn keep_caller_fields(
    extensions: &Extensions,
    original: &HeaderMap,
    headers: &mut HeaderMap,
    report: &mut ProfilePreservationReport,
) {
    let user_agent = extensions.contains::<PreserveHeaderUserAgent>();
    let client_hints = extensions.contains::<PreserveClientHints>();
    if !user_agent && !client_hints {
        return;
    }
    let mut kept = Vec::new();
    let differences = mem::take(&mut report.differences).into_vec();
    let mut retained = Vec::with_capacity(differences.len());
    for difference in differences {
        let ProfilePreservationDifference::CallerValueReplaced { name, occurrence } = &difference
        else {
            retained.push(difference);
            continue;
        };
        let item = if user_agent && name == USER_AGENT {
            LoweredProfileItem::CallerUserAgent
        } else if client_hints && ClientHint::match_header_name(name).is_some() {
            LoweredProfileItem::CallerClientHints
        } else {
            retained.push(difference);
            continue;
        };
        if restore_caller_value(original, headers, name, *occurrence) {
            tracing::trace!(header.name = %name, occurrence, "caller header value kept");
            if !kept.contains(&item) {
                kept.push(item);
            }
        } else {
            retained.push(difference);
        }
    }
    report.differences = retained.into();
    for item in kept {
        report_kept(report, item);
    }
}

fn restore_caller_value(
    original: &HeaderMap,
    headers: &mut HeaderMap,
    name: &HeaderName,
    occurrence: u32,
) -> bool {
    let Some(caller) = original.get_all(name).iter().nth(occurrence as usize) else {
        return false;
    };
    let Entry::Occupied(mut entry) = headers.entry(name) else {
        return false;
    };
    let Some(value) = entry.iter_mut().nth(occurrence as usize) else {
        return false;
    };
    let sensitive = value.is_sensitive() || caller.is_sensitive();
    *value = caller.clone();
    value.set_sensitive(sensitive);
    true
}
