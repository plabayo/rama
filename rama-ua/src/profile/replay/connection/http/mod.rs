//! HTTP connection settings shared by UA modifiers and native connectors.

use crate::profile::model::http::HttpProfile;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_http::{
    Version,
    conn::{H2ClientContextParams, Http1ClientContextParams},
};

/// Apply a legacy profile's settings for the connection's negotiated HTTP version.
///
/// Settings are attached to `input` before the HTTP handshake consumes them.
/// Existing HTTP/2 connection parameters, including captured replay frames, are
/// retained unless the legacy profile supplies the corresponding setting.
pub fn apply_legacy_settings(
    input: &impl ExtensionsRef,
    version: Version,
    profile: &HttpProfile,
) -> Result<(), BoxError> {
    match version {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
            tracing::trace!("UA emulation add http1-specific settings",);
            input.extensions().insert(Http1ClientContextParams {
                title_header_case: profile
                    .h1
                    .as_ref()
                    .and_then(|h1| h1.settings.as_ref())
                    .ok_or_else(|| BoxError::from_static_str("missing HTTP/1 settings"))?
                    .title_case_headers,
            });
        }
        Version::HTTP_2 => {
            let settings = profile
                .h2
                .as_ref()
                .and_then(|h2| h2.settings.as_ref())
                .ok_or_else(|| BoxError::from_static_str("missing HTTP/2 settings"))?;
            let pseudo_headers = settings.http_pseudo_headers.clone();
            let early_frames = settings.early_frames.clone();
            let existing = input
                .extensions()
                .get_ref::<H2ClientContextParams>()
                .cloned();
            let replay_early_frames = existing
                .as_ref()
                .and_then(|params| params.replay_early_frames.clone());

            if pseudo_headers.is_some() || early_frames.is_some() || replay_early_frames.is_some() {
                tracing::trace!(
                    "user agent emulation: insert h2 settings into extensions: (pseudo headers = {:?} ; early frames: {:?})",
                    pseudo_headers,
                    early_frames,
                );
                let mut params = existing.unwrap_or_default();
                if let Some(pseudo_headers) = pseudo_headers {
                    params.headers_pseudo_order = Some(pseudo_headers);
                }
                if let Some(early_frames) = early_frames {
                    params.early_frames = Some(early_frames);
                }
                input.extensions().insert(params);
            }
        }
        Version::HTTP_3 => {
            tracing::debug!("legacy profile has no HTTP/3 connect settings; passing through");
        }
        // defensive forward-compat arm; native Version is currently exhaustive
        #[expect(
            unreachable_patterns,
            reason = "forward-compat fallback for future Version variants"
        )]
        _ => tracing::debug!(
            http.version = ?version,
            "UA emulation not supported for unknown http version: not applying anything version-specific",
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
