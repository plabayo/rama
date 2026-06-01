//! `Permissions-Policy` header — [W3C Permissions Policy](https://www.w3.org/TR/permissions-policy/).
//!
//! Comma-separated list of `feature=(allowlist)` entries. Built from
//! typed [`PermissionsPolicyDirective`]s; per-feature deny-all
//! shortcuts (`with_deny_camera`, `set_deny_microphone`, …) are
//! generated via [`rama_utils::macros::generate_set_and_with`].

mod directive;

pub use self::directive::{
    AllowlistSource, PermissionsPolicyDirective, PermissionsPolicyDirectiveName,
};

use std::fmt;

use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::macros::generate_set_and_with;

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Permissions-Policy` response header.
///
/// Adding a directive that already exists in the policy *replaces* its
/// allow-list in place (preserving declared order). The user agent
/// would treat the second occurrence as the winner per RFC 8941
/// structured-fields anyway, so we collapse to the caller-most-recent
/// value.
///
/// # Examples
///
/// Deny the common ambient-capability features:
///
/// ```
/// use rama_http_headers::PermissionsPolicy;
///
/// let pp = PermissionsPolicy::empty()
///     .with_deny_camera()
///     .with_deny_microphone()
///     .with_deny_geolocation()
///     .with_deny_payment()
///     .with_deny_usb()
///     .with_deny_interest_cohort();
///
/// let rendered = pp.to_string();
/// assert!(rendered.contains("camera=()"));
/// assert!(rendered.contains("interest-cohort=()"));
/// ```
///
/// Drop down to the generic surface for an allow-list or for a
/// proposed/draft feature that isn't yet modelled:
///
/// ```
/// use rama_http_headers::{
///     PermissionsPolicy, PermissionsPolicyDirective, PermissionsPolicyDirectiveName,
///     AllowlistSource,
/// };
///
/// let pp = PermissionsPolicy::empty()
///     .with(PermissionsPolicyDirective::allow(
///         PermissionsPolicyDirectiveName::Camera,
///         AllowlistSource::SelfOrigin,
///     ))
///     .with(PermissionsPolicyDirective::deny(
///         // Unknown / vendor / draft feature names land in the
///         // auto-generated `Unknown` variant via `From<&str>`.
///         PermissionsPolicyDirectiveName::from("x-vendor-experimental"),
///     ));
/// assert_eq!(pp.to_string(), "camera=(self), x-vendor-experimental=()");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionsPolicy {
    directives: Vec<PermissionsPolicyDirective>,
}

impl PermissionsPolicy {
    /// Empty policy. Build from this when adding directives one at a
    /// time.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            directives: Vec::new(),
        }
    }

    /// Iterate the policy's directives in encoding order.
    pub fn directives(&self) -> impl Iterator<Item = &PermissionsPolicyDirective> + '_ {
        self.directives.iter()
    }

    /// Generic escape hatch: append or replace a directive by name.
    /// If a directive with the same name exists, its allow-list is
    /// overwritten in place (order preserved); otherwise it's
    /// appended.
    #[must_use]
    pub fn with(mut self, directive: PermissionsPolicyDirective) -> Self {
        self.upsert(directive);
        self
    }

    /// In-place sibling of [`with`](Self::with).
    pub fn set(&mut self, directive: PermissionsPolicyDirective) -> &mut Self {
        self.upsert(directive);
        self
    }

    fn upsert(&mut self, directive: PermissionsPolicyDirective) {
        if let Some(slot) = self
            .directives
            .iter_mut()
            .find(|d| d.name == directive.name)
        {
            slot.allow_list = directive.allow_list;
        } else {
            self.directives.push(directive);
        }
    }

    // ---- per-directive deny-all shortcuts ----
    //
    // Each macro invocation generates both a `with_deny_*` (chaining,
    // takes ownership) and a `set_deny_*` (`&mut self`) form. Body
    // routes through `upsert` so all paths share one canonical write.

    generate_set_and_with! {
        /// Set `camera=()` (deny-all).
        pub fn deny_camera(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Camera,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `microphone=()` (deny-all).
        pub fn deny_microphone(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Microphone,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `geolocation=()` (deny-all).
        pub fn deny_geolocation(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Geolocation,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `payment=()` (deny-all).
        pub fn deny_payment(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Payment,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `usb=()` (deny-all).
        pub fn deny_usb(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Usb,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `interest-cohort=()` (deny-all). Opts the site out of
        /// the deprecated FLoC experiment. Pair with
        /// [`deny_browsing_topics`](Self::with_deny_browsing_topics)
        /// to also block Topics API, FLoC's shipped successor.
        pub fn deny_interest_cohort(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::InterestCohort,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `browsing-topics=()` (deny-all). Opts the site out of
        /// the Topics API (Privacy Sandbox).
        pub fn deny_browsing_topics(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::BrowsingTopics,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `attribution-reporting=()` (deny-all). Opts the site
        /// out of the Attribution Reporting API (Privacy Sandbox).
        pub fn deny_attribution_reporting(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::AttributionReporting,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `accelerometer=()` (deny-all).
        pub fn deny_accelerometer(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Accelerometer,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `ambient-light-sensor=()` (deny-all).
        pub fn deny_ambient_light_sensor(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::AmbientLightSensor,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `autoplay=()` (deny-all).
        pub fn deny_autoplay(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Autoplay,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `battery=()` (deny-all).
        pub fn deny_battery(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Battery,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `bluetooth=()` (deny-all).
        pub fn deny_bluetooth(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Bluetooth,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `display-capture=()` (deny-all).
        pub fn deny_display_capture(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::DisplayCapture,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `encrypted-media=()` (deny-all).
        pub fn deny_encrypted_media(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::EncryptedMedia,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `fullscreen=()` (deny-all).
        pub fn deny_fullscreen(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Fullscreen,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `gyroscope=()` (deny-all).
        pub fn deny_gyroscope(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Gyroscope,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `idle-detection=()` (deny-all).
        pub fn deny_idle_detection(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::IdleDetection,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `magnetometer=()` (deny-all).
        pub fn deny_magnetometer(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Magnetometer,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `midi=()` (deny-all).
        pub fn deny_midi(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::Midi,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `picture-in-picture=()` (deny-all).
        pub fn deny_picture_in_picture(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::PictureInPicture,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `publickey-credentials-get=()` (deny-all).
        pub fn deny_publickey_credentials_get(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::PublickeyCredentialsGet,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `screen-wake-lock=()` (deny-all).
        pub fn deny_screen_wake_lock(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::ScreenWakeLock,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `sync-xhr=()` (deny-all).
        pub fn deny_sync_xhr(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::SyncXhr,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `web-share=()` (deny-all).
        pub fn deny_web_share(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::WebShare,
            ));
            self
        }
    }
    generate_set_and_with! {
        /// Set `xr-spatial-tracking=()` (deny-all).
        pub fn deny_xr_spatial_tracking(mut self) -> Self {
            self.upsert(PermissionsPolicyDirective::deny(
                PermissionsPolicyDirectiveName::XrSpatialTracking,
            ));
            self
        }
    }
}

impl fmt::Display for PermissionsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, d) in self.directives.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            fmt::Display::fmt(d, f)?;
        }
        Ok(())
    }
}

impl TypedHeader for PermissionsPolicy {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::PERMISSIONS_POLICY
    }
}

impl HeaderDecode for PermissionsPolicy {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // The spec allows the header to be set multiple times — the
        // user agent intersects all returned policies. For round-
        // tripping we concatenate them preserving order, then upsert
        // so repeats collapse to the last-seen allow-list.
        let mut out = Self::empty();
        let mut any = false;
        for value in values {
            any = true;
            let s = value.to_str().map_err(|_err| Error::invalid())?;
            for raw in split_top_level_commas(s) {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let Some(directive) = parse_directive(trimmed) else {
                    // Drop malformed directives, keep the rest. The
                    // alternative would be to fail the whole header
                    // on a single bad token, which would be more
                    // surprising than logging it and moving on.
                    continue;
                };
                out.upsert(directive);
            }
        }
        if !any {
            return Err(Error::invalid());
        }
        Ok(out)
    }
}

impl HeaderEncode for PermissionsPolicy {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let rendered = self.to_string();
        match HeaderValue::try_from(rendered) {
            Ok(v) => values.extend(::std::iter::once(v)),
            Err(_) => {
                values.extend(::std::iter::once(HeaderValue::from_static("")));
            }
        }
    }
}

/// Split the header value on commas that are not inside `()`. The
/// allow-list is parenthesised, so a comma inside an allow-list isn't
/// the directive separator. (Tokens themselves don't contain commas,
/// and origin sf-strings don't either by spec.)
fn split_top_level_commas(s: &str) -> impl Iterator<Item = &str> {
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut out: Vec<&str> = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= s.len() {
        out.push(&s[start..]);
    }
    out.into_iter()
}

fn parse_directive(s: &str) -> Option<PermissionsPolicyDirective> {
    let eq = s.find('=')?;
    let name_raw = s[..eq].trim();
    let value_raw = s[eq + 1..].trim();
    if name_raw.is_empty() {
        return None;
    }
    let inner = value_raw
        .strip_prefix('(')
        .and_then(|t| t.strip_suffix(')'))?;
    // `From<&str>` on the @String enum is case-insensitive and falls
    // through to `Unknown(String)` for unrecognised tokens — exactly
    // the spec semantic (preserve declared name, even if not in the
    // typed registry).
    let name = PermissionsPolicyDirectiveName::from(name_raw);
    let allow_list = inner
        .split_whitespace()
        .filter_map(AllowlistSource::from_token)
        .collect();
    Some(PermissionsPolicyDirective { name, allow_list })
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn empty_renders_to_empty_string() {
        let pp = PermissionsPolicy::empty();
        assert_eq!(pp.to_string(), "");
    }

    #[test]
    fn keyword_shortcuts_render_deny_all_chain() {
        let pp = PermissionsPolicy::empty()
            .with_deny_camera()
            .with_deny_microphone()
            .with_deny_geolocation();
        assert_eq!(pp.to_string(), "camera=(), microphone=(), geolocation=()");
    }

    #[test]
    fn keyword_shortcuts_share_path_with_generic_with() {
        // The shortcut and the generic hatch should produce identical
        // typed state, which falls out of routing both through
        // `upsert`.
        let via_shortcut = PermissionsPolicy::empty().with_deny_camera();
        let via_generic = PermissionsPolicy::empty().with(PermissionsPolicyDirective::deny(
            PermissionsPolicyDirectiveName::Camera,
        ));
        assert_eq!(via_shortcut, via_generic);
    }

    #[test]
    fn set_mutates_in_place() {
        let mut pp = PermissionsPolicy::empty();
        pp.set_deny_camera();
        pp.set(PermissionsPolicyDirective::allow(
            PermissionsPolicyDirectiveName::Microphone,
            AllowlistSource::SelfOrigin,
        ));
        assert_eq!(pp.to_string(), "camera=(), microphone=(self)");
    }

    #[test]
    fn allow_list_self_and_origin_render() {
        let pp = PermissionsPolicy::empty().with(PermissionsPolicyDirective::allow_from(
            PermissionsPolicyDirectiveName::Camera,
            [
                AllowlistSource::SelfOrigin,
                AllowlistSource::Origin(Cow::Borrowed("https://example.com")),
            ],
        ));
        assert_eq!(pp.to_string(), r#"camera=(self "https://example.com")"#);
    }

    #[test]
    fn wildcard_and_src_render() {
        let pp_wild = PermissionsPolicy::empty().with(PermissionsPolicyDirective::allow(
            PermissionsPolicyDirectiveName::Camera,
            AllowlistSource::Wildcard,
        ));
        assert_eq!(pp_wild.to_string(), "camera=(*)");

        let pp_src = PermissionsPolicy::empty().with(PermissionsPolicyDirective::allow(
            PermissionsPolicyDirectiveName::Camera,
            AllowlistSource::Src,
        ));
        assert_eq!(pp_src.to_string(), "camera=(src)");
    }

    #[test]
    fn unknown_feature_via_other_round_trips() {
        // Use a vendor-prefixed name that's deliberately not in the
        // typed-variant set so the round-trip exercises the auto-
        // generated `Unknown` path. (The registry grows over time,
        // so any name we picked would risk becoming a real variant
        // in a future revision.)
        let pp = PermissionsPolicy::empty().with(PermissionsPolicyDirective::deny(
            PermissionsPolicyDirectiveName::from("x-vendor-experimental"),
        ));
        assert_eq!(pp.to_string(), "x-vendor-experimental=()");
        let parsed = test_decode::<PermissionsPolicy>(&[pp.to_string().as_str()]).expect("decode");
        assert_eq!(parsed, pp);
    }

    #[test]
    fn decode_parses_canonical_deny_all_chain() {
        let parsed = test_decode::<PermissionsPolicy>(&[
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
        ])
        .expect("decode");
        let names: Vec<&str> = parsed.directives().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "camera",
                "microphone",
                "geolocation",
                "payment",
                "usb",
                "interest-cohort",
            ]
        );
        for d in parsed.directives() {
            assert!(
                d.allow_list.is_empty(),
                "{} should be deny-all",
                d.name.as_str()
            );
        }
    }

    #[test]
    fn decode_preserves_declared_order() {
        let parsed = test_decode::<PermissionsPolicy>(&["usb=(), camera=()"]).expect("decode");
        let names: Vec<&str> = parsed.directives().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["usb", "camera"]);
    }

    #[test]
    fn decode_collapses_repeated_feature_last_wins() {
        let parsed =
            test_decode::<PermissionsPolicy>(&["camera=(), camera=(self)"]).expect("decode");
        let directives: Vec<_> = parsed.directives().collect();
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].name, PermissionsPolicyDirectiveName::Camera);
        assert_eq!(
            directives[0].allow_list.as_slice(),
            &[AllowlistSource::SelfOrigin]
        );
    }

    #[test]
    fn decode_handles_multiple_header_values() {
        let parsed = test_decode::<PermissionsPolicy>(&["camera=()", "microphone=()"])
            .expect("decode multi-value");
        let names: Vec<&str> = parsed.directives().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["camera", "microphone"]);
    }

    #[test]
    fn decode_tolerates_whitespace() {
        let parsed =
            test_decode::<PermissionsPolicy>(&["  camera = ( self )  ,  microphone = ( )  "])
                .expect("decode whitespace-heavy");
        let directives: Vec<_> = parsed.directives().collect();
        assert_eq!(directives.len(), 2);
        assert_eq!(
            directives[0].allow_list.as_slice(),
            &[AllowlistSource::SelfOrigin]
        );
        assert!(directives[1].allow_list.is_empty());
    }

    #[test]
    fn decode_case_insensitive_on_known_features() {
        let parsed = test_decode::<PermissionsPolicy>(&["Camera=()"]).expect("decode");
        let directives: Vec<_> = parsed.directives().collect();
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].name, PermissionsPolicyDirectiveName::Camera);
    }

    #[test]
    fn decode_mixed_sources() {
        let parsed = test_decode::<PermissionsPolicy>(&[r#"camera=(self "https://a.example" *)"#])
            .expect("decode");
        let directives: Vec<_> = parsed.directives().collect();
        assert_eq!(directives.len(), 1);
        assert_eq!(
            directives[0].allow_list.as_slice(),
            &[
                AllowlistSource::SelfOrigin,
                AllowlistSource::Origin(Cow::Owned("https://a.example".to_owned())),
                AllowlistSource::Wildcard,
            ]
        );
    }

    #[test]
    fn decode_empty_returns_error() {
        assert_eq!(test_decode::<PermissionsPolicy>(&[] as &[&str]), None);
    }

    #[test]
    fn newer_feature_names_round_trip_as_typed_variants() {
        // Regression for the post-ticket spec audit: these used to
        // fall through to `Other(...)`. They should now parse to
        // their canonical typed variants.
        for (token, expected) in [
            (
                "browsing-topics",
                PermissionsPolicyDirectiveName::BrowsingTopics,
            ),
            (
                "attribution-reporting",
                PermissionsPolicyDirectiveName::AttributionReporting,
            ),
            (
                "clipboard-read",
                PermissionsPolicyDirectiveName::ClipboardRead,
            ),
            (
                "clipboard-write",
                PermissionsPolicyDirectiveName::ClipboardWrite,
            ),
            (
                "compute-pressure",
                PermissionsPolicyDirectiveName::ComputePressure,
            ),
            ("gamepad", PermissionsPolicyDirectiveName::Gamepad),
            ("hid", PermissionsPolicyDirectiveName::Hid),
            ("serial", PermissionsPolicyDirectiveName::Serial),
            (
                "storage-access",
                PermissionsPolicyDirectiveName::StorageAccess,
            ),
            (
                "publickey-credentials-create",
                PermissionsPolicyDirectiveName::PublickeyCredentialsCreate,
            ),
            (
                "window-management",
                PermissionsPolicyDirectiveName::WindowManagement,
            ),
            ("local-fonts", PermissionsPolicyDirectiveName::LocalFonts),
            ("unload", PermissionsPolicyDirectiveName::Unload),
        ] {
            let raw = format!("{token}=()");
            let parsed = test_decode::<PermissionsPolicy>(&[raw.as_str()])
                .unwrap_or_else(|| panic!("decode {token}"));
            let directive = parsed.directives().next().expect("one directive");
            assert_eq!(directive.name, expected, "token `{token}` parsed wrong");
            assert_eq!(parsed.to_string(), raw, "round-trip changed `{token}`");
        }
    }

    #[test]
    fn topics_and_attribution_shortcuts_render_canonical_tokens() {
        let pp = PermissionsPolicy::empty()
            .with_deny_interest_cohort()
            .with_deny_browsing_topics()
            .with_deny_attribution_reporting();
        assert_eq!(
            pp.to_string(),
            "interest-cohort=(), browsing-topics=(), attribution-reporting=()",
        );
    }

    #[test]
    fn encode_round_trips_through_header_map() {
        let pp = PermissionsPolicy::empty()
            .with_deny_camera()
            .with_deny_microphone()
            .with(PermissionsPolicyDirective::allow_from(
                PermissionsPolicyDirectiveName::Geolocation,
                [
                    AllowlistSource::SelfOrigin,
                    AllowlistSource::Origin(Cow::Borrowed("https://example.com")),
                ],
            ));
        let map = test_encode(pp.clone());
        let raw = map
            .get(PermissionsPolicy::name())
            .expect("set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, pp.to_string());
        let parsed = test_decode::<PermissionsPolicy>(&[raw.as_str()]).expect("decode");
        assert_eq!(parsed, pp);
    }
}
