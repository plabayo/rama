use std::fmt;

use rama_utils::collections::smallvec::{SmallVec, smallvec};
use rama_utils::macros::enums::enum_builder;

/// A single entry in a [`PermissionsPolicy`](super::PermissionsPolicy):
/// pairs a feature name with the origins allowed to use it.
///
/// Construct via [`Self::deny`], [`Self::allow`], or [`Self::allow_from`]
/// — those are the three shapes the spec actually defines.
///
/// Note: the [`PermissionsPolicy`](super::PermissionsPolicy) struct
/// itself has per-feature `with_deny_*` / `set_deny_*` shortcuts for
/// the deny-all case (the overwhelmingly common one); reach for these
/// constructors when you need an actual allow-list.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PermissionsPolicyDirective {
    pub name: PermissionsPolicyDirectiveName,
    /// Empty allow-list serialises to `name=()` — the deny-all form.
    /// The W3C spec has no `None` allow-list state, so the deny-all
    /// directive is just an empty list.
    pub allow_list: SmallVec<[AllowlistSource; 4]>,
}

impl PermissionsPolicyDirective {
    /// Deny-all directive: `name=()`.
    #[must_use]
    pub fn deny(name: impl Into<PermissionsPolicyDirectiveName>) -> Self {
        Self {
            name: name.into(),
            allow_list: SmallVec::new(),
        }
    }

    /// Single-source allow-list: `name=(source)`.
    #[must_use]
    pub fn allow(name: impl Into<PermissionsPolicyDirectiveName>, source: AllowlistSource) -> Self {
        Self {
            name: name.into(),
            allow_list: smallvec![source],
        }
    }

    /// Multi-source allow-list: `name=(src1 src2 …)`.
    #[must_use]
    pub fn allow_from(
        name: impl Into<PermissionsPolicyDirectiveName>,
        sources: impl IntoIterator<Item = AllowlistSource>,
    ) -> Self {
        Self {
            name: name.into(),
            allow_list: sources.into_iter().collect(),
        }
    }
}

impl fmt::Display for PermissionsPolicyDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=(", self.name.as_str())?;
        for (i, src) in self.allow_list.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(src, f)?;
        }
        f.write_str(")")
    }
}

enum_builder! {
    /// W3C-registered feature names plus an escape hatch for the long
    /// tail (proposed / draft / vendor-prefixed features).
    ///
    /// Comparisons are case-insensitive on the wire — the
    /// [`From<&str>`](Self) impl folds unrecognised tokens into the
    /// [`Unknown`](Self::Unknown) variant. The registry grows over
    /// time so callers should expect to land there for less-common
    /// features.
    @String
    pub enum PermissionsPolicyDirectiveName {
        // ---- W3C registry / MDN, in spec order roughly ----
        Accelerometer => "accelerometer",
        AmbientLightSensor => "ambient-light-sensor",
        AttributionReporting => "attribution-reporting",
        Autoplay => "autoplay",
        Battery => "battery",
        Bluetooth => "bluetooth",
        BrowsingTopics => "browsing-topics",
        Camera => "camera",
        ClipboardRead => "clipboard-read",
        ClipboardWrite => "clipboard-write",
        ComputePressure => "compute-pressure",
        CrossOriginIsolated => "cross-origin-isolated",
        DisplayCapture => "display-capture",
        EncryptedMedia => "encrypted-media",
        Fullscreen => "fullscreen",
        Gamepad => "gamepad",
        Geolocation => "geolocation",
        Gyroscope => "gyroscope",
        Hid => "hid",
        IdentityCredentialsGet => "identity-credentials-get",
        IdleDetection => "idle-detection",
        /// Deprecated FLoC opt-out. Kept for parsing legacy policies;
        /// the modern equivalent is `BrowsingTopics`.
        InterestCohort => "interest-cohort",
        LocalFonts => "local-fonts",
        Magnetometer => "magnetometer",
        Microphone => "microphone",
        Midi => "midi",
        OtpCredentials => "otp-credentials",
        Payment => "payment",
        PictureInPicture => "picture-in-picture",
        PublickeyCredentialsCreate => "publickey-credentials-create",
        PublickeyCredentialsGet => "publickey-credentials-get",
        ScreenWakeLock => "screen-wake-lock",
        Serial => "serial",
        SpeakerSelection => "speaker-selection",
        StorageAccess => "storage-access",
        SyncXhr => "sync-xhr",
        Unload => "unload",
        Usb => "usb",
        WebShare => "web-share",
        WindowManagement => "window-management",
        XrSpatialTracking => "xr-spatial-tracking",
    }
}

enum_builder! {
    /// Allowlist token shapes per the W3C Permissions Policy spec.
    ///
    /// The deny-all directive is represented by an empty
    /// [`PermissionsPolicyDirective::allow_list`] (no `None` variant
    /// here) so that the typed state and the wire form
    /// (`feature=()`) line up one-to-one.
    ///
    /// Specific origins (e.g. `"https://example.com"`) land in the
    /// auto-generated [`Unknown`](Self::Unknown) variant — use
    /// [`Self::origin`] to construct one with the required RFC 8941
    /// sf-string double-quoting baked in.
    @String
    pub enum AllowlistSource {
        /// `self` — same-origin only (no surrounding quotes on the
        /// wire, unlike CSP).
        SelfOrigin => "self",
        /// `*` — any origin.
        Wildcard => "*",
        /// `src` — legacy `<iframe allow=…>` token, lets the iframe
        /// inherit from its `src` attribute. Rare outside iframe
        /// context.
        Src => "src",
    }
}

impl AllowlistSource {
    /// Construct an origin allow-list source from a bare origin string
    /// — the surrounding RFC 8941 sf-string double-quotes are added
    /// for you. Pass `https://example.com`, not `"https://example.com"`.
    #[must_use]
    pub fn origin(origin: impl AsRef<str>) -> Self {
        Self::Unknown(format!("\"{}\"", origin.as_ref()).into())
    }

    /// Parse a single allowlist token. Returns `None` on a
    /// structurally invalid token — caller decides whether to drop
    /// the directive or just the token.
    pub(crate) fn from_token(s: &str) -> Option<Self> {
        if let Some(inner) = s.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            // Quoted sf-string origin. Keep the quotes on the stored
            // value so Display (macro-generated for `Unknown`) emits
            // the canonical wire form unchanged.
            if inner.is_empty() {
                None
            } else {
                Some(Self::Unknown(format!("\"{inner}\"").into()))
            }
        } else {
            // Bare keyword: macro-generated `From<&str>` matches
            // `self`/`*`/`src` case-insensitively and falls through
            // to `Unknown(String)` otherwise. We reject the latter —
            // only quoted strings are valid non-keyword tokens per
            // the spec.
            match Self::from(s) {
                Self::Unknown(_) => None,
                parsed => Some(parsed),
            }
        }
    }
}
