use std::ptr;

use rama_utils::str::arcstr::ArcStr;

use crate::{
    error::XpcError,
    ffi::{
        xpc_connection_set_peer_code_signing_requirement,
        xpc_connection_set_peer_entitlement_exists_requirement,
        xpc_connection_set_peer_entitlement_matches_value_requirement,
        xpc_connection_set_peer_lightweight_code_requirement,
        xpc_connection_set_peer_platform_identity_requirement,
        xpc_connection_set_peer_team_identity_requirement, xpc_connection_t,
    },
    message::XpcMessage,
    object::OwnedXpcObject,
    util::make_c_string,
};

/// A security constraint applied to an XPC connection before it is activated.
///
/// Set via [`XpcClientConfig`](crate::XpcClientConfig) or
/// [`XpcListenerConfig`](crate::XpcListenerConfig). The kernel enforces the constraint;
/// if the peer does not satisfy it, the connection is invalidated before any message is
/// delivered and an [`XpcConnectionError::PeerRequirementFailed`](crate::XpcConnectionError::PeerRequirementFailed)
/// is reported through the event stream.
///
/// See `<xpc/peer_requirement.h>` for the underlying API.
///
/// ## Choosing a variant
///
/// - Prefer [`LightweightCodeRequirement`](Self::LightweightCodeRequirement) on
///   macOS 13+ — it is the modern, flexible format and has the broadest Apple support.
/// - Use [`TeamIdentity`](Self::TeamIdentity) to accept any binary signed by your
///   Apple Developer team without specifying an exact binary.
/// - Use [`EntitlementExists`](Self::EntitlementExists) /
///   [`EntitlementMatchesValue`](Self::EntitlementMatchesValue) to enforce that the
///   peer binary carries specific entitlement keys baked into its provisioning profile.
/// - [`CodeSigning`](Self::CodeSigning) accepts a legacy code signing requirement string
///   (same syntax as `codesign -r`).
/// - [`PlatformIdentity`](Self::PlatformIdentity) is for Apple-internal binaries signed
///   with a platform identity; rarely needed outside of OS-level software.
#[derive(Debug, Clone)]
pub enum PeerSecurityRequirement {
    /// Legacy code signing requirement string (e.g. `"identifier com.example.app"`).
    ///
    /// Passed to `xpc_connection_set_peer_code_signing_requirement`.
    CodeSigning(ArcStr),
    /// Require the peer to be signed by the given Apple Developer team.
    ///
    /// `None` accepts any team-signed binary. Passed to
    /// `xpc_connection_set_peer_team_identity_requirement`.
    TeamIdentity(Option<ArcStr>),
    /// Require the peer to be signed with a platform (Apple OS) identity.
    ///
    /// `None` accepts any platform-signed binary. Passed to
    /// `xpc_connection_set_peer_platform_identity_requirement`.
    PlatformIdentity(Option<ArcStr>),
    /// Require the peer binary to carry the named entitlement key.
    ///
    /// Passed to `xpc_connection_set_peer_entitlement_exists_requirement`.
    EntitlementExists(ArcStr),
    /// Require the peer binary to carry the named entitlement with a specific value.
    ///
    /// Passed to `xpc_connection_set_peer_entitlement_matches_value_requirement`.
    EntitlementMatchesValue {
        entitlement: ArcStr,
        value: XpcMessage,
    },
    /// Modern lightweight code requirement (macOS 13+).
    ///
    /// The `value` must be a `Dictionary` encoding the LCR structure.
    /// Passed to `xpc_connection_set_peer_lightweight_code_requirement`.
    LightweightCodeRequirement(XpcMessage),
}

impl PeerSecurityRequirement {
    pub(crate) fn apply(&self, connection: xpc_connection_t) -> Result<(), XpcError> {
        // SAFETY for all arms: `connection` is a valid, non-null xpc_connection_t passed
        // in by the caller (always sourced from OwnedXpcObject). String arguments are
        // null-terminated C strings from make_c_string or null (accepted by the APIs).
        // XPC object arguments are valid retained objects from OwnedXpcObject::from_message.
        let result = match self {
            Self::CodeSigning(requirement) => {
                let requirement = make_c_string(requirement)?;
                unsafe {
                    xpc_connection_set_peer_code_signing_requirement(
                        connection,
                        requirement.as_ptr(),
                    )
                }
            }
            Self::TeamIdentity(signing_identifier) => {
                let signing_identifier = signing_identifier
                    .as_deref()
                    .map(make_c_string)
                    .transpose()?;
                unsafe {
                    xpc_connection_set_peer_team_identity_requirement(
                        connection,
                        signing_identifier
                            .as_ref()
                            .map_or(ptr::null(), |value| value.as_ptr()),
                    )
                }
            }
            Self::PlatformIdentity(signing_identifier) => {
                let signing_identifier = signing_identifier
                    .as_deref()
                    .map(make_c_string)
                    .transpose()?;
                unsafe {
                    xpc_connection_set_peer_platform_identity_requirement(
                        connection,
                        signing_identifier
                            .as_ref()
                            .map_or(ptr::null(), |value| value.as_ptr()),
                    )
                }
            }
            Self::EntitlementExists(entitlement) => {
                let entitlement = make_c_string(entitlement)?;
                unsafe {
                    xpc_connection_set_peer_entitlement_exists_requirement(
                        connection,
                        entitlement.as_ptr(),
                    )
                }
            }
            Self::EntitlementMatchesValue { entitlement, value } => {
                let entitlement = make_c_string(entitlement)?;
                let value = OwnedXpcObject::from_message(value.clone())?;
                unsafe {
                    xpc_connection_set_peer_entitlement_matches_value_requirement(
                        connection,
                        entitlement.as_ptr(),
                        value.raw,
                    )
                }
            }
            Self::LightweightCodeRequirement(requirement) => {
                let requirement = OwnedXpcObject::from_message(requirement.clone())?;
                unsafe {
                    xpc_connection_set_peer_lightweight_code_requirement(
                        connection,
                        requirement.raw,
                    )
                }
            }
        };

        if result == 0 {
            Ok(())
        } else {
            Err(XpcError::PeerRequirementFailed {
                code: result,
                context: "apply xpc peer requirement",
            })
        }
    }
}
