use std::ptr;

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

#[derive(Debug, Clone)]
pub enum PeerSecurityRequirement {
    CodeSigning(String),
    TeamIdentity(Option<String>),
    PlatformIdentity(Option<String>),
    EntitlementExists(String),
    EntitlementMatchesValue {
        entitlement: String,
        value: XpcMessage,
    },
    LightweightCodeRequirement(XpcMessage),
}

impl PeerSecurityRequirement {
    pub(crate) fn apply(&self, connection: xpc_connection_t) -> Result<(), XpcError> {
        let result = match self {
            Self::CodeSigning(requirement) => {
                let requirement = make_c_string(requirement)?;
                unsafe {
                    xpc_connection_set_peer_code_signing_requirement(connection, requirement.as_ptr())
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
                    xpc_connection_set_peer_lightweight_code_requirement(connection, requirement.raw)
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
