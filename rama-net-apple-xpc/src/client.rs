use rama_core::telemetry::tracing;
use rama_utils::str::arcstr::ArcStr;

use crate::{
    connection::XpcConnection,
    error::XpcError,
    ffi::{XPC_CONNECTION_MACH_SERVICE_PRIVILEGED, xpc_connection_create_mach_service},
    object::OwnedXpcObject,
    peer::PeerSecurityRequirement,
    util::{DispatchQueue, make_c_string},
};

/// Configuration for a client-side XPC connection.
///
/// Pass to [`XpcConnection::connect`] or [`XpcConnector`](crate::XpcConnector).
///
/// The `service_name` must match the `MachServices` key in the launchd plist of
/// the target service (e.g. `"com.example.myservice"`).
#[derive(Debug, Clone)]
pub struct XpcClientConfig {
    service_name: ArcStr,
    privileged: bool,
    target_queue_label: Option<ArcStr>,
    peer_requirement: Option<PeerSecurityRequirement>,
}

impl XpcClientConfig {
    /// Create a config targeting `service_name`.
    ///
    /// `service_name` is looked up in the launchd bootstrap namespace.
    pub fn new(service_name: impl Into<ArcStr>) -> Self {
        Self {
            service_name: service_name.into(),
            privileged: false,
            target_queue_label: None,
            peer_requirement: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Connect to the privileged Mach bootstrap context (`XPC_CONNECTION_MACH_SERVICE_PRIVILEGED`).
        ///
        /// Set this when targeting a launchd daemon registered in the system bootstrap
        /// context rather than the per-user session context.
        pub fn privileged(mut self, privileged: bool) -> Self {
            self.privileged = privileged;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the GCD dispatch queue label used for the connection's event handler.
        ///
        /// `None` uses a default anonymous queue.
        pub fn target_queue_label(mut self, label: Option<ArcStr>) -> Self {
            self.target_queue_label = label;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Require the server to satisfy a security constraint before any message is exchanged.
        ///
        /// Applied before the connection is activated. If the server does not satisfy it,
        /// [`XpcConnectionError::PeerRequirementFailed`](crate::XpcConnectionError::PeerRequirementFailed)
        /// is delivered through the event stream and no messages are exchanged.
        pub fn peer_requirement(mut self, requirement: Option<PeerSecurityRequirement>) -> Self {
            self.peer_requirement = requirement;
            self
        }
    }
}

impl XpcConnection {
    /// Establish a client connection to the named XPC service.
    ///
    /// The service must be registered with launchd under `config.service_name`.
    /// The connection is lazy — no handshake occurs until the first message is sent
    /// or a peer requirement failure is reported through [`recv`](XpcConnection::recv).
    pub fn connect(config: XpcClientConfig) -> Result<Self, XpcError> {
        let XpcClientConfig {
            service_name,
            privileged,
            target_queue_label,
            peer_requirement,
        } = config;
        tracing::debug!(
            service = %service_name,
            privileged,
            "create xpc client connection"
        );
        let service_name = make_c_string(&service_name)?;
        let queue = DispatchQueue::new(target_queue_label.as_deref())?;
        let flags = if privileged {
            XPC_CONNECTION_MACH_SERVICE_PRIVILEGED as u64
        } else {
            0
        };

        // SAFETY: service_name is a valid null-terminated C string from make_c_string.
        // queue.raw is either a valid dispatch_queue_t or null. flags is a valid
        // XPC_CONNECTION_MACH_SERVICE_* combination (0 or PRIVILEGED).
        let raw =
            unsafe { xpc_connection_create_mach_service(service_name.as_ptr(), queue.raw, flags) };
        let connection = OwnedXpcObject::from_raw(raw as _, "client connection")?;

        if let Some(requirement) = peer_requirement.as_ref() {
            requirement.apply(connection.raw as _)?;
        }

        Self::from_owned_peer(connection)
    }
}
