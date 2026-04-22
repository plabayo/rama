use rama_utils::str::arcstr::ArcStr;

use crate::{
    connection::XpcConnection,
    error::XpcError,
    ffi::{XPC_CONNECTION_MACH_SERVICE_PRIVILEGED, xpc_connection_create_mach_service},
    object::OwnedXpcObject,
    peer::PeerSecurityRequirement,
    util::{DispatchQueue, make_c_string},
};

#[derive(Debug, Clone)]
pub struct XpcClientConfig {
    service_name: ArcStr,
    privileged: bool,
    target_queue_label: Option<ArcStr>,
    peer_requirement: Option<PeerSecurityRequirement>,
}

impl XpcClientConfig {
    pub fn new(service_name: impl Into<ArcStr>) -> Self {
        Self {
            service_name: service_name.into(),
            privileged: false,
            target_queue_label: None,
            peer_requirement: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn privileged(mut self, privileged: bool) -> Self {
            self.privileged = privileged;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn target_queue_label(mut self, label: Option<ArcStr>) -> Self {
            self.target_queue_label = label;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn peer_requirement(mut self, requirement: Option<PeerSecurityRequirement>) -> Self {
            self.peer_requirement = requirement;
            self
        }
    }
}

impl XpcConnection {
    pub fn connect(config: XpcClientConfig) -> Result<Self, XpcError> {
        let XpcClientConfig {
            service_name,
            privileged,
            target_queue_label,
            peer_requirement,
        } = config;
        let service_name = make_c_string(&service_name)?;
        let queue = DispatchQueue::new(target_queue_label.as_deref())?;
        let flags = if privileged {
            XPC_CONNECTION_MACH_SERVICE_PRIVILEGED as u64
        } else {
            0
        };

        let raw =
            unsafe { xpc_connection_create_mach_service(service_name.as_ptr(), queue.raw, flags) };
        let connection = OwnedXpcObject::from_raw(raw as _, "client connection")?;

        if let Some(requirement) = peer_requirement.as_ref() {
            requirement.apply(connection.raw as _)?;
        }

        Self::from_owned_peer(connection)
    }
}
