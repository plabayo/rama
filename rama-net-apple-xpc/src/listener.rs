use std::ops::Deref;

use rama_utils::str::arcstr::ArcStr;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::{
    block::ConcreteBlock,
    connection::XpcConnection,
    error::XpcError,
    ffi::{
        XPC_CONNECTION_MACH_SERVICE_LISTENER, xpc_connection_activate,
        xpc_connection_cancel, xpc_connection_create_mach_service,
        xpc_connection_set_event_handler, xpc_object_t,
    },
    object::OwnedXpcObject,
    peer::PeerSecurityRequirement,
    util::{DispatchQueue, make_c_string},
};

#[derive(Debug, Clone)]
pub struct XpcListenerConfig {
    service_name: ArcStr,
    target_queue_label: Option<ArcStr>,
    peer_requirement: Option<PeerSecurityRequirement>,
}

impl XpcListenerConfig {
    pub fn new(service_name: impl Into<ArcStr>) -> Self {
        Self {
            service_name: service_name.into(),
            target_queue_label: None,
            peer_requirement: None,
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

#[derive(Debug)]
pub struct XpcListener {
    connection: OwnedXpcObject,
    receiver: UnboundedReceiver<XpcConnection>,
}

impl XpcListener {
    pub fn bind(config: XpcListenerConfig) -> Result<Self, XpcError> {
        let XpcListenerConfig {
            service_name,
            target_queue_label,
            peer_requirement,
        } = config;
        let service_name = make_c_string(&service_name)?;
        let queue = DispatchQueue::new(target_queue_label.as_deref())?;
        let raw = unsafe {
            xpc_connection_create_mach_service(
                service_name.as_ptr(),
                queue.raw,
                XPC_CONNECTION_MACH_SERVICE_LISTENER as u64,
            )
        };
        let connection = OwnedXpcObject::from_raw(raw as _, "listener connection")?;

        if let Some(requirement) = peer_requirement.as_ref() {
            requirement.apply(connection.raw as _)?;
        }

        let (sender, receiver) = unbounded_channel();
        let raw_connection = connection.raw as _;

        let block = ConcreteBlock::new(move |event: xpc_object_t| {
            if let Ok(peer) = OwnedXpcObject::retain(event, "listener peer connection")
                && let Ok(peer_conn) = XpcConnection::from_owned_peer(peer)
            {
                let _ = sender.send(peer_conn);
            }
        })
        .copy();

        unsafe {
            xpc_connection_set_event_handler(raw_connection, block.deref() as *const _ as *mut _);
            xpc_connection_activate(raw_connection);
        }

        Ok(Self {
            connection,
            receiver,
        })
    }

    pub async fn accept(&mut self) -> Option<XpcConnection> {
        self.receiver.recv().await
    }
}

impl Drop for XpcListener {
    fn drop(&mut self) {
        unsafe { xpc_connection_cancel(self.connection.raw as _) };
    }
}
