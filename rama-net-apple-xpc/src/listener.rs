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

/// Configuration for a server-side XPC listener.
///
/// Pass to [`XpcListener::bind`].
///
/// The `service_name` must match the `MachServices` key in the launchd plist of
/// this process (e.g. `"com.example.myservice"`). The plist must be installed and
/// loaded before [`XpcListener::bind`] is called.
#[derive(Debug, Clone)]
pub struct XpcListenerConfig {
    service_name: ArcStr,
    target_queue_label: Option<ArcStr>,
    peer_requirement: Option<PeerSecurityRequirement>,
}

impl XpcListenerConfig {
    /// Create a config for `service_name`.
    ///
    /// `service_name` must be registered in the launchd bootstrap namespace.
    pub fn new(service_name: impl Into<ArcStr>) -> Self {
        Self {
            service_name: service_name.into(),
            target_queue_label: None,
            peer_requirement: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the GCD dispatch queue label used for the listener's event handler.
        ///
        /// `None` uses a default anonymous queue.
        pub fn target_queue_label(mut self, label: Option<ArcStr>) -> Self {
            self.target_queue_label = label;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Require connecting clients to satisfy a security constraint.
        ///
        /// Applied to each incoming peer connection before it is delivered by
        /// [`XpcListener::accept`]. Peers that fail the check are silently dropped.
        pub fn peer_requirement(mut self, requirement: Option<PeerSecurityRequirement>) -> Self {
            self.peer_requirement = requirement;
            self
        }
    }
}

/// A server-side XPC listener that accepts incoming peer connections.
///
/// Created with [`XpcListener::bind`]. Each call to [`accept`](Self::accept)
/// yields an [`XpcConnection`] for the next connecting client.
///
/// The listener is cancelled and the underlying Mach service is torn down on [`Drop`].
///
/// # Requirements
///
/// The service name in [`XpcListenerConfig`] must be registered with launchd via a
/// plist file before [`bind`](Self::bind) is called. Without launchd registration,
/// `bind` will succeed but no clients will be able to connect by name. Use
/// [`XpcEndpoint`](crate::XpcEndpoint) to hand off connection references out-of-band
/// for services that do not have a launchd entry.
#[derive(Debug)]
pub struct XpcListener {
    connection: OwnedXpcObject,
    receiver: UnboundedReceiver<XpcConnection>,
}

impl XpcListener {
    /// Bind to the XPC service name in `config` and start accepting connections.
    ///
    /// Activates the underlying Mach service immediately; clients may begin connecting
    /// before the first call to [`accept`](Self::accept).
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

    /// Await the next incoming peer connection.
    ///
    /// Returns `None` if the listener has been cancelled and the internal channel
    /// is drained. Under normal operation this method yields indefinitely.
    pub async fn accept(&mut self) -> Option<XpcConnection> {
        self.receiver.recv().await
    }
}

impl Drop for XpcListener {
    fn drop(&mut self) {
        unsafe { xpc_connection_cancel(self.connection.raw as _) };
    }
}
