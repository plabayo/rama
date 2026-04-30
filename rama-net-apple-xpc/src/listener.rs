use std::{ffi::c_void, ptr};

use rama_core::telemetry::tracing;
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use block2::RcBlock;

use crate::{
    connection::XpcConnection,
    error::XpcError,
    ffi::{
        _xpc_type_connection, _xpc_type_error, XPC_CONNECTION_MACH_SERVICE_LISTENER,
        xpc_connection_activate, xpc_connection_cancel, xpc_connection_create_mach_service,
        xpc_connection_set_event_handler, xpc_get_type, xpc_object_t,
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
        tracing::debug!(service = %service_name, "create xpc listener");
        let service_name = make_c_string(&service_name)?;
        let queue = DispatchQueue::new(target_queue_label.as_deref())?;
        // SAFETY: service_name is a valid null-terminated C string produced by
        // make_c_string. queue.raw is either a valid dispatch_queue_t or null (anonymous
        // queue). XPC_CONNECTION_MACH_SERVICE_LISTENER is the correct flag for a server-
        // side Mach service. The returned value is a new retained connection or NULL.
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

        let block = RcBlock::new(move |event: xpc_object_t| {
            if raw_is_error(event) {
                tracing::debug!("xpc listener: ignoring error event");
                return;
            }

            if !raw_is_connection(event) {
                tracing::debug!("xpc listener: ignoring non-connection event");
                return;
            }

            let Ok(peer) = OwnedXpcObject::retain(event, "listener peer connection") else {
                return;
            };

            if let Ok(peer_conn) = XpcConnection::from_owned_peer(peer) {
                let _ = sender.send(peer_conn);
            }
        });

        // SAFETY: raw_connection is a valid, non-null xpc_connection_t from OwnedXpcObject.
        // RcBlock is a heap-allocated reference-counted Block; XPC retains it internally
        // after xpc_connection_set_event_handler so it remains valid beyond this scope.
        // xpc_connection_activate must be called exactly once to begin accepting connections.
        unsafe {
            xpc_connection_set_event_handler(
                raw_connection,
                RcBlock::as_ptr(&block).cast::<c_void>(),
            );
            xpc_connection_activate(raw_connection);
        }

        Ok(Self {
            connection,
            receiver,
        })
    }

    /// Await the next incoming peer connection.
    ///
    /// Cancel-safe: if this future is dropped before it resolves, no connection is lost.
    /// Returns `None` once the listener has been cancelled and the internal channel drains.
    /// Under normal operation this method yields indefinitely.
    pub async fn accept(&mut self) -> Option<XpcConnection> {
        let connection = self.receiver.recv().await;
        if connection.is_some() {
            tracing::debug!("xpc listener accepted peer connection");
        }
        connection
    }

    /// Explicitly cancel the listener.
    ///
    /// Stops accepting new connections and tears down the underlying Mach service.
    /// Safe to call multiple times — cancelling an already-cancelled listener is a no-op.
    /// The listener is also cancelled automatically on [`Drop`].
    pub fn cancel(&self) {
        tracing::debug!("xpc listener cancel");
        // SAFETY: self.connection.raw is a valid, non-null xpc_connection_t held by
        // OwnedXpcObject. xpc_connection_cancel is idempotent per Apple's documentation.
        unsafe { xpc_connection_cancel(self.connection.raw as _) };
    }
}

impl Drop for XpcListener {
    fn drop(&mut self) {
        // SAFETY: Same contract as cancel(). Called at most once because Drop runs once.
        unsafe { xpc_connection_cancel(self.connection.raw as _) };
    }
}

/// Caller must pass a valid, non-null `xpc_object_t` (we always do — these
/// helpers are reached only from the listener event-handler block where
/// libxpc hands us a retained event).
fn raw_is_type(event: xpc_object_t, ty: *const c_void) -> bool {
    // SAFETY: see function-level comment — `event` is a valid xpc_object_t.
    let value_type = unsafe { xpc_get_type(event) };
    ptr::eq(value_type.cast::<c_void>(), ty)
}

fn raw_is_error(event: xpc_object_t) -> bool {
    raw_is_type(event, unsafe {
        // SAFETY: `_xpc_type_error` is a static XPC type singleton exported
        // by libxpc and valid for the lifetime of the process.
        &_xpc_type_error as *const _ as *const c_void
    })
}

fn raw_is_connection(event: xpc_object_t) -> bool {
    raw_is_type(event, unsafe {
        // SAFETY: `_xpc_type_connection` is a static XPC type singleton
        // exported by libxpc and valid for the lifetime of the process.
        &_xpc_type_connection as *const _ as *const c_void
    })
}
