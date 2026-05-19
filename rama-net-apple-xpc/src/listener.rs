use std::{ffi::c_void, ptr};

use rama_core::telemetry::tracing;
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::mpsc::{Receiver, channel, error::TrySendError};

use block2::RcBlock;

use crate::{
    connection::{DEFAULT_MAX_PENDING_EVENTS, XpcConnection},
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

/// Default capacity for the listener's accept (peer-connection) queue.
pub const DEFAULT_MAX_PENDING_CONNECTIONS: usize = 1024;

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
    max_pending_connections: usize,
    peer_max_pending_events: usize,
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
            max_pending_connections: DEFAULT_MAX_PENDING_CONNECTIONS,
            peer_max_pending_events: DEFAULT_MAX_PENDING_EVENTS,
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

    rama_utils::macros::generate_set_and_with! {
        /// Maximum number of unaccepted peer connections that may queue inside
        /// [`XpcListener::accept`]'s internal channel before new arrivals are
        /// dropped (with a warn-level log).
        ///
        /// Defaults to [`DEFAULT_MAX_PENDING_CONNECTIONS`]. Values of `0` are
        /// clamped to `1`. Lower this for stricter back-pressure, raise it for
        /// bursty workloads.
        pub fn max_pending_connections(mut self, capacity: usize) -> Self {
            self.max_pending_connections = capacity.max(1);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum number of unread events that may queue per accepted peer
        /// connection before new events are dropped (with a warn-level log).
        ///
        /// Each peer connection produced by this listener inherits this capacity.
        /// Defaults to
        /// [`DEFAULT_MAX_PENDING_EVENTS`](crate::connection::DEFAULT_MAX_PENDING_EVENTS).
        /// Values of `0` are clamped to `1`.
        pub fn peer_max_pending_events(mut self, capacity: usize) -> Self {
            self.peer_max_pending_events = capacity.max(1);
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
    receiver: Receiver<XpcConnection>,
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
            max_pending_connections,
            peer_max_pending_events,
        } = config;
        let max_pending_connections = max_pending_connections.max(1);
        let peer_max_pending_events = peer_max_pending_events.max(1);
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

        let (sender, receiver) = channel(max_pending_connections);
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

            match XpcConnection::from_owned_peer_with_capacity(
                peer,
                peer_max_pending_events,
                peer_max_pending_events,
            ) {
                Ok(peer_conn) => {
                    if let Err(TrySendError::Full(_)) = sender.try_send(peer_conn) {
                        tracing::warn!(
                            capacity = max_pending_connections,
                            "xpc listener accept queue full; dropping incoming peer connection"
                        );
                    }
                    // Ok and Closed are both no-ops.
                }
                Err(err) => {
                    tracing::warn!(%err, "xpc listener: failed to wrap peer connection");
                }
            }
        });

        // SAFETY: `raw_connection` is a valid, non-null xpc_connection_t held by
        // `connection` (OwnedXpcObject) for the lifetime of this Self. The `RcBlock`
        // lives on the heap and `RcBlock::as_ptr` is documented (block2 rc_block.rs)
        // valid for at least as long as the RcBlock is alive; Apple's
        // `xpc_connection_set_event_handler` is documented to `_Block_copy` the
        // block, transferring an extra refcount to libxpc — so when the local
        // `RcBlock` is dropped at end-of-scope, libxpc's copy keeps the block alive
        // for as long as the connection accepts events. `xpc_connection_activate`
        // must be called exactly once to begin accepting connections.
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "set-handler-then-activate is a single XPC listener-init sequence; the SAFETY comment above covers both calls"
        )]
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
