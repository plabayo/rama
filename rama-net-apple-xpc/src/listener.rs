use std::sync::{Arc, LazyLock, OnceLock};

use ahash::{HashMap, HashMapExt as _};
use parking_lot::Mutex;
use rama_core::telemetry::tracing;
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::{
    Notify,
    mpsc::{Receiver, channel, error::TryRecvError, error::TrySendError},
};

use crate::{
    connection::{
        ConnectionObject, DEFAULT_MAX_PENDING_EVENTS, InactiveXpcConnection, XpcConnection,
        map_connection_error,
    },
    error::{XpcConnectionError, XpcError},
    ffi::{
        _xpc_type_connection, _xpc_type_error, XPC_CONNECTION_MACH_SERVICE_LISTENER,
        xpc_connection_cancel, xpc_connection_create_mach_service, xpc_object_t,
    },
    handler::XpcHandler,
    object::raw_type_is,
    peer::PeerSecurityRequirement,
    util::{DispatchQueue, make_c_string},
};

/// Process-global registry of live named listeners, keyed by Mach service name.
///
/// Mach semantics allow at most one listener per service name per process: the
/// receive right is checked out once, and a second
/// `xpc_connection_create_mach_service(LISTENER)` for the same name is delivered
/// an async `XPC_ERROR_CONNECTION_INVALID` instead of peers. The registry lets
/// [`XpcListener::bind`] detect an earlier in-process listener for the same name
/// and (by default) cancel it so the new listener can acquire the right — the
/// stale listener may otherwise be unreachable, e.g. owned by a task on a wedged
/// runtime that will never drop it.
///
/// Entries hold their own retain on the listener connection and are removed by
/// [`XpcListener::drop`] (pointer-checked, so a displaced listener's drop does
/// not evict its replacement).
///
/// Safety invariant: every entry is an activated listener connection.
static ACTIVE_NAMED_LISTENERS: LazyLock<Mutex<HashMap<ArcStr, ConnectionObject>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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
    takeover: bool,
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
            takeover: true,
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

    rama_utils::macros::generate_set_and_with! {
        /// Cancel a live in-process listener already bound to the same service
        /// name before binding this one (default: `true`).
        ///
        /// Mach semantics allow one listener per name per process, so a second
        /// bind is otherwise delivered `XPC_ERROR_CONNECTION_INVALID` while the
        /// earlier listener keeps the receive right — even when that listener
        /// is unreachable (e.g. stranded on a wedged runtime). Disable only if
        /// a same-name rebind in this process must fail instead of taking over.
        pub fn takeover(mut self, takeover: bool) -> Self {
            self.takeover = takeover;
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
    // Safety invariant: `connection` is an activated listener connection.
    connection: ConnectionObject,
    receiver: Receiver<XpcConnection>,
    service_name: ArcStr,
    terminated: Arc<OnceLock<XpcConnectionError>>,
    terminated_notify: Arc<Notify>,
    /// Set (before `xpc_connection_cancel`) by [`Self::cancel`] and by
    /// [`Drop`]: libxpc delivers a final `XPC_ERROR_CONNECTION_INVALID`
    /// after every cancel, and the event handler must be able to tell
    /// that deliberate teardown apart from a genuine termination — an
    /// explicit cancel stays a graceful path (no error log, no
    /// [`Self::termination_reason`]). A cancel issued by a same-name
    /// takeover intentionally does NOT set this flag (it goes through
    /// the raw registry handle), so a displaced listener still reports
    /// terminated.
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl XpcListener {
    /// Bind to the XPC service name in `config` and start accepting connections.
    ///
    /// Activates the underlying Mach service immediately; clients may begin connecting
    /// before the first call to [`accept`](Self::accept).
    ///
    /// When [`XpcListenerConfig::with_takeover`] is enabled (the default), a
    /// live in-process listener already bound to the same name is cancelled
    /// first so this listener can acquire the Mach receive right.
    pub fn bind(config: XpcListenerConfig) -> Result<Self, XpcError> {
        let XpcListenerConfig {
            service_name,
            target_queue_label,
            peer_requirement,
            max_pending_connections,
            peer_max_pending_events,
            takeover,
        } = config;
        let max_pending_connections = max_pending_connections.max(1);
        let peer_max_pending_events = peer_max_pending_events.max(1);
        tracing::info!(
            service = %service_name,
            target_queue = ?target_queue_label,
            max_pending_connections,
            peer_max_pending_events,
            peer_requirement = peer_requirement.is_some(),
            takeover,
            "xpc listener binding"
        );
        let service_name_c = make_c_string(&service_name)?;
        let queue = DispatchQueue::new(target_queue_label.as_deref())?;

        // SAFETY: requires a non-null NUL-terminated name (`XPC_NONNULL1`), a nullable
        // target queue and `XPC_CONNECTION_MACH_SERVICE_*` flags. `service_name_c` is a
        // live `CString`, `queue.as_raw()` is null or a live queue, and the flag is
        // `XPC_CONNECTION_MACH_SERVICE_LISTENER`.
        let raw = unsafe {
            xpc_connection_create_mach_service(
                service_name_c.as_ptr(),
                queue.as_raw(),
                XPC_CONNECTION_MACH_SERVICE_LISTENER as u64,
            )
        };
        // SAFETY: `raw` is null or the +1, not yet activated result of an
        // `xpc_connection_create*` call (`XPC_RETURNS_RETAINED`) with no other alias;
        // ownership moves.
        let connection = unsafe { InactiveXpcConnection::from_raw(raw, "listener connection") }?;

        if let Some(requirement) = peer_requirement.as_ref() {
            requirement.apply(&connection)?;
        }

        let (sender, receiver) = channel(max_pending_connections);
        let terminated = Arc::new(OnceLock::<XpcConnectionError>::new());
        let terminated_notify = Arc::new(Notify::new());
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let block_service_name = service_name.clone();
        let block_terminated = terminated.clone();
        let block_terminated_notify = terminated_notify.clone();
        let block_cancelled = cancelled.clone();
        // The handler keeps its own alias of the connection (xpc_object(3): an object used
        // by an asynchronously executed block is retained for it). The cycle ends when
        // libxpc releases the handler after cancellation.
        let make_handler = move |handler_connection: ConnectionObject| {
            XpcHandler::new(move |event: xpc_object_t| {
                // SAFETY: the handler argument is non-null and live for this invocation.
                if unsafe { raw_type_is(event, &raw const _xpc_type_error) } {
                    // A listener connection only receives error events when it is
                    // done for good (cancelled, or the Mach receive right was not /
                    // no longer granted — e.g. the name is held by another listener).
                    //
                    // libxpc also delivers a final `XPC_ERROR_CONNECTION_INVALID`
                    // after a deliberate `xpc_connection_cancel` — that is normal
                    // teardown, not a failure, so it must not be recorded as a
                    // termination reason nor logged as an error.
                    if block_cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        tracing::debug!(
                            service = %block_service_name,
                            "xpc listener cancelled; ignoring final invalidation event"
                        );
                        return;
                    }
                    // Surface it: record the reason for `accept` and wake any waiter.
                    // SAFETY: the handler argument is non-null and live for this invocation.
                    let error = unsafe { map_connection_error(&handler_connection, event) }
                        .unwrap_or(XpcConnectionError::Invalidated(None));
                    tracing::error!(
                        service = %block_service_name,
                        %error,
                        "xpc listener terminated by error event"
                    );
                    // Set-then-notify: `accept` checks the state before awaiting the
                    // (permit-storing) notify, so this cannot be missed.
                    _ = block_terminated.set(error);
                    block_terminated_notify.notify_one();
                    return;
                }

                // SAFETY: as above.
                if !unsafe { raw_type_is(event, &raw const _xpc_type_connection) } {
                    tracing::debug!("xpc listener: ignoring non-connection event");
                    return;
                }

                // SAFETY: `event` is a peer connection (checked) passed to this listener's
                // running handler invocation; libxpc delivers each peer once, so no
                // `ConnectionObject` for it exists yet.
                let peer_conn = unsafe {
                    XpcConnection::accept_received(
                        event,
                        peer_max_pending_events,
                        peer_max_pending_events,
                    )
                };
                let pid = peer_conn.pid();
                let asid = peer_conn.asid();
                match sender.try_send(peer_conn) {
                    Ok(()) => {
                        tracing::info!(pid, asid, "xpc listener enqueued incoming peer connection");
                    }
                    Err(TrySendError::Full(_)) => {
                        tracing::warn!(
                            pid,
                            asid,
                            capacity = max_pending_connections,
                            "xpc listener accept queue full; dropping incoming peer connection"
                        );
                    }
                    Err(TrySendError::Closed(_)) => {
                        tracing::warn!(
                            pid,
                            asid,
                            "xpc listener accept queue closed; dropping incoming peer connection"
                        );
                    }
                }
            })
        };

        // Serialise same-name binds: the lock is held across displace + activate
        // + register so (a) two concurrent binds for one name cannot both think
        // they own the receive right, and (b) a displaced entry is always a
        // fully-activated connection (cancel of a never-activated connection is
        // a libxpc programming error).
        let mut registry = ACTIVE_NAMED_LISTENERS.lock();
        let register = match registry.remove(&service_name) {
            Some(previous) if takeover => {
                tracing::warn!(
                    service = %service_name,
                    "xpc listener bind: cancelling live in-process listener with the same \
                     service name (takeover)"
                );
                previous.with_raw(|previous| {
                    // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `previous`
                    // is an activated listener connection (registry invariant), on which
                    // cancel is valid, under its call lock.
                    unsafe { xpc_connection_cancel(previous) };
                });
                true
            }
            Some(previous) => {
                tracing::warn!(
                    service = %service_name,
                    "xpc listener bind: live in-process listener with the same service \
                     name exists and takeover is disabled; this bind will likely be \
                     invalidated by libxpc"
                );
                // The previous listener keeps the receive right and its registry
                // slot; this doomed bind is deliberately not registered.
                registry.insert(service_name.clone(), previous);
                false
            }
            None => true,
        };

        let connection = connection.activate(make_handler);
        if register {
            // Registry invariant: `connection` was activated just above.
            registry.insert(service_name.clone(), connection.retain_clone());
        }
        drop(registry);

        tracing::info!("xpc listener activated");

        Ok(Self {
            connection,
            receiver,
            service_name,
            terminated,
            terminated_notify,
            cancelled,
        })
    }

    /// Await the next incoming peer connection.
    ///
    /// Cancel-safe: if this future is dropped before it resolves, no connection is lost.
    /// Returns `None` once the listener has been cancelled and the internal channel drains,
    /// or once the listener was terminated by libxpc (e.g. the Mach receive right was
    /// revoked or never granted) — inspect [`termination_reason`](Self::termination_reason)
    /// to tell the two apart. Under normal operation this method yields indefinitely.
    pub async fn accept(&mut self) -> Option<XpcConnection> {
        loop {
            // Drain peers that arrived before a terminal error: they are
            // independent connection objects and remain serviceable.
            let connection = match self.receiver.try_recv() {
                Ok(peer) => Some(peer),
                Err(TryRecvError::Disconnected) => None,
                Err(TryRecvError::Empty) => {
                    if let Some(error) = self.terminated.get() {
                        tracing::error!(
                            service = %self.service_name,
                            %error,
                            "xpc listener terminated; no further peer connections"
                        );
                        return None;
                    }
                    tokio::select! {
                        connection = self.receiver.recv() => connection,
                        // `notify_one` stores a permit, and the terminated state
                        // is re-checked at the top of the loop, so a signal raced
                        // with this select cannot be lost.
                        _ = self.terminated_notify.notified() => continue,
                    }
                }
            };

            return if let Some(peer) = connection {
                tracing::info!(
                    pid = peer.pid(),
                    asid = peer.asid(),
                    "xpc listener accepted peer connection"
                );
                Some(peer)
            } else {
                tracing::warn!("xpc listener accept channel closed");
                None
            };
        }
    }

    /// Reason the listener stopped accepting, when libxpc terminated it.
    ///
    /// `Some` after [`accept`](Self::accept) returned `None` because of an
    /// error event (e.g. the Mach service name is held by another listener, or
    /// the receive right was revoked). `None` while healthy, and also for a
    /// plain [`cancel`](Self::cancel)-then-drain shutdown.
    pub fn termination_reason(&self) -> Option<&XpcConnectionError> {
        self.terminated.get()
    }

    /// Explicitly cancel the listener.
    ///
    /// Stops accepting new connections and tears down the underlying Mach service.
    /// Safe to call multiple times — cancelling an already-cancelled listener is a no-op.
    /// The listener is also cancelled automatically on [`Drop`].
    ///
    /// This is a graceful shutdown: the final `XPC_ERROR_CONNECTION_INVALID`
    /// libxpc schedules for a cancelled connection is not treated as a
    /// termination — [`accept`](Self::accept) drains and returns `None`, and
    /// [`termination_reason`](Self::termination_reason) stays `None`.
    pub fn cancel(&self) {
        tracing::debug!("xpc listener cancel");
        // Before the cancel, so the event handler observes the flag by the
        // time libxpc delivers the scheduled final invalidation event.
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is an
            // activated listener connection (field invariant), on which cancel is valid.
            unsafe { xpc_connection_cancel(connection) };
        });
    }

    /// Remove this listener's registry entry, unless a takeover already
    /// replaced it with a newer listener for the same name.
    fn unregister(&self) {
        let mut registry = ACTIVE_NAMED_LISTENERS.lock();
        if registry
            .get(&self.service_name)
            .is_some_and(|entry| entry.same_object(&self.connection))
        {
            registry.remove(&self.service_name);
        }
    }
}

impl Drop for XpcListener {
    fn drop(&mut self) {
        self.unregister();
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered_ptr(name: &ArcStr) -> Option<usize> {
        ACTIVE_NAMED_LISTENERS
            .lock()
            .get(name)
            .map(ConnectionObject::addr)
    }

    #[test]
    fn registry_tracks_bind_takeover_and_drop() {
        let name: ArcStr = format!(
            "org.ramaproxy.test.xpc.registry.takeover.{}",
            std::process::id()
        )
        .into();

        let a = XpcListener::bind(XpcListenerConfig::new(name.clone())).expect("bind a");
        let a_ptr = a.connection.addr();
        assert_eq!(registered_ptr(&name), Some(a_ptr));

        let b = XpcListener::bind(XpcListenerConfig::new(name.clone())).expect("bind b");
        let b_ptr = b.connection.addr();
        assert_eq!(
            registered_ptr(&name),
            Some(b_ptr),
            "takeover replaces entry"
        );

        // The displaced listener's drop must not evict its replacement.
        drop(a);
        assert_eq!(registered_ptr(&name), Some(b_ptr));

        drop(b);
        assert_eq!(registered_ptr(&name), None);
    }

    #[test]
    fn registry_keeps_previous_when_takeover_disabled() {
        let name: ArcStr = format!(
            "org.ramaproxy.test.xpc.registry.no-takeover.{}",
            std::process::id()
        )
        .into();

        let a = XpcListener::bind(XpcListenerConfig::new(name.clone())).expect("bind a");
        let a_ptr = a.connection.addr();

        let b = XpcListener::bind(XpcListenerConfig::new(name.clone()).with_takeover(false))
            .expect("bind b");
        assert_eq!(
            registered_ptr(&name),
            Some(a_ptr),
            "takeover disabled: previous listener keeps its registry slot"
        );

        // The doomed second bind was never registered; dropping it must not
        // evict the rightful owner.
        drop(b);
        assert_eq!(registered_ptr(&name), Some(a_ptr));

        drop(a);
        assert_eq!(registered_ptr(&name), None);
    }
}
