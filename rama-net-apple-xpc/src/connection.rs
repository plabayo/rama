use std::{
    ffi::{CStr, c_void},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

// `xpc_connection_copy_invalidation_reason` returns a caller-owned C string. Declared
// locally rather than pulling in the `libc` crate for one symbol.
unsafe extern "C" {
    /// `void free(void *ptr)` from `<stdlib.h>`.
    #[link_name = "free"]
    fn libc_free(ptr: *mut c_void);
}

use parking_lot::Mutex;
use rama_core::{
    Service,
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::{
    mpsc::{Receiver, Sender, channel, error::TrySendError},
    oneshot,
};

/// Default capacity for the per-connection event channel.
///
/// Sized generously so that well-behaved peers never see back-pressure-induced
/// drops, while still bounding the worst-case memory footprint of a misbehaving
/// or stuck reader. Override per-connection via
/// [`XpcClientConfig::with_max_pending_events`](crate::XpcClientConfig::with_max_pending_events)
/// or via the listener-level knobs on
/// [`XpcListenerConfig`](crate::XpcListenerConfig).
pub const DEFAULT_MAX_PENDING_EVENTS: usize = 10_000;

use crate::{
    call::XpcCall,
    error::{XpcConnectionError, XpcError},
    ffi::{
        _xpc_error_connection_interrupted, _xpc_error_key_description,
        _xpc_error_peer_code_signing_requirement, _xpc_type_connection, _xpc_type_dictionary,
        _xpc_type_error, xpc_connection_activate, xpc_connection_cancel,
        xpc_connection_copy_invalidation_reason, xpc_connection_get_asid, xpc_connection_get_egid,
        xpc_connection_get_euid, xpc_connection_get_name, xpc_connection_get_pid,
        xpc_connection_resume, xpc_connection_send_message, xpc_connection_send_message_with_reply,
        xpc_connection_set_event_handler, xpc_connection_suspend, xpc_connection_t,
        xpc_dictionary_create_reply, xpc_dictionary_get_string, xpc_dictionary_set_value,
        xpc_object_t, xpc_release, xpc_retain,
    },
    handler::XpcHandler,
    message::XpcMessage,
    object::{OwnedXpcObject, raw_type_is},
    router::extract_result,
    util::make_c_string,
    xpc_serde,
};

/// An owned reference to an activated (or listener-delivered) connection, plus the
/// call lock shared by every Rust alias of it.
///
/// libxpc documents no concurrency guarantee for `xpc_connection_t`, so every libxpc
/// call Rust makes on a connection runs under that lock ([`with_raw`](Self::with_raw)).
/// Retain/release, `xpc_get_type` (the object's fixed type) and libxpc's own threads
/// are outside the lock.
#[derive(Debug)]
pub(crate) struct ConnectionObject {
    // Safety invariant: `raw` is a live `XPC_TYPE_CONNECTION` object on which this value
    // owns one reference, released by `Drop`. Whenever that release can be the last one,
    // the connection is activated and not suspended (see `InactiveXpcConnection` and
    // `XpcConnection::suspend_count`), or it was delivered to a listener, for which
    // libxpc keeps its own reference until it is invalid (`xpc_connection_set_event_handler`).
    // `calls` is shared by every `ConnectionObject` and `InactiveXpcConnection` alias of
    // `raw`, and is held across every libxpc call on `raw` other than retain/release.
    raw: xpc_connection_t,
    calls: Arc<Mutex<()>>,
}

// SAFETY: every libxpc call on the connection through any Rust alias holds `calls`
// (field invariant), so Rust never makes concurrent libxpc calls on it; xpc_object(3)
// permits using and releasing an object on a queue other than the one that retained it.
unsafe impl Send for ConnectionObject {}
// SAFETY: `&self` methods reach the connection only through `with_raw` (lock held),
// `retain_clone` (retain) and `same_object` (pointer comparison).
unsafe impl Sync for ConnectionObject {}

impl ConnectionObject {
    pub(crate) fn retain_clone(&self) -> Self {
        // SAFETY: `xpc_retain` requires a live object; `self.raw` is one (field
        // invariant). The new reference shares `calls` and is owned by the result.
        unsafe { xpc_retain(self.raw.cast()) };
        Self {
            raw: self.raw,
            calls: self.calls.clone(),
        }
    }

    /// Run `f` with the connection while holding the call lock of all its aliases.
    ///
    /// `f` must not call `with_raw` on an alias of the same connection (it would
    /// deadlock).
    ///
    /// # Safety-usable invariant
    ///
    /// `f` receives a live connection, and no other Rust alias makes a libxpc call on it
    /// until `f` returns.
    pub(crate) fn with_raw<R>(&self, f: impl FnOnce(xpc_connection_t) -> R) -> R {
        let _calls = self.calls.lock();
        f(self.raw)
    }

    pub(crate) fn same_object(&self, other: &Self) -> bool {
        ptr::eq(self.raw, other.raw)
    }

    #[cfg(test)]
    pub(crate) fn addr(&self) -> usize {
        self.raw as usize
    }
}

impl Drop for ConnectionObject {
    fn drop(&mut self) {
        // SAFETY: `xpc_release` requires an object the caller holds a reference on; this
        // value owns one (field invariant), and the invariant's lifecycle clause makes a
        // last release valid. `raw` is not used afterwards.
        unsafe { xpc_release(self.raw.cast()) };
    }
}

/// A connection returned by an `xpc_connection_create*` call that is not active yet.
///
/// Dropping it before [`activate`](Self::activate) still activates and then cancels the
/// connection: <xpc/connection.h> calls releasing an inactive connection undefined
/// (libxpc traps on it), and activating requires an event handler. It hands out no
/// alias, so a leaked (`mem::forget`) value never releases.
#[derive(Debug)]
pub(crate) struct InactiveXpcConnection {
    // Safety invariant: while `transferred` is false, `raw` is a connection returned by
    // an `xpc_connection_create*` call, not activated, on which this value owns the one
    // Rust reference, and outside `activate` no other Rust alias exists. Once
    // `transferred` is set, the connection is activated and that reference belongs to
    // the `ConnectionObject` `activate` returned. `calls` is the lock its
    // `ConnectionObject` aliases share.
    raw: xpc_connection_t,
    calls: Arc<Mutex<()>>,
    transferred: bool,
}

impl InactiveXpcConnection {
    /// Wrap the reference returned by an `xpc_connection_create*` call.
    ///
    /// # Safety
    ///
    /// The caller must ensure `raw` is null or a connection returned by an
    /// `xpc_connection_create*` call that has not been activated or resumed, on which the
    /// caller owns that call's reference and no other Rust alias exists. The reference
    /// moves into the result; a null `raw` returns [`XpcError::NullConnection`].
    pub(crate) unsafe fn from_raw(
        raw: xpc_connection_t,
        context: &'static str,
    ) -> Result<Self, XpcError> {
        if raw.is_null() {
            return Err(XpcError::NullConnection(context));
        }
        Ok(Self {
            raw,
            calls: Arc::new(Mutex::new(())),
            transferred: false,
        })
    }

    /// # Safety-usable invariant
    ///
    /// Returns a live connection, returned by an `xpc_connection_create*` call and not
    /// activated, with no other Rust alias (so calls on it need no lock).
    pub(crate) fn as_raw(&self) -> xpc_connection_t {
        self.raw
    }

    /// Install the handler built by `make_handler` and activate the connection.
    ///
    /// `make_handler` receives an alias for the handler to keep.
    pub(crate) fn activate(
        mut self,
        make_handler: impl FnOnce(ConnectionObject) -> XpcHandler,
    ) -> ConnectionObject {
        // SAFETY: `xpc_retain` requires a live object; `self.raw` is one (field invariant).
        unsafe { xpc_retain(self.raw.cast()) };
        // ConnectionObject invariant: this alias is never the last reference while the
        // connection is inactive, since `self` keeps its own until it is activated here
        // or torn down by `Drop` (also on unwind out of `make_handler`).
        let handler = make_handler(ConnectionObject {
            raw: self.raw,
            calls: self.calls.clone(),
        });
        {
            let _calls = self.calls.lock();
            // SAFETY: requires a live connection and a non-null `void (^)(xpc_object_t)`
            // block (`XPC_NONNULL_ALL`); `self.raw` is live and `handler.as_block_ptr()`
            // is such a block (`XpcHandler`). The parameter is escaping (no
            // `XPC_NOESCAPE`), so libxpc keeps its own `Block_copy` after `handler` drops.
            unsafe { xpc_connection_set_event_handler(self.raw, handler.as_block_ptr()) };
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`), as above.
            unsafe { xpc_connection_activate(self.raw) };
        }
        // Field invariant: the connection is active and this value's reference moves to
        // the result, so `Drop` neither tears down nor releases it.
        self.transferred = true;
        ConnectionObject {
            raw: self.raw,
            calls: self.calls.clone(),
        }
    }
}

impl Drop for InactiveXpcConnection {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        let handler = XpcHandler::new(|_event| {});
        let _calls = self.calls.lock();
        // SAFETY: as in `activate`: live connection, `XpcHandler` block.
        unsafe { xpc_connection_set_event_handler(self.raw, handler.as_block_ptr()) };
        // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `self.raw` is one.
        unsafe { xpc_connection_activate(self.raw) };
        // SAFETY: requires a live connection; it is now active, so cancelling it is valid.
        unsafe { xpc_connection_cancel(self.raw) };
        // SAFETY: `xpc_release` requires an owned reference: this value owns one (field
        // invariant), and the connection is activated, so a last release is valid.
        unsafe { xpc_release(self.raw.cast()) };
    }
}

/// How a connection reached this process; it decides what libxpc permits on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionOrigin {
    /// Returned by an `xpc_connection_create*` call.
    Created,
    /// Delivered to a listener connection's event handler.
    Received,
}

/// An event received on an [`XpcConnection`].
#[derive(Debug)]
pub enum XpcEvent {
    /// An incoming peer connection from a listener-style connection.
    Connection(XpcConnection),
    /// An incoming message from the peer.
    Message(ReceivedXpcMessage),
    /// A connection lifecycle error. After this event the connection is permanently closed.
    Error(XpcConnectionError),
}

/// An incoming XPC message together with the context needed to send a reply.
///
/// Obtained from [`XpcEvent::Message`] via [`XpcConnection::recv`]. Holds its own
/// retained reference to the originating connection: the parent
/// [`XpcConnection`] may be dropped while a `ReceivedXpcMessage` is still in
/// flight, and [`reply`](Self::reply) remains safe to call.
#[derive(Debug)]
pub struct ReceivedXpcMessage {
    // Independent retained reference to the originating connection — keeps it alive
    // for the lifetime of this message even if the parent XpcConnection is dropped.
    connection: ConnectionObject,
    message: XpcMessage,
    /// `None` for a message sent without a reply context (fire-and-forget).
    reply: Option<PendingReply>,
}

/// The empty reply dictionary `xpc_dictionary_create_reply` made for a received message.
///
/// Created while the event handler runs, so the received message graph never leaves the
/// handler invocation; only this fresh dictionary crosses threads.
#[derive(Debug)]
struct PendingReply {
    // Safety invariant: `dictionary` is a dictionary returned by
    // `xpc_dictionary_create_reply` that holds no values until `ReceivedXpcMessage::reply`
    // fills it, and `dictionary` is its only Rust owner.
    dictionary: OwnedXpcObject,
}

// SAFETY: the moved value is the only Rust owner of a dictionary with no children (field
// invariant), so all Rust access to it moves with it; xpc_object(3) permits using and
// releasing an object on a queue other than the one that created it.
unsafe impl Send for PendingReply {}
// SAFETY: `&PendingReply` gives no access to the dictionary: the field is private, the
// only use is by value in `ReceivedXpcMessage::reply`, and `Debug` prints the pointer.
unsafe impl Sync for PendingReply {}

impl ReceivedXpcMessage {
    /// Borrow the decoded message.
    pub fn message(&self) -> &XpcMessage {
        &self.message
    }

    /// Consume this wrapper and return the decoded message, discarding reply capability.
    pub fn into_message(self) -> XpcMessage {
        self.message
    }

    /// Send a reply to the peer.
    ///
    /// `message` must be a [`XpcMessage::Dictionary`]; any other variant returns
    /// [`XpcError::ReplyNotExpected`]. The reply is delivered to the future awaiting
    /// [`XpcConnection::send_request`] on the other side.
    ///
    /// `reply` consumes the message: each incoming message may be replied to at most
    /// once. To inspect the message without replying use [`message`](Self::message);
    /// to extract without replying use [`into_message`](Self::into_message).
    pub fn reply(self, message: XpcMessage) -> Result<(), XpcError> {
        let XpcMessage::Dictionary(values) = message else {
            return Err(XpcError::ReplyNotExpected);
        };

        // No reply context ⇒ nothing to reply to; `ReplyNotExpected` lets a server
        // swallow it rather than treating it as a fatal error.
        let Some(PendingReply { dictionary: reply }) = self.reply else {
            return Err(XpcError::ReplyNotExpected);
        };

        for (key, value) in values {
            let key = make_c_string(&key)?;
            let value = OwnedXpcObject::from_message(value)?;
            // SAFETY: requires a live dictionary and a non-null NUL-terminated key
            // (`XPC_NONNULL1 XPC_NONNULL2`). `reply` is the reply dictionary, owned only
            // here (`PendingReply` invariant); `key` is a live `CString`; the dictionary
            // retains `value`.
            unsafe { xpc_dictionary_set_value(reply.as_raw(), key.as_ptr(), value.as_raw()) };
        }

        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection and a dictionary message
            // (`XPC_NONNULL_ALL`). `connection` is live under the call lock
            // (`with_raw`), even if the parent `XpcConnection` was dropped; `reply` is a
            // live dictionary, logically copied by the call.
            unsafe { xpc_connection_send_message(connection, reply.as_raw()) };
        });
        Ok(())
    }
}

/// A bidirectional async XPC connection to a peer process.
///
/// On the **client** side, create one with [`XpcConnection::connect`].
/// On the **server** side, connections are delivered by [`XpcListener::accept`](crate::XpcListener::accept).
/// An [`XpcEndpoint`](crate::XpcEndpoint) can also produce a connection via
/// [`XpcEndpoint::into_connection`](crate::XpcEndpoint::into_connection) without a launchd service name.
///
/// ## Sending
///
/// - [`send`](Self::send) — fire-and-forget; queues the message and returns immediately.
/// - [`send_request`](Self::send_request) — awaits a [`XpcMessage::Dictionary`] reply
///   from the peer (the peer calls [`ReceivedXpcMessage::reply`]).
///
/// ## Receiving
///
/// [`recv`](Self::recv) yields the next [`XpcEvent`]. After an
/// [`XpcEvent::Error`] the connection is permanently closed; further `recv` calls
/// return `None`.
///
/// ## Lifecycle
///
/// The connection is cancelled automatically on [`Drop`]. You may also call
/// [`cancel`](Self::cancel) explicitly. [`suspend`](Self::suspend) and
/// [`resume`](Self::resume) gate event delivery and must be called in balanced pairs.
///
/// ## Peer identity
///
/// [`pid`](Self::pid), [`euid`](Self::euid), [`egid`](Self::egid),
/// [`asid`](Self::asid), and [`name`](Self::name) expose kernel-reported peer
/// credentials. For security decisions, prefer [`asid`](Self::asid) over
/// [`pid`](Self::pid): audit session IDs are stable within a login session and
/// are not subject to PID recycling.
///
/// ## Security
///
/// Pass a [`PeerSecurityRequirement`](crate::PeerSecurityRequirement) to
/// [`XpcClientConfig`](crate::XpcClientConfig) or
/// [`XpcListenerConfig`](crate::XpcListenerConfig) to restrict which peer binaries
/// may connect. The kernel enforces the constraint before any message is delivered.
#[derive(Debug)]
pub struct XpcConnection {
    // Safety invariant: `connection` has been activated (and given an event handler).
    connection: ConnectionObject,
    // Safety invariant: `Created` only if `connection` was returned by an
    // `xpc_connection_create*` call.
    origin: ConnectionOrigin,
    // Safety invariant: never exceeds the number of returned `xpc_connection_suspend`
    // calls on `connection` not yet balanced by an `xpc_connection_resume`.
    suspend_count: AtomicUsize,
    extensions: Extensions,
    receiver: Receiver<XpcEvent>,
    /// Per-request timeout for [`send_request`](Self::send_request); `None` waits
    /// indefinitely. Set via [`with_call_timeout`](Self::with_call_timeout).
    call_timeout: Option<std::time::Duration>,
}

impl XpcConnection {
    /// Activate a connection this process created.
    pub(crate) fn from_inactive(
        connection: InactiveXpcConnection,
        capacity: usize,
        peer_event_capacity: usize,
    ) -> Self {
        let (sender, receiver) = channel(capacity.max(1));
        let connection = connection.activate(|handler_connection| {
            Self::event_handler(handler_connection, sender, peer_event_capacity)
        });
        Self::activated(connection, ConnectionOrigin::Created, receiver)
    }

    /// Accept a peer connection delivered to a listener's event handler.
    ///
    /// # Safety
    ///
    /// The caller must ensure `raw` is a peer connection passed to the currently running
    /// event-handler invocation of a listener connection, and that no
    /// [`ConnectionObject`] for it exists yet.
    pub(crate) unsafe fn accept_received(
        raw: xpc_object_t,
        capacity: usize,
        peer_event_capacity: usize,
    ) -> Self {
        // SAFETY: the handler argument is live and retainable whatever its type
        // (`xpc_connection_set_event_handler`); the new reference is owned below.
        unsafe { xpc_retain(raw) };
        // ConnectionObject invariant: a fresh lock is shared by all aliases, as no other
        // `ConnectionObject` exists (contract); releases are valid because libxpc keeps
        // its own reference to a delivered connection until it is invalid.
        let connection = ConnectionObject {
            raw: raw.cast(),
            calls: Arc::new(Mutex::new(())),
        };
        let (sender, receiver) = channel(capacity.max(1));
        let handler = Self::event_handler(connection.retain_clone(), sender, peer_event_capacity);
        connection.with_raw(|raw| {
            // SAFETY: requires a live connection and a non-null `void (^)(xpc_object_t)`
            // block (`XPC_NONNULL_ALL`); `raw` is live under the call lock and
            // `handler.as_block_ptr()` is such a block (`XpcHandler`). The parameter is
            // escaping, so libxpc keeps its own `Block_copy` after `handler` drops.
            unsafe { xpc_connection_set_event_handler(raw, handler.as_block_ptr()) };
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`), as above.
            unsafe { xpc_connection_activate(raw) };
        });
        Self::activated(connection, ConnectionOrigin::Received, receiver)
    }

    /// The handler holds its own reference on the connection: xpc_object(3) requires
    /// objects used by asynchronously executed blocks to be retained by the block. libxpc
    /// is observed to release the handler after the final `XPC_ERROR_CONNECTION_INVALID`
    /// that `Drop`'s cancel schedules, breaking the cycle; otherwise it would only leak.
    fn event_handler(
        handler_connection: ConnectionObject,
        sender: Sender<XpcEvent>,
        peer_event_capacity: usize,
    ) -> XpcHandler {
        let peer_event_capacity = peer_event_capacity.max(1);
        XpcHandler::new(move |event: xpc_object_t| {
            // SAFETY: `event` is the argument of this event-handler invocation of
            // `handler_connection`.
            let event = unsafe { map_event(&handler_connection, event, peer_event_capacity) };
            forward_event(&sender, event);
        })
    }

    fn activated(
        connection: ConnectionObject,
        origin: ConnectionOrigin,
        receiver: Receiver<XpcEvent>,
    ) -> Self {
        let connection = Self {
            connection,
            origin,
            suspend_count: AtomicUsize::new(0),
            extensions: Extensions::new(),
            receiver,
            call_timeout: None,
        };
        tracing::info!(pid = connection.pid(), "xpc peer connection activated");
        connection
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the per-request timeout for [`send_request`](Self::send_request); `None`
        /// waits indefinitely.
        pub fn call_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
            self.call_timeout = timeout;
            self
        }
    }

    /// Current per-request timeout, if any. See [`with_call_timeout`](Self::with_call_timeout).
    pub fn call_timeout(&self) -> Option<std::time::Duration> {
        self.call_timeout
    }

    /// Await the next event from the peer.
    ///
    /// Cancel-safe: dropping this future before it resolves does not discard any
    /// pending event; the next call to `recv` will yield it.
    ///
    /// Returns `None` when the connection has been closed and the internal channel
    /// is drained. After receiving [`XpcEvent::Error`] the channel will close and
    /// subsequent calls will return `None`.
    pub async fn recv(&mut self) -> Option<XpcEvent> {
        self.receiver.recv().await
    }

    /// Send a message to the peer without waiting for a reply.
    ///
    /// The message is queued and the call returns immediately. Use
    /// [`send_request`](Self::send_request) when you need the peer's response.
    pub fn send(&self, message: XpcMessage) -> Result<(), XpcError> {
        tracing::trace!(message = ?message, "xpc send");
        Self::ensure_dictionary(&message)?;
        let object = OwnedXpcObject::from_message(message)?;
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection and a dictionary message
            // (`XPC_NONNULL_ALL`); `connection` is live under the call lock and `object`
            // is a dictionary (`ensure_dictionary`), logically copied by the call.
            unsafe { xpc_connection_send_message(connection, object.as_raw()) };
        });
        Ok(())
    }

    /// Send a message and await a [`XpcMessage::Dictionary`] reply from the peer.
    ///
    /// **Not cancel-safe.** The message is enqueued with XPC before this future is
    /// polled for the reply. If the future is dropped after the message has been sent
    /// but before the peer replies, the message is already in flight — the peer will
    /// still receive and process it, but the reply will be silently discarded.
    ///
    /// The peer satisfies the future by calling [`ReceivedXpcMessage::reply`] on the
    /// corresponding received message. Returns [`XpcError::ReplyCanceled`] if the
    /// connection closes before a reply is delivered.
    pub async fn send_request(&self, message: XpcMessage) -> Result<XpcMessage, XpcError> {
        tracing::trace!(message = ?message, "xpc send request");
        Self::ensure_dictionary(&message)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        let reply_sender = Mutex::new(Some(reply_sender));
        // xpc_object(3): an object used by an asynchronously executed block is retained
        // for it; the handler is released after its single invocation.
        let reply_connection = self.connection.retain_clone();

        {
            // Scoped: `OwnedXpcObject` and `XpcHandler` must not live across the await.
            let object = OwnedXpcObject::from_message(message)?;
            let handler = XpcHandler::new(move |reply: xpc_object_t| {
                // SAFETY (both blocks): `reply` is the non-null `xpc_handler_t` argument,
                // live for this invocation (the caller is not responsible for releasing
                // it). Graph condition: as for `map_event`, a delivered reply is a new
                // object reachable only through this argument, decoded here.
                let error = unsafe { map_connection_error(&reply_connection, reply) };
                let result = match error {
                    // Preserve the specific connection-error variant (Interrupted /
                    // Invalidated / PeerRequirementFailed).
                    Some(error) => Err(XpcError::Connection(error)),
                    None => unsafe { OwnedXpcObject::retain(reply, "async reply") }
                        .and_then(|reply| reply.to_message()),
                };

                if let Some(reply_sender) = reply_sender.lock().take() {
                    _ = reply_sender.send(result);
                }
            });

            self.connection.with_raw(|connection| {
                // SAFETY: requires a live connection, a dictionary message and a non-null
                // `void (^)(xpc_object_t)` block (`XPC_NONNULL1 XPC_NONNULL2
                // XPC_NONNULL4`); a null `replyq` selects the connection's target queue.
                // `connection` is live under the call lock, `object` is a dictionary
                // (`ensure_dictionary`), and `handler.as_block_ptr()` is such a block
                // (`XpcHandler`). The handler is escaping (no `XPC_NOESCAPE`), so libxpc
                // keeps its own `Block_copy` after `handler` drops.
                unsafe {
                    xpc_connection_send_message_with_reply(
                        connection,
                        object.as_raw(),
                        ptr::null_mut(),
                        handler.as_block_ptr(),
                    );
                }
            });
        }

        let reply = match self.call_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, reply_receiver).await {
                Ok(res) => res.map_err(|_e| XpcError::ReplyCanceled)??,
                Err(_elapsed) => return Err(XpcError::CallTimedOut(timeout)),
            },
            None => reply_receiver
                .await
                .map_err(|_e| XpcError::ReplyCanceled)??,
        };
        tracing::trace!(reply = ?reply, "xpc received reply");
        Ok(reply)
    }

    /// libxpc aborts the process on a non-dictionary top-level message; reject it
    /// as a recoverable [`XpcError::InvalidMessage`] instead.
    fn ensure_dictionary(message: &XpcMessage) -> Result<(), XpcError> {
        if matches!(message, XpcMessage::Dictionary(_)) {
            Ok(())
        } else {
            Err(XpcError::InvalidMessage(rama_utils::str::arcstr::arcstr!(
                "top-level xpc connection message must be a Dictionary"
            )))
        }
    }

    /// Send a selector call to the peer without waiting for a reply.
    ///
    /// Encodes `selector` and `arguments` into the standard
    /// `{"$selector": …, "$arguments": […]}` wire format and calls [`send`](Self::send).
    pub fn send_selector(
        &self,
        selector: ArcStr,
        arguments: Vec<XpcMessage>,
    ) -> Result<(), XpcError> {
        let call = XpcCall::with_arguments(selector, arguments);
        self.send(call.into())
    }

    /// Send a selector call and await a reply [`XpcMessage`].
    ///
    /// Encodes the call in the standard wire format and calls
    /// [`send_request`](Self::send_request).  The raw reply dictionary is returned
    /// as-is; use [`extract_result`](crate::router::extract_result) to decode a
    /// `{"$result": …}` reply produced by a typed [`XpcMessageRouter`](crate::XpcMessageRouter) handler.
    ///
    /// **Not cancel-safe** — see [`send_request`](Self::send_request).
    pub async fn request_selector(
        &self,
        selector: ArcStr,
        arguments: Vec<XpcMessage>,
    ) -> Result<XpcMessage, XpcError> {
        let call = XpcCall::with_arguments(selector, arguments);
        self.send_request(call.into()).await
    }

    /// Send a typed request to a selector and await a deserialized reply.
    ///
    /// `req` is serialized via [`to_xpc_message`](crate::to_xpc_message) and
    /// placed as the sole entry in the `$arguments` array.  The reply is expected to
    /// be a `{"$result": …}` dictionary as produced by a typed
    /// [`XpcMessageRouter`](crate::XpcMessageRouter) handler; the `$result` value is
    /// deserialized as `Res`.
    ///
    /// **Not cancel-safe** — see [`send_request`](Self::send_request).
    pub async fn request_typed<Req, Res>(
        &self,
        selector: ArcStr,
        req: &Req,
    ) -> Result<Res, XpcError>
    where
        Req: serde::Serialize,
        Res: serde::de::DeserializeOwned,
    {
        let arg = xpc_serde::to_xpc_message(req)?;
        let reply = self.request_selector(selector, vec![arg]).await?;
        extract_result(reply)
    }

    /// Process ID of the remote peer at the time the connection was established.
    ///
    /// PIDs are recycled by the kernel. For session-stable identity, use [`asid`](Self::asid).
    pub fn pid(&self) -> i32 {
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is one.
            unsafe { xpc_connection_get_pid(connection) }
        })
    }

    /// Effective user ID of the remote peer.
    pub fn euid(&self) -> u32 {
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is one.
            unsafe { xpc_connection_get_euid(connection) }
        })
    }

    /// Effective group ID of the remote peer.
    pub fn egid(&self) -> u32 {
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is one.
            unsafe { xpc_connection_get_egid(connection) }
        })
    }

    /// Audit session identifier of the remote peer.
    ///
    /// The audit session ID is a kernel-assigned, per-session identity that is stable
    /// across PID recycling within the same login session. It is more reliable than
    /// [`pid`](Self::pid) for session-level identity checks.
    pub fn asid(&self) -> i32 {
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is one.
            unsafe { xpc_connection_get_asid(connection) }
        })
    }

    /// Service name of this connection, if any.
    ///
    /// Returns `None` for anonymous or peer connections created from endpoints.
    pub fn name(&self) -> Option<String> {
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is one.
            // Returns the connection's service name or NULL (handled below).
            let ptr = unsafe { xpc_connection_get_name(connection) };
            if ptr.is_null() {
                return None;
            }
            // SAFETY: `CStr::from_ptr` needs a non-null NUL-terminated buffer unmutated
            // while borrowed. `ptr` is non-null (checked) and is the name the connection
            // was created with, kept alive by `self.connection`; the borrow ends at
            // `into_owned`, inside the call lock.
            Some(
                unsafe { CStr::from_ptr(ptr) }
                    .to_string_lossy()
                    .into_owned(),
            )
        })
    }

    /// Explicitly cancel the connection.
    ///
    /// Safe to call multiple times — canceling an already-canceled connection is a no-op.
    /// The connection is also canceled automatically on [`Drop`].
    pub fn cancel(&self) {
        tracing::debug!("xpc connection cancel");
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is an
            // activated one (field invariant), on which cancel is valid.
            unsafe { xpc_connection_cancel(connection) };
        });
    }

    /// Suspend event delivery on the connection.
    ///
    /// Balance it with [`resume`](Self::resume). Suspensions still outstanding when the
    /// connection is dropped are resumed automatically, as libxpc requires before release.
    pub fn suspend(&self) {
        tracing::trace!("xpc connection suspend");
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is one.
            unsafe { xpc_connection_suspend(connection) };
        });
        // Counted only after the suspend returned (field invariant). Release pairs with
        // the Acquire in `resume`, ordering this suspend before the resume it enables.
        self.suspend_count.fetch_add(1, Ordering::AcqRel);
    }

    /// Resume a previously suspended connection.
    ///
    /// A call without a matching [`suspend`](Self::suspend) is ignored: libxpc treats
    /// resuming more often than suspending as a fatal error.
    pub fn resume(&self) {
        let mut current = self.suspend_count.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_sub(1) else {
                tracing::debug!("xpc connection resume without matching suspend; ignored");
                return;
            };
            match self.suspend_count.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        tracing::trace!("xpc connection resume");
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is one.
            // The decrement above consumed one completed, unbalanced suspend (field
            // invariant), so this resume does not over-resume.
            unsafe { xpc_connection_resume(connection) };
        });
    }

    /// Run `f` under the call lock with a connection this process created; fails with
    /// [`XpcError::EndpointUnsupported`] for a listener-delivered peer.
    ///
    /// # Safety-usable invariant
    ///
    /// `f` receives a live connection returned by an `xpc_connection_create*` call, with
    /// the guarantees of [`ConnectionObject::with_raw`].
    pub(crate) fn with_created_raw<R>(
        &self,
        f: impl FnOnce(xpc_connection_t) -> R,
    ) -> Result<R, XpcError> {
        match self.origin {
            ConnectionOrigin::Created => Ok(self.connection.with_raw(f)),
            ConnectionOrigin::Received => Err(XpcError::EndpointUnsupported),
        }
    }
}

impl ExtensionsRef for XpcConnection {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
        let suspended = *self.suspend_count.get_mut();
        self.connection.with_raw(|connection| {
            // SAFETY: requires a live connection (`XPC_NONNULL_ALL`); `connection` is an
            // activated one (field invariant), on which cancel is valid.
            unsafe { xpc_connection_cancel(connection) };
            // <xpc/connection.h>: suspends must be balanced before the last release.
            for _ in 0..suspended {
                // SAFETY: as above; `&mut self` rules out concurrent `suspend`/`resume`,
                // so `suspended` is exactly the number of unbalanced suspends.
                unsafe { xpc_connection_resume(connection) };
            }
        });
    }
}

impl Service<XpcMessage> for XpcConnection {
    type Output = ();
    type Error = XpcError;

    async fn serve(&self, input: XpcMessage) -> Result<Self::Output, Self::Error> {
        self.send(input)
    }
}

/// Classify one event delivered to `connection`'s event handler.
///
/// # Safety
///
/// The caller must ensure `event` is the argument of the currently running
/// event-handler invocation of `connection`.
unsafe fn map_event(
    connection: &ConnectionObject,
    event: xpc_object_t,
    peer_event_capacity: usize,
) -> XpcEvent {
    // SAFETY: the handler argument is non-null and live for the invocation (contract).
    if unsafe { raw_type_is(event, &raw const _xpc_type_connection) } {
        tracing::info!("xpc listener received peer connection");
        // SAFETY: `event` is a peer connection delivered to this listener invocation
        // (contract, checked type); libxpc delivers each peer once, so no
        // `ConnectionObject` for it exists yet.
        return XpcEvent::Connection(unsafe {
            XpcConnection::accept_received(event, peer_event_capacity, peer_event_capacity)
        });
    }

    // SAFETY: the handler argument is non-null and live for this invocation (contract).
    if let Some(error) = unsafe { map_connection_error(connection, event) } {
        tracing::debug!(?error, "xpc connection lifecycle event");
        return XpcEvent::Error(error);
    }

    // SAFETY: the handler argument is live for this invocation and retainable
    // (`xpc_connection_set_event_handler`). Collection graph: the delivered message is
    // a new object (the sender's dictionary is logically copied,
    // `xpc_connection_send_message`) reachable only through this argument, and this
    // crate keeps no owner of it or its non-endpoint children past this call.
    let event = match unsafe { OwnedXpcObject::retain(event, "peer event") } {
        Ok(event) => event,
        Err(err) => {
            return XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
                err.to_string(),
            ))));
        }
    };

    if !event.is_type(&raw const _xpc_type_dictionary) {
        return XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
            "unexpected non-dictionary xpc event",
        ))));
    }

    let message = match event.to_message() {
        Ok(message) => message,
        Err(err) => {
            return XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
                err.to_string(),
            ))));
        }
    };
    tracing::trace!(message = ?message, "xpc incoming message");

    // SAFETY: requires a non-null live object (`XPC_NONNULL_ALL`); `event` is one, used
    // only on this thread. Returns a new +1 reply dictionary, or NULL when the message
    // has no reply context (fire-and-forget), handled below. The reply dictionary holds
    // the message's transaction until it is sent or released (`xpc_transaction_begin`).
    let reply = unsafe { xpc_dictionary_create_reply(event.as_raw()) };
    let reply = if reply.is_null() {
        None
    } else {
        // SAFETY: `reply` is the non-null +1 dictionary just returned, with no other
        // owner; ownership moves.
        match unsafe { OwnedXpcObject::from_raw(reply, "reply message") } {
            // `PendingReply` invariant: a new, empty dictionary owned only here.
            Ok(dictionary) => Some(PendingReply { dictionary }),
            Err(err) => {
                return XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
                    err.to_string(),
                ))));
            }
        }
    };

    // Independent retain on the connection so a held ReceivedXpcMessage outlives its
    // parent XpcConnection if necessary (reply remains safe).
    XpcEvent::Message(ReceivedXpcMessage {
        connection: connection.retain_clone(),
        message,
        reply,
    })
}

/// Send `event` on `sender` with backpressure-aware semantics.
///
/// On a full channel we **drop the new event** and log a warning. Graceful-by-default:
/// a stuck reader cannot make us crash, deadlock, or grow memory without bound.
/// Closed channels (receiver dropped) are logged because they can explain missing
/// request handling for a peer that was otherwise accepted by libxpc.
pub(crate) fn forward_event(sender: &Sender<XpcEvent>, event: XpcEvent) {
    match sender.try_send(event) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            tracing::warn!(
                capacity = sender.max_capacity(),
                "xpc connection event channel full; dropping event"
            );
        }
        Err(TrySendError::Closed(_)) => {
            tracing::warn!("xpc connection event channel closed; dropping event");
        }
    }
}

/// Serialises this crate's reads of libxpc's process-wide `XPC_ERROR_*` dictionaries,
/// which every connection's handlers share.
static ERROR_OBJECT_CALLS: Mutex<()> = Mutex::new(());

/// Map an `XPC_TYPE_ERROR` event to its error; `None` for any other event.
///
/// # Safety
///
/// The caller must ensure `event` is a non-null libxpc object that is live for the call.
pub(crate) unsafe fn map_connection_error(
    connection: &ConnectionObject,
    event: xpc_object_t,
) -> Option<XpcConnectionError> {
    // SAFETY: `event` is non-null and live (contract).
    if !unsafe { raw_type_is(event, &raw const _xpc_type_error) } {
        return None;
    }

    let event_ptr = event.cast_const();
    if ptr::eq(
        event_ptr,
        (&raw const _xpc_error_connection_interrupted).cast(),
    ) {
        return Some(XpcConnectionError::Interrupted);
    }

    if ptr::eq(
        event_ptr,
        (&raw const _xpc_error_peer_code_signing_requirement).cast(),
    ) {
        // SAFETY: `event` is a live error object (checked above, contract).
        return Some(XpcConnectionError::PeerRequirementFailed(unsafe {
            connection_error_description(connection, event)
        }));
    }

    // SAFETY: as above.
    Some(XpcConnectionError::Invalidated(unsafe {
        connection_error_description(connection, event)
    }))
}

/// # Safety
///
/// The caller must ensure `event` is an `XPC_TYPE_ERROR` object live for the call.
unsafe fn connection_error_description(
    connection: &ConnectionObject,
    event: xpc_object_t,
) -> Option<ArcStr> {
    let copied = connection.with_raw(|connection| {
        // SAFETY: requires a live connection (`XPC_NONNULL1`); `connection` is one, under
        // the call lock. Returns NULL or a caller-owned NUL-terminated string (libxpc
        // `copy` naming, released with free(3) as for `xpc_copy_description` in
        // xpc_object(3)).
        unsafe { xpc_connection_copy_invalidation_reason(connection) }
    });
    if !copied.is_null() {
        // SAFETY: `copied` is non-null (checked), NUL-terminated and owned by this
        // function until the `free` below; the borrow ends before it.
        let value = ArcStr::from(unsafe { CStr::from_ptr(copied) }.to_string_lossy());
        // SAFETY: `free` requires a pointer from the C allocator not freed yet; `copied`
        // is the caller-owned string returned above and is not used afterwards. It must
        // not go to `CString::from_raw`, which frees with Rust's allocator.
        unsafe { libc_free(copied.cast::<c_void>()) };
        return Some(value);
    }

    // SAFETY: reads the immutable extern static `const char *const
    // _xpc_error_key_description` (<xpc/xpc.h>); a pointer copy, no reference is formed.
    let key = unsafe { _xpc_error_key_description };
    if key.is_null() {
        return None;
    }

    let _calls = ERROR_OBJECT_CALLS.lock();
    // SAFETY: requires a live dictionary and a non-null NUL-terminated key
    // (`XPC_NONNULL_ALL`); error objects are dictionaries (`XPC_TYPE_ERROR`). `event` is
    // live (contract), `key` is non-null (checked) and libxpc's own key constant. This
    // crate never mutates error objects and reads them only under `ERROR_OBJECT_CALLS`.
    let value = unsafe { xpc_dictionary_get_string(event, key) };
    if value.is_null() {
        return None;
    }

    Some(ArcStr::from(
        // SAFETY: `value` is non-null (checked) and NUL-terminated, owned by `event`
        // which outlives the borrow; the lock above is still held.
        unsafe { CStr::from_ptr(value) }.to_string_lossy(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{InactiveXpcConnection, XpcHandler};
    use crate::ffi::{xpc_connection_cancel, xpc_connection_create};

    /// Activation moves the call lock into the returned owner; once every owner is gone
    /// the lock is freed.
    #[test]
    fn activation_does_not_leak_call_lock() {
        // SAFETY: a NULL name creates an anonymous listener connection; NULL `targetq` is
        // allowed. Returns a +1, inactive connection.
        let raw = unsafe { xpc_connection_create(std::ptr::null(), std::ptr::null_mut()) };
        // SAFETY: `raw` is the +1, not yet activated result of `xpc_connection_create`
        // with no other alias; ownership moves.
        let inactive = unsafe { InactiveXpcConnection::from_raw(raw, "test connection") }
            .expect("inactive connection");
        let calls = Arc::downgrade(&inactive.calls);

        let connection = inactive.activate(|alias| {
            drop(alias);
            XpcHandler::new(|_event| {})
        });
        connection.with_raw(|raw| {
            // SAFETY: requires a live connection; `raw` is an activated one.
            unsafe { xpc_connection_cancel(raw) };
        });
        drop(connection);

        assert_eq!(calls.strong_count(), 0);
    }
}
