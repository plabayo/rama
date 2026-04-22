use std::{
    ffi::{CStr, CString},
    ops::Deref,
    ptr,
};

use parking_lot::Mutex;
use rama_core::{
    Service,
    extensions::{Extensions, ExtensionsRef},
};
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::{
    mpsc::{UnboundedReceiver, unbounded_channel},
    oneshot,
};

use crate::{
    block::ConcreteBlock,
    error::{XpcConnectionError, XpcError},
    ffi::{
        _xpc_error_connection_interrupted, _xpc_error_connection_invalid,
        _xpc_error_key_description, _xpc_error_peer_code_signing_requirement, _xpc_type_error,
        xpc_connection_cancel, xpc_connection_copy_invalidation_reason, xpc_connection_get_asid,
        xpc_connection_get_egid, xpc_connection_get_euid, xpc_connection_get_name,
        xpc_connection_get_pid, xpc_connection_resume, xpc_connection_send_message,
        xpc_connection_send_message_with_reply, xpc_connection_set_event_handler,
        xpc_connection_suspend, xpc_connection_t, xpc_dictionary_create_reply,
        xpc_dictionary_get_string, xpc_dictionary_set_value, xpc_object_t,
    },
    message::XpcMessage,
    object::OwnedXpcObject,
    util::make_c_string,
};

/// An event received on an [`XpcConnection`].
#[derive(Debug)]
pub enum XpcEvent {
    /// An incoming message from the peer.
    Message(ReceivedXpcMessage),
    /// A connection lifecycle error. After this event the connection is permanently closed.
    Error(XpcConnectionError),
}

/// An incoming XPC message together with the context needed to send a reply.
///
/// Obtained from [`XpcEvent::Message`] via [`XpcConnection::recv`].
#[derive(Debug)]
pub struct ReceivedXpcMessage {
    connection: xpc_connection_t,
    message: XpcMessage,
    raw_event: OwnedXpcObject,
}

unsafe impl Send for ReceivedXpcMessage {}
unsafe impl Sync for ReceivedXpcMessage {}

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
    pub fn reply(&self, message: XpcMessage) -> Result<(), XpcError> {
        let XpcMessage::Dictionary(values) = message else {
            return Err(XpcError::ReplyNotExpected);
        };

        // SAFETY: self.raw_event.raw is a valid XPC dictionary object retained by
        // OwnedXpcObject. xpc_dictionary_create_reply returns a new retained dictionary
        // or NULL if the message does not support replies.
        let reply = unsafe { xpc_dictionary_create_reply(self.raw_event.raw) };
        let reply = OwnedXpcObject::from_raw(reply, "reply message")?;

        for (key, value) in values {
            let key = make_c_string(&key)?;
            let value = OwnedXpcObject::from_message(value)?;
            // SAFETY: reply.raw is a valid mutable XPC dictionary. key.as_ptr() is a
            // valid null-terminated C string. value.raw is a valid retained XPC object.
            unsafe { xpc_dictionary_set_value(reply.raw, key.as_ptr(), value.raw) };
        }

        // SAFETY: self.connection is the raw connection from which this message was
        // received; it remains valid because the kernel keeps the connection alive while
        // an event handler block is executing. reply.raw is a valid retained XPC object.
        unsafe { xpc_connection_send_message(self.connection, reply.raw) };
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
    connection: OwnedXpcObject,
    extensions: Extensions,
    receiver: UnboundedReceiver<XpcEvent>,
}

unsafe impl Send for XpcConnection {}
unsafe impl Sync for XpcConnection {}

impl XpcConnection {
    pub(crate) fn from_owned_peer(connection: OwnedXpcObject) -> Result<Self, XpcError> {
        let (sender, receiver) = unbounded_channel();
        let raw_connection = connection.raw as xpc_connection_t;

        let block = ConcreteBlock::new(move |event: xpc_object_t| {
            let Ok(retained) = OwnedXpcObject::retain(event, "peer event") else {
                return;
            };
            let event = map_event(raw_connection, retained);
            let _ = sender.send(event);
        })
        .copy();

        // SAFETY: raw_connection is a valid, non-null xpc_connection_t from OwnedXpcObject.
        // block is a heap-allocated copied Block whose lifetime is managed by XPC after
        // xpc_connection_set_event_handler transfers ownership. xpc_connection_resume
        // activates the connection; it must be called exactly once before any messages
        // are sent or received.
        unsafe {
            xpc_connection_set_event_handler(raw_connection, block.deref() as *const _ as *mut _);
            xpc_connection_resume(raw_connection);
        }

        Ok(Self {
            connection,
            extensions: Extensions::new(),
            receiver,
        })
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
        let object = OwnedXpcObject::from_message(message)?;
        // SAFETY: self.connection.raw is a valid xpc_connection_t held by OwnedXpcObject
        // for the lifetime of &self. object.raw is a valid retained XPC object.
        unsafe { xpc_connection_send_message(self.connection.raw as xpc_connection_t, object.raw) };
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
        let object = OwnedXpcObject::from_message(message)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        let reply_sender = Mutex::new(Some(reply_sender));
        let raw_connection = self.connection.raw as xpc_connection_t;

        let block = ConcreteBlock::new(move |reply: xpc_object_t| {
            let result = match OwnedXpcObject::retain(reply, "async reply") {
                Ok(reply) => match map_connection_error(raw_connection, &reply) {
                    Some(err) => Err(XpcError::Connection(err)),
                    None => reply.to_message(),
                },
                Err(err) => Err(err),
            };

            if let Some(reply_sender) = reply_sender.lock().take() {
                let _ = reply_sender.send(result);
            }
        })
        .copy();

        // SAFETY: raw_connection is a valid xpc_connection_t. object.raw is a valid
        // retained XPC object. The queue argument is null, so XPC uses the connection's
        // own queue. block is a heap-allocated copied Block; XPC retains it until after
        // the callback fires, at which point it is released.
        unsafe {
            xpc_connection_send_message_with_reply(
                raw_connection,
                object.raw,
                ptr::null_mut(),
                block.deref() as *const _ as *mut _,
            );
        }

        reply_receiver.await.map_err(|_| XpcError::ReplyCanceled)?
    }

    /// Process ID of the remote peer at the time the connection was established.
    ///
    /// PIDs are recycled by the kernel. For session-stable identity, use [`asid`](Self::asid).
    pub fn pid(&self) -> i32 {
        // SAFETY: self.connection.raw is a valid, non-null xpc_connection_t for &self's lifetime.
        unsafe { xpc_connection_get_pid(self.connection.raw as xpc_connection_t) }
    }

    /// Effective user ID of the remote peer.
    pub fn euid(&self) -> u32 {
        // SAFETY: Same as pid().
        unsafe { xpc_connection_get_euid(self.connection.raw as xpc_connection_t) }
    }

    /// Effective group ID of the remote peer.
    pub fn egid(&self) -> u32 {
        // SAFETY: Same as pid().
        unsafe { xpc_connection_get_egid(self.connection.raw as xpc_connection_t) }
    }

    /// Audit session identifier of the remote peer.
    ///
    /// The audit session ID is a kernel-assigned, per-session identity that is stable
    /// across PID recycling within the same login session. It is more reliable than
    /// [`pid`](Self::pid) for session-level identity checks.
    pub fn asid(&self) -> i32 {
        // SAFETY: Same as pid().
        unsafe { xpc_connection_get_asid(self.connection.raw as xpc_connection_t) }
    }

    /// Service name of this connection, if any.
    ///
    /// Returns `None` for anonymous or peer connections created from endpoints.
    pub fn name(&self) -> Option<String> {
        // SAFETY: self.connection.raw is a valid xpc_connection_t. The returned pointer
        // is either null or a valid C string borrowed from the connection object; it
        // remains valid for &self's lifetime. We copy it to a String before returning.
        let ptr = unsafe { xpc_connection_get_name(self.connection.raw as xpc_connection_t) };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: ptr is non-null and points to a valid, null-terminated C string
        // owned by the XPC connection object, as guaranteed by the API contract above.
        Some(
            unsafe { std::ffi::CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    /// Explicitly cancel the connection.
    ///
    /// Safe to call multiple times — canceling an already-canceled connection is a no-op.
    /// The connection is also canceled automatically on [`Drop`].
    pub fn cancel(&self) {
        // SAFETY: self.connection.raw is a valid xpc_connection_t. xpc_connection_cancel
        // is idempotent per Apple's documentation.
        unsafe { xpc_connection_cancel(self.connection.raw as xpc_connection_t) };
    }

    /// Suspend event delivery on the connection.
    ///
    /// Every call to `suspend` must be balanced by a corresponding call to [`resume`](Self::resume)
    /// before the connection is released. Unbalanced suspends will cause a crash.
    pub fn suspend(&self) {
        // SAFETY: self.connection.raw is a valid xpc_connection_t for &self's lifetime.
        unsafe { xpc_connection_suspend(self.connection.raw as xpc_connection_t) };
    }

    /// Resume a previously suspended connection.
    ///
    /// Must be called once for each preceding call to [`suspend`](Self::suspend).
    pub fn resume(&self) {
        // SAFETY: Same as suspend().
        unsafe { xpc_connection_resume(self.connection.raw as xpc_connection_t) };
    }

    pub(crate) fn connection_raw(&self) -> xpc_connection_t {
        self.connection.raw as xpc_connection_t
    }
}

impl ExtensionsRef for XpcConnection {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
        // SAFETY: self.connection.raw is a valid xpc_connection_t. xpc_connection_cancel
        // is idempotent, so calling it here after an explicit cancel() is safe.
        unsafe { xpc_connection_cancel(self.connection.raw as xpc_connection_t) };
    }
}

impl Service<XpcMessage> for XpcConnection {
    type Output = ();
    type Error = XpcError;

    async fn serve(&self, input: XpcMessage) -> Result<Self::Output, Self::Error> {
        self.send(input)
    }
}

pub(crate) fn map_event(connection: xpc_connection_t, event: OwnedXpcObject) -> XpcEvent {
    if let Some(error) = map_connection_error(connection, &event) {
        return XpcEvent::Error(error);
    }

    match event.to_message() {
        Ok(message) => XpcEvent::Message(ReceivedXpcMessage {
            connection,
            message,
            raw_event: event,
        }),
        Err(err) => XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
            err.to_string(),
        )))),
    }
}

pub(crate) fn map_connection_error(
    connection: xpc_connection_t,
    event: &OwnedXpcObject,
) -> Option<XpcConnectionError> {
    if !event.is_type(unsafe { &_xpc_type_error as *const _ as *const std::ffi::c_void }) {
        return None;
    }

    if ptr::eq(
        event.raw.cast_const(),
        (&raw const _xpc_error_connection_interrupted).cast(),
    ) {
        return Some(XpcConnectionError::Interrupted);
    }

    if ptr::eq(
        event.raw.cast_const(),
        (&raw const _xpc_error_peer_code_signing_requirement).cast(),
    ) {
        return Some(XpcConnectionError::PeerRequirementFailed(
            connection_error_description(connection, event.raw),
        ));
    }

    if ptr::eq(
        event.raw.cast_const(),
        (&raw const _xpc_error_connection_invalid).cast(),
    ) {
        return Some(XpcConnectionError::Invalidated(
            connection_error_description(connection, event.raw),
        ));
    }

    Some(XpcConnectionError::Invalidated(
        connection_error_description(connection, event.raw),
    ))
}

fn connection_error_description(
    connection: xpc_connection_t,
    event: xpc_object_t,
) -> Option<ArcStr> {
    let copied = unsafe { xpc_connection_copy_invalidation_reason(connection) };
    if !copied.is_null() {
        let value = ArcStr::from(unsafe { CString::from_raw(copied) }.to_string_lossy());
        return Some(value);
    }

    let key = unsafe { _xpc_error_key_description };
    if key.is_null() {
        return None;
    }

    let value = unsafe { xpc_dictionary_get_string(event, key) };
    if value.is_null() {
        return None;
    }

    Some(ArcStr::from(
        unsafe { CStr::from_ptr(value) }.to_string_lossy(),
    ))
}
