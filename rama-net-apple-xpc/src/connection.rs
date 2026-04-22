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
        _xpc_error_connection_interrupted, _xpc_error_connection_invalid, _xpc_error_key_description,
        _xpc_error_peer_code_signing_requirement, _xpc_type_error,
        xpc_connection_cancel, xpc_connection_copy_invalidation_reason,
        xpc_connection_get_euid, xpc_connection_get_pid, xpc_connection_resume,
        xpc_connection_send_message, xpc_connection_send_message_with_reply,
        xpc_connection_set_event_handler, xpc_connection_t, xpc_dictionary_create_reply,
        xpc_dictionary_get_string, xpc_dictionary_set_value, xpc_object_t,
    },
    message::XpcMessage,
    object::OwnedXpcObject,
    util::make_c_string,
};

#[derive(Debug)]
pub enum XpcEvent {
    Message(ReceivedXpcMessage),
    Error(XpcConnectionError),
}

#[derive(Debug)]
pub struct ReceivedXpcMessage {
    connection: xpc_connection_t,
    message: XpcMessage,
    raw_event: OwnedXpcObject,
}

unsafe impl Send for ReceivedXpcMessage {}
unsafe impl Sync for ReceivedXpcMessage {}

impl ReceivedXpcMessage {
    pub fn message(&self) -> &XpcMessage {
        &self.message
    }

    pub fn into_message(self) -> XpcMessage {
        self.message
    }

    pub fn reply(&self, message: XpcMessage) -> Result<(), XpcError> {
        let XpcMessage::Dictionary(values) = message else {
            return Err(XpcError::ReplyNotExpected);
        };

        let reply = unsafe { xpc_dictionary_create_reply(self.raw_event.raw) };
        let reply = OwnedXpcObject::from_raw(reply, "reply message")?;

        for (key, value) in values {
            let key = make_c_string(&key)?;
            let value = OwnedXpcObject::from_message(value)?;
            unsafe { xpc_dictionary_set_value(reply.raw, key.as_ptr(), value.raw) };
        }

        unsafe { xpc_connection_send_message(self.connection, reply.raw) };
        Ok(())
    }
}

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

    pub async fn recv(&mut self) -> Option<XpcEvent> {
        self.receiver.recv().await
    }

    pub fn send(&self, message: XpcMessage) -> Result<(), XpcError> {
        let object = OwnedXpcObject::from_message(message)?;
        unsafe { xpc_connection_send_message(self.connection.raw as xpc_connection_t, object.raw) };
        Ok(())
    }

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

    pub fn pid(&self) -> i32 {
        unsafe { xpc_connection_get_pid(self.connection.raw as xpc_connection_t) }
    }

    pub fn euid(&self) -> u32 {
        unsafe { xpc_connection_get_euid(self.connection.raw as xpc_connection_t) }
    }
}

impl ExtensionsRef for XpcConnection {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
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
        return Some(XpcConnectionError::Invalidated(connection_error_description(
            connection, event.raw,
        )));
    }

    Some(XpcConnectionError::Invalidated(connection_error_description(
        connection, event.raw,
    )))
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

    Some(ArcStr::from(unsafe { CStr::from_ptr(value) }.to_string_lossy()))
}
