use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, c_char, c_void},
    fmt,
    ops::Deref,
    os::fd::RawFd,
    ptr,
    sync::mpsc,
};

use block::{Block, ConcreteBlock};
use rama_core::Service;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::ffi::{
    _xpc_error_connection_interrupted, _xpc_error_connection_invalid, _xpc_error_key_description,
    _xpc_error_peer_code_signing_requirement, _xpc_type_array, _xpc_type_bool, _xpc_type_data,
    _xpc_type_dictionary, _xpc_type_double, _xpc_type_error, _xpc_type_fd, _xpc_type_int64,
    _xpc_type_null, _xpc_type_string, _xpc_type_uint64, XPC_CONNECTION_MACH_SERVICE_LISTENER,
    XPC_CONNECTION_MACH_SERVICE_PRIVILEGED, dispatch_queue_create, dispatch_queue_t,
    xpc_array_append_value, xpc_array_apply, xpc_array_create, xpc_array_get_count,
    xpc_bool_create, xpc_bool_get_value, xpc_connection_activate, xpc_connection_cancel,
    xpc_connection_copy_invalidation_reason, xpc_connection_create_mach_service,
    xpc_connection_get_euid, xpc_connection_get_pid, xpc_connection_resume,
    xpc_connection_send_message, xpc_connection_send_message_with_reply_sync,
    xpc_connection_set_event_handler, xpc_connection_set_peer_code_signing_requirement,
    xpc_connection_set_peer_entitlement_exists_requirement,
    xpc_connection_set_peer_entitlement_matches_value_requirement,
    xpc_connection_set_peer_lightweight_code_requirement,
    xpc_connection_set_peer_platform_identity_requirement,
    xpc_connection_set_peer_team_identity_requirement, xpc_connection_t, xpc_data_create,
    xpc_data_get_bytes_ptr, xpc_data_get_length, xpc_dictionary_apply, xpc_dictionary_create,
    xpc_dictionary_create_reply, xpc_dictionary_get_count, xpc_dictionary_get_string,
    xpc_dictionary_set_value, xpc_double_create, xpc_double_get_value, xpc_fd_create, xpc_fd_dup,
    xpc_get_type, xpc_int64_create, xpc_int64_get_value, xpc_null_create, xpc_object_t,
    xpc_release, xpc_retain, xpc_string_create, xpc_string_get_string_ptr, xpc_uint64_create,
    xpc_uint64_get_value,
};

#[derive(Debug, Clone, PartialEq)]
pub enum XpcMessage {
    Null,
    Bool(bool),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    String(String),
    Data(Vec<u8>),
    Fd(RawFd),
    Array(Vec<Self>),
    Dictionary(BTreeMap<String, Self>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XpcConnectionError {
    Interrupted,
    Invalidated(Option<String>),
    PeerRequirementFailed(Option<String>),
}

#[derive(Debug)]
pub enum XpcError {
    InvalidCString(String),
    NullConnection(&'static str),
    NullObject(&'static str),
    UnsupportedObjectType(&'static str),
    QueueCreationFailed,
    PeerRequirementFailed { code: i32, context: &'static str },
    ReplyNotExpected,
    Connection(XpcConnectionError),
}

impl fmt::Display for XpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCString(value) => write!(f, "string contains interior NUL: {value:?}"),
            Self::NullConnection(context) => {
                write!(f, "xpc connection creation returned NULL: {context}")
            }
            Self::NullObject(context) => write!(f, "xpc returned NULL object: {context}"),
            Self::UnsupportedObjectType(kind) => write!(f, "unsupported xpc object type: {kind}"),
            Self::QueueCreationFailed => f.write_str("failed to create dispatch queue"),
            Self::PeerRequirementFailed { code, context } => {
                write!(f, "xpc peer requirement failed with code {code}: {context}")
            }
            Self::ReplyNotExpected => f.write_str("incoming xpc message does not support replies"),
            Self::Connection(err) => write!(f, "{err:?}"),
        }
    }
}

impl std::error::Error for XpcError {}

#[derive(Debug, Clone)]
pub enum PeerSecurityRequirement {
    CodeSigning(String),
    TeamIdentity(Option<String>),
    PlatformIdentity(Option<String>),
    EntitlementExists(String),
    EntitlementMatchesValue {
        entitlement: String,
        value: XpcMessage,
    },
    LightweightCodeRequirement(XpcMessage),
}

#[derive(Debug, Clone)]
pub struct XpcClientConfig {
    service_name: String,
    privileged: bool,
    target_queue_label: Option<String>,
    peer_requirement: Option<PeerSecurityRequirement>,
}

impl XpcClientConfig {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            privileged: false,
            target_queue_label: None,
            peer_requirement: None,
        }
    }

    #[must_use]
    pub fn privileged(mut self, privileged: bool) -> Self {
        self.privileged = privileged;
        self
    }

    #[must_use]
    pub fn target_queue_label(mut self, label: impl Into<String>) -> Self {
        self.target_queue_label = Some(label.into());
        self
    }

    #[must_use]
    pub fn peer_requirement(mut self, requirement: PeerSecurityRequirement) -> Self {
        self.peer_requirement = Some(requirement);
        self
    }
}

#[derive(Debug, Clone)]
pub struct XpcListenerConfig {
    service_name: String,
    target_queue_label: Option<String>,
    peer_requirement: Option<PeerSecurityRequirement>,
}

impl XpcListenerConfig {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            target_queue_label: None,
            peer_requirement: None,
        }
    }

    #[must_use]
    pub fn target_queue_label(mut self, label: impl Into<String>) -> Self {
        self.target_queue_label = Some(label.into());
        self
    }

    #[must_use]
    pub fn peer_requirement(mut self, requirement: PeerSecurityRequirement) -> Self {
        self.peer_requirement = Some(requirement);
        self
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct XpcConnector;

impl Service<XpcClientConfig> for XpcConnector {
    type Output = XpcConnection;
    type Error = XpcError;

    async fn serve(&self, input: XpcClientConfig) -> Result<Self::Output, Self::Error> {
        XpcConnection::connect(input)
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
        let connection = OwnedXpcObject::from_raw(raw as xpc_object_t, "listener connection")?;

        if let Some(requirement) = peer_requirement.as_ref() {
            requirement.apply(connection.as_connection())?;
        }

        let (sender, receiver) = unbounded_channel();
        let raw_connection = connection.as_connection();

        let block = ConcreteBlock::new(move |event: xpc_object_t| {
            if let Ok(peer) = OwnedXpcObject::retain(event, "listener peer connection")
                && let Ok(peer_conn) = XpcConnection::from_incoming_peer(peer)
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
        unsafe { xpc_connection_cancel(self.connection.as_connection()) };
    }
}

#[derive(Debug)]
pub struct XpcConnection {
    connection: OwnedXpcObject,
    receiver: UnboundedReceiver<XpcEvent>,
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
        let connection = OwnedXpcObject::from_raw(raw as xpc_object_t, "client connection")?;

        if let Some(requirement) = peer_requirement.as_ref() {
            requirement.apply(connection.as_connection())?;
        }

        Self::from_owned_peer(connection)
    }

    fn from_incoming_peer(connection: OwnedXpcObject) -> Result<Self, XpcError> {
        Self::from_owned_peer(connection)
    }

    fn from_owned_peer(connection: OwnedXpcObject) -> Result<Self, XpcError> {
        let (sender, receiver) = unbounded_channel();
        let raw_connection = connection.as_connection();

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
            receiver,
        })
    }

    pub async fn recv(&mut self) -> Option<XpcEvent> {
        self.receiver.recv().await
    }

    pub fn send(&self, message: XpcMessage) -> Result<(), XpcError> {
        let object = OwnedXpcObject::from_message(message)?;
        unsafe { xpc_connection_send_message(self.connection.as_connection(), object.raw) };
        Ok(())
    }

    pub fn send_request_sync(&self, message: XpcMessage) -> Result<XpcMessage, XpcError> {
        let object = OwnedXpcObject::from_message(message)?;
        let reply = unsafe {
            xpc_connection_send_message_with_reply_sync(self.connection.as_connection(), object.raw)
        };
        let reply = OwnedXpcObject::from_raw(reply, "sync reply")?;
        match map_connection_error(self.connection.as_connection(), &reply) {
            Some(err) => Err(XpcError::Connection(err)),
            None => reply.to_message(),
        }
    }

    pub fn pid(&self) -> i32 {
        unsafe { xpc_connection_get_pid(self.connection.as_connection()) }
    }

    pub fn euid(&self) -> u32 {
        unsafe { xpc_connection_get_euid(self.connection.as_connection()) }
    }
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
        unsafe { xpc_connection_cancel(self.connection.as_connection()) };
    }
}

impl Service<XpcMessage> for XpcConnection {
    type Output = ();
    type Error = XpcError;

    async fn serve(&self, input: XpcMessage) -> Result<Self::Output, Self::Error> {
        self.send(input)
    }
}

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
        let reply = OwnedXpcObject::from_raw(reply, "reply dictionary")?;
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
struct OwnedXpcObject {
    raw: xpc_object_t,
}

unsafe impl Send for OwnedXpcObject {}
unsafe impl Sync for OwnedXpcObject {}

impl OwnedXpcObject {
    fn from_raw(raw: xpc_object_t, context: &'static str) -> Result<Self, XpcError> {
        if raw.is_null() {
            return Err(XpcError::NullObject(context));
        }
        Ok(Self { raw })
    }

    fn retain(raw: xpc_object_t, context: &'static str) -> Result<Self, XpcError> {
        if raw.is_null() {
            return Err(XpcError::NullObject(context));
        }
        unsafe { xpc_retain(raw) };
        Ok(Self { raw })
    }

    fn from_message(message: XpcMessage) -> Result<Self, XpcError> {
        let raw = match message {
            XpcMessage::Null => unsafe { xpc_null_create() },
            XpcMessage::Bool(value) => unsafe { xpc_bool_create(value) },
            XpcMessage::Int64(value) => unsafe { xpc_int64_create(value) },
            XpcMessage::Uint64(value) => unsafe { xpc_uint64_create(value) },
            XpcMessage::Double(value) => unsafe { xpc_double_create(value) },
            XpcMessage::String(value) => {
                let value = make_c_string(&value)?;
                unsafe { xpc_string_create(value.as_ptr()) }
            }
            XpcMessage::Data(value) => unsafe {
                xpc_data_create(value.as_ptr().cast(), value.len())
            },
            XpcMessage::Fd(value) => unsafe { xpc_fd_create(value) },
            XpcMessage::Array(values) => {
                let raw = unsafe { xpc_array_create(ptr::null_mut(), 0) };
                for value in values {
                    let value = Self::from_message(value)?;
                    unsafe { xpc_array_append_value(raw, value.raw) };
                }
                raw
            }
            XpcMessage::Dictionary(values) => {
                let raw = unsafe { xpc_dictionary_create(ptr::null(), ptr::null_mut(), 0) };
                for (key, value) in values {
                    let key = make_c_string(&key)?;
                    let value = Self::from_message(value)?;
                    unsafe { xpc_dictionary_set_value(raw, key.as_ptr(), value.raw) };
                }
                raw
            }
        };
        Self::from_raw(raw, "message encode")
    }

    fn to_message(&self) -> Result<XpcMessage, XpcError> {
        if self.is_type(unsafe { &_xpc_type_null as *const _ as *const c_void }) {
            return Ok(XpcMessage::Null);
        }
        if self.is_type(unsafe { &_xpc_type_bool as *const _ as *const c_void }) {
            return Ok(XpcMessage::Bool(unsafe { xpc_bool_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_int64 as *const _ as *const c_void }) {
            return Ok(XpcMessage::Int64(unsafe { xpc_int64_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_uint64 as *const _ as *const c_void }) {
            return Ok(XpcMessage::Uint64(unsafe {
                xpc_uint64_get_value(self.raw)
            }));
        }
        if self.is_type(unsafe { &_xpc_type_double as *const _ as *const c_void }) {
            return Ok(XpcMessage::Double(unsafe {
                xpc_double_get_value(self.raw)
            }));
        }
        if self.is_type(unsafe { &_xpc_type_string as *const _ as *const c_void }) {
            let ptr = unsafe { xpc_string_get_string_ptr(self.raw) };
            let value = unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned();
            return Ok(XpcMessage::String(value));
        }
        if self.is_type(unsafe { &_xpc_type_data as *const _ as *const c_void }) {
            let ptr = unsafe { xpc_data_get_bytes_ptr(self.raw) }.cast::<u8>();
            let len = unsafe { xpc_data_get_length(self.raw) };
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            return Ok(XpcMessage::Data(bytes));
        }
        if self.is_type(unsafe { &_xpc_type_fd as *const _ as *const c_void }) {
            return Ok(XpcMessage::Fd(unsafe { xpc_fd_dup(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_array as *const _ as *const c_void }) {
            let (sender, receiver) = mpsc::channel();
            let mut block = ConcreteBlock::new(move |_idx: usize, value: xpc_object_t| {
                let _ = sender.send(Self::retain(value, "array element"));
                true
            });
            unsafe {
                xpc_array_apply(self.raw, &mut *block as *mut Block<_, _> as *mut c_void);
            }
            let mut values = Vec::new();
            for _ in 0..unsafe { xpc_array_get_count(self.raw) } {
                let value = receiver
                    .recv()
                    .map_err(|_| XpcError::UnsupportedObjectType("array"))??;
                values.push(value.to_message()?);
            }
            return Ok(XpcMessage::Array(values));
        }
        if self.is_type(unsafe { &_xpc_type_dictionary as *const _ as *const c_void }) {
            let (sender, receiver) = mpsc::channel();
            let mut block = ConcreteBlock::new(move |key: *const c_char, value: xpc_object_t| {
                let key = unsafe { CStr::from_ptr(key) }
                    .to_string_lossy()
                    .into_owned();
                let _ = sender.send((key, Self::retain(value, "dictionary value")));
                true
            });
            unsafe {
                xpc_dictionary_apply(self.raw, &mut *block as *mut Block<_, _> as *mut c_void);
            }
            let mut values = BTreeMap::new();
            for _ in 0..unsafe { xpc_dictionary_get_count(self.raw) } {
                let (key, value) = receiver
                    .recv()
                    .map_err(|_| XpcError::UnsupportedObjectType("dictionary"))?;
                values.insert(key, value?.to_message()?);
            }
            return Ok(XpcMessage::Dictionary(values));
        }

        Err(XpcError::UnsupportedObjectType("xpc object"))
    }

    fn is_type(&self, ty: *const c_void) -> bool {
        let value_type = unsafe { xpc_get_type(self.raw) };
        ptr::eq(value_type.cast::<c_void>(), ty)
    }

    fn as_connection(&self) -> xpc_connection_t {
        self.raw as xpc_connection_t
    }
}

impl Drop for OwnedXpcObject {
    fn drop(&mut self) {
        unsafe { xpc_release(self.raw) };
    }
}

#[derive(Debug)]
struct DispatchQueue {
    raw: dispatch_queue_t,
}

impl DispatchQueue {
    fn new(label: Option<&str>) -> Result<Self, XpcError> {
        let raw = match label {
            Some(label) => {
                let label = make_c_string(label)?;
                unsafe { dispatch_queue_create(label.as_ptr(), ptr::null_mut()) }
            }
            None => ptr::null_mut(),
        };
        if label.is_some() && raw.is_null() {
            return Err(XpcError::QueueCreationFailed);
        }
        Ok(Self { raw })
    }
}

unsafe impl Send for XpcConnection {}
unsafe impl Sync for XpcConnection {}

fn make_c_string(value: &str) -> Result<CString, XpcError> {
    CString::new(value).map_err(|_| XpcError::InvalidCString(value.to_owned()))
}

fn map_event(connection: xpc_connection_t, event: OwnedXpcObject) -> XpcEvent {
    if let Some(error) = map_connection_error(connection, &event) {
        return XpcEvent::Error(error);
    }

    match event.to_message() {
        Ok(message) => XpcEvent::Message(ReceivedXpcMessage {
            connection,
            message,
            raw_event: event,
        }),
        Err(err) => XpcEvent::Error(XpcConnectionError::Invalidated(Some(err.to_string()))),
    }
}

fn map_connection_error(
    connection: xpc_connection_t,
    event: &OwnedXpcObject,
) -> Option<XpcConnectionError> {
    if !event.is_type(unsafe { &_xpc_type_error as *const _ as *const c_void }) {
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
) -> Option<String> {
    let copied = unsafe { xpc_connection_copy_invalidation_reason(connection) };
    if !copied.is_null() {
        let value = unsafe { CString::from_raw(copied) }
            .to_string_lossy()
            .into_owned();
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

    Some(
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned(),
    )
}

impl PeerSecurityRequirement {
    fn apply(&self, connection: xpc_connection_t) -> Result<(), XpcError> {
        let result = match self {
            Self::CodeSigning(requirement) => {
                let requirement = make_c_string(requirement)?;
                unsafe {
                    xpc_connection_set_peer_code_signing_requirement(
                        connection,
                        requirement.as_ptr(),
                    )
                }
            }
            Self::TeamIdentity(signing_identifier) => {
                let signing_identifier = signing_identifier
                    .as_deref()
                    .map(make_c_string)
                    .transpose()?;
                unsafe {
                    xpc_connection_set_peer_team_identity_requirement(
                        connection,
                        signing_identifier
                            .as_ref()
                            .map_or(ptr::null(), |value| value.as_ptr()),
                    )
                }
            }
            Self::PlatformIdentity(signing_identifier) => {
                let signing_identifier = signing_identifier
                    .as_deref()
                    .map(make_c_string)
                    .transpose()?;
                unsafe {
                    xpc_connection_set_peer_platform_identity_requirement(
                        connection,
                        signing_identifier
                            .as_ref()
                            .map_or(ptr::null(), |value| value.as_ptr()),
                    )
                }
            }
            Self::EntitlementExists(entitlement) => {
                let entitlement = make_c_string(entitlement)?;
                unsafe {
                    xpc_connection_set_peer_entitlement_exists_requirement(
                        connection,
                        entitlement.as_ptr(),
                    )
                }
            }
            Self::EntitlementMatchesValue { entitlement, value } => {
                let entitlement = make_c_string(entitlement)?;
                let value = OwnedXpcObject::from_message(value.clone())?;
                unsafe {
                    xpc_connection_set_peer_entitlement_matches_value_requirement(
                        connection,
                        entitlement.as_ptr(),
                        value.raw,
                    )
                }
            }
            Self::LightweightCodeRequirement(requirement) => {
                let requirement = OwnedXpcObject::from_message(requirement.clone())?;
                unsafe {
                    xpc_connection_set_peer_lightweight_code_requirement(
                        connection,
                        requirement.raw,
                    )
                }
            }
        };

        if result == 0 {
            Ok(())
        } else {
            Err(XpcError::PeerRequirementFailed {
                code: result,
                context: "apply xpc peer requirement",
            })
        }
    }
}
