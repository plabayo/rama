use std::{
    collections::BTreeMap,
    ffi::{CStr, c_char, c_void},
    ptr, sync::mpsc,
};

use crate::{
    block::{Block, ConcreteBlock},
    endpoint::XpcEndpoint,
    error::XpcError,
    ffi::{
        _xpc_type_array, _xpc_type_bool, _xpc_type_data, _xpc_type_date, _xpc_type_dictionary,
        _xpc_type_double, _xpc_type_endpoint, _xpc_type_fd, _xpc_type_int64, _xpc_type_null,
        _xpc_type_string, _xpc_type_uint64, _xpc_type_uuid, xpc_array_append_value,
        xpc_array_apply, xpc_array_create, xpc_array_get_count, xpc_bool_create,
        xpc_bool_get_value, xpc_data_create, xpc_data_get_bytes_ptr, xpc_data_get_length,
        xpc_date_create, xpc_date_get_value, xpc_dictionary_apply, xpc_dictionary_create,
        xpc_dictionary_get_count, xpc_dictionary_set_value, xpc_double_create,
        xpc_double_get_value, xpc_fd_create, xpc_fd_dup, xpc_get_type, xpc_int64_create,
        xpc_int64_get_value, xpc_null_create, xpc_object_t, xpc_release, xpc_retain,
        xpc_string_create, xpc_string_get_string_ptr, xpc_uint64_create, xpc_uint64_get_value,
        xpc_uuid_create, xpc_uuid_get_bytes,
    },
    message::XpcMessage,
    util::make_c_string,
};

#[derive(Debug)]
pub(crate) struct OwnedXpcObject {
    pub(crate) raw: xpc_object_t,
}

unsafe impl Send for OwnedXpcObject {}
unsafe impl Sync for OwnedXpcObject {}

impl OwnedXpcObject {
    pub(crate) fn from_raw(raw: xpc_object_t, context: &'static str) -> Result<Self, XpcError> {
        if raw.is_null() {
            return Err(XpcError::NullObject(context));
        }
        Ok(Self { raw })
    }

    pub(crate) fn retain(raw: xpc_object_t, context: &'static str) -> Result<Self, XpcError> {
        if raw.is_null() {
            return Err(XpcError::NullObject(context));
        }
        // SAFETY: raw is non-null (checked above). xpc_retain increments the XPC
        // object's reference count; OwnedXpcObject::drop will call xpc_release once.
        unsafe { xpc_retain(raw) };
        Ok(Self { raw })
    }

    pub(crate) fn from_message(message: XpcMessage) -> Result<Self, XpcError> {
        // SAFETY for the entire match: each xpc_*_create function takes a valid Rust
        // value and returns a new retained XPC object (or NULL on allocation failure,
        // caught by from_raw). Arguments derived from Rust types satisfy each API's
        // documented preconditions.
        let raw = match message {
            XpcMessage::Null => unsafe { xpc_null_create() },
            XpcMessage::Bool(value) => unsafe { xpc_bool_create(value) },
            XpcMessage::Int64(value) => unsafe { xpc_int64_create(value) },
            XpcMessage::Uint64(value) => unsafe { xpc_uint64_create(value) },
            XpcMessage::Double(value) => unsafe { xpc_double_create(value) },
            XpcMessage::String(value) => {
                let value = make_c_string(&value)?;
                // SAFETY: value is a valid null-terminated C string with no interior NULs.
                unsafe { xpc_string_create(value.as_ptr()) }
            }
            XpcMessage::Data(value) => {
                // SAFETY: value.as_ptr() points to len() initialised bytes.
                unsafe { xpc_data_create(value.as_ptr().cast(), value.len()) }
            }
            XpcMessage::Fd(value) => unsafe { xpc_fd_create(value) },
            XpcMessage::Uuid(bytes) => {
                // SAFETY: bytes is a 16-element array; as_ptr() gives a valid pointer to
                // exactly 16 bytes as required by xpc_uuid_create.
                unsafe { xpc_uuid_create(bytes.as_ptr()) }
            }
            XpcMessage::Date(nanos) => unsafe { xpc_date_create(nanos) },
            XpcMessage::Endpoint(endpoint) => {
                // SAFETY: endpoint.raw_object().raw is a valid retained XPC endpoint
                // object held by the Arc inside XpcEndpoint. We retain it here so the
                // new OwnedXpcObject can hold an independent reference with its own release.
                unsafe { xpc_retain(endpoint.raw_object().raw) };
                endpoint.raw_object().raw
            }
            XpcMessage::Array(values) => {
                // SAFETY: Passing null/0 creates an empty mutable array.
                let raw = unsafe { xpc_array_create(ptr::null_mut(), 0) };
                for value in values {
                    let value = Self::from_message(value)?;
                    // SAFETY: raw is a valid mutable XPC array; value.raw is a valid
                    // retained XPC object. xpc_array_append_value retains value.raw.
                    unsafe { xpc_array_append_value(raw, value.raw) };
                }
                raw
            }
            XpcMessage::Dictionary(values) => {
                // SAFETY: Passing null/null/0 creates an empty mutable dictionary.
                let raw = unsafe { xpc_dictionary_create(ptr::null(), ptr::null_mut(), 0) };
                for (key, value) in values {
                    let key = make_c_string(&key)?;
                    let value = Self::from_message(value)?;
                    // SAFETY: raw is a valid mutable XPC dictionary. key.as_ptr() is a
                    // valid null-terminated C string. value.raw is a valid retained XPC
                    // object. xpc_dictionary_set_value retains value.raw.
                    unsafe { xpc_dictionary_set_value(raw, key.as_ptr(), value.raw) };
                }
                raw
            }
        };
        Self::from_raw(raw, "message encode")
    }

    pub(crate) fn to_message(&self) -> Result<XpcMessage, XpcError> {
        // Common precondition for every branch below: self.raw is a valid, non-null
        // XPC object held by OwnedXpcObject. is_type() confirms the runtime type
        // before any type-specific accessor is called.

        // SAFETY: _xpc_type_* are static XPC type singleton objects. xpc_get_type
        // returns a pointer to the type singleton for any valid XPC object.
        if self.is_type(unsafe { &_xpc_type_null as *const _ as *const c_void }) {
            return Ok(XpcMessage::Null);
        }
        if self.is_type(unsafe { &_xpc_type_bool as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_BOOL above.
            return Ok(XpcMessage::Bool(unsafe { xpc_bool_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_int64 as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_INT64 above.
            return Ok(XpcMessage::Int64(unsafe { xpc_int64_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_uint64 as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_UINT64 above.
            return Ok(XpcMessage::Uint64(unsafe { xpc_uint64_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_double as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_DOUBLE above.
            return Ok(XpcMessage::Double(unsafe { xpc_double_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_string as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_STRING. xpc_string_get_string_ptr
            // returns a valid, null-terminated C string borrowed from self.raw; it
            // remains valid for the lifetime of self (OwnedXpcObject keeps self.raw
            // retained). We copy to a String before returning.
            let ptr = unsafe { xpc_string_get_string_ptr(self.raw) };
            let value = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
            return Ok(XpcMessage::String(value));
        }
        if self.is_type(unsafe { &_xpc_type_data as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_DATA. Both pointers are valid and
            // live as long as self.raw. We copy the bytes into a Vec before returning.
            let ptr = unsafe { xpc_data_get_bytes_ptr(self.raw) }.cast::<u8>();
            let len = unsafe { xpc_data_get_length(self.raw) };
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            return Ok(XpcMessage::Data(bytes));
        }
        if self.is_type(unsafe { &_xpc_type_fd as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_FD. xpc_fd_dup duplicates the file
            // descriptor; the caller receives ownership of the new fd.
            return Ok(XpcMessage::Fd(unsafe { xpc_fd_dup(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_uuid as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_UUID. xpc_uuid_get_bytes returns a
            // pointer to exactly 16 bytes, valid for the lifetime of self.raw.
            let ptr = unsafe { xpc_uuid_get_bytes(self.raw) };
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, 16) });
            return Ok(XpcMessage::Uuid(bytes));
        }
        if self.is_type(unsafe { &_xpc_type_date as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_DATE above.
            return Ok(XpcMessage::Date(unsafe { xpc_date_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_endpoint as *const _ as *const c_void }) {
            let retained = Self::retain(self.raw, "endpoint to message")?;
            return Ok(XpcMessage::Endpoint(XpcEndpoint::from_raw_object(retained)));
        }
        if self.is_type(unsafe { &_xpc_type_array as *const _ as *const c_void }) {
            let (sender, receiver) = mpsc::channel();
            let mut block = ConcreteBlock::new(move |_idx: usize, value: xpc_object_t| {
                let _ = sender.send(Self::retain(value, "array element"));
                true
            });
            // SAFETY: self.raw is a valid XPC array. xpc_array_apply calls the block
            // synchronously for each element before returning, so all sends complete
            // before the subsequent recv() calls below.
            unsafe {
                xpc_array_apply(self.raw, &mut *block as *mut Block<_, _> as *mut c_void);
            }
            let mut values = Vec::new();
            // SAFETY: xpc_array_get_count on a valid XPC array returns the element count.
            // The recv() calls will not block because xpc_array_apply above has already
            // sent exactly xpc_array_get_count items into the channel.
            for _ in 0..unsafe { xpc_array_get_count(self.raw) } {
                let value = receiver.recv().map_err(|_| XpcError::UnsupportedObjectType("array"))??;
                values.push(value.to_message()?);
            }
            return Ok(XpcMessage::Array(values));
        }
        if self.is_type(unsafe { &_xpc_type_dictionary as *const _ as *const c_void }) {
            let (sender, receiver) = mpsc::channel();
            let mut block = ConcreteBlock::new(move |key: *const c_char, value: xpc_object_t| {
                // SAFETY: key is a valid null-terminated C string borrowed from the XPC
                // dictionary for the duration of this callback invocation.
                let key = unsafe { CStr::from_ptr(key) }.to_string_lossy().into_owned();
                let _ = sender.send((key, Self::retain(value, "dictionary value")));
                true
            });
            // SAFETY: self.raw is a valid XPC dictionary. xpc_dictionary_apply calls the
            // block synchronously for each entry before returning.
            unsafe {
                xpc_dictionary_apply(self.raw, &mut *block as *mut Block<_, _> as *mut c_void);
            }
            let mut values = BTreeMap::new();
            // SAFETY: xpc_dictionary_get_count on a valid XPC dictionary returns the entry
            // count. recv() will not block for the same reason as the array case above.
            for _ in 0..unsafe { xpc_dictionary_get_count(self.raw) } {
                let (key, value) =
                    receiver.recv().map_err(|_| XpcError::UnsupportedObjectType("dictionary"))?;
                values.insert(key, value?.to_message()?);
            }
            return Ok(XpcMessage::Dictionary(values));
        }

        Err(XpcError::UnsupportedObjectType("xpc object"))
    }

    pub(crate) fn is_type(&self, ty: *const c_void) -> bool {
        // SAFETY: self.raw is a valid, non-null XPC object. xpc_get_type returns a
        // non-null pointer to the type singleton for any valid XPC object.
        let value_type = unsafe { xpc_get_type(self.raw) };
        ptr::eq(value_type.cast::<c_void>(), ty)
    }
}

impl Drop for OwnedXpcObject {
    fn drop(&mut self) {
        // SAFETY: self.raw is a valid retained XPC object. Each OwnedXpcObject holds
        // exactly one reference (from from_raw or from an explicit retain call), so
        // releasing once here correctly balances the retain count.
        unsafe { xpc_release(self.raw) };
    }
}
