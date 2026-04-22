use std::{
    collections::BTreeMap,
    ffi::{CStr, c_char, c_void},
    ptr, sync::mpsc,
};

use crate::{
    block::{Block, ConcreteBlock},
    error::XpcError,
    ffi::{
        _xpc_type_array, _xpc_type_bool, _xpc_type_data, _xpc_type_dictionary, _xpc_type_double,
        _xpc_type_fd, _xpc_type_int64, _xpc_type_null, _xpc_type_string, _xpc_type_uint64,
        xpc_array_append_value, xpc_array_apply, xpc_array_create, xpc_array_get_count,
        xpc_bool_create, xpc_bool_get_value, xpc_data_create, xpc_data_get_bytes_ptr,
        xpc_data_get_length, xpc_dictionary_apply, xpc_dictionary_create,
        xpc_dictionary_get_count, xpc_dictionary_set_value, xpc_double_create,
        xpc_double_get_value, xpc_fd_create, xpc_fd_dup, xpc_get_type, xpc_int64_create,
        xpc_int64_get_value, xpc_null_create, xpc_object_t, xpc_release, xpc_retain,
        xpc_string_create, xpc_string_get_string_ptr, xpc_uint64_create, xpc_uint64_get_value,
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
        unsafe { xpc_retain(raw) };
        Ok(Self { raw })
    }

    pub(crate) fn from_message(message: XpcMessage) -> Result<Self, XpcError> {
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
            XpcMessage::Data(value) => unsafe { xpc_data_create(value.as_ptr().cast(), value.len()) },
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

    pub(crate) fn to_message(&self) -> Result<XpcMessage, XpcError> {
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
            return Ok(XpcMessage::Uint64(unsafe { xpc_uint64_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_double as *const _ as *const c_void }) {
            return Ok(XpcMessage::Double(unsafe { xpc_double_get_value(self.raw) }));
        }
        if self.is_type(unsafe { &_xpc_type_string as *const _ as *const c_void }) {
            let ptr = unsafe { xpc_string_get_string_ptr(self.raw) };
            let value = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
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
                let value = receiver.recv().map_err(|_| XpcError::UnsupportedObjectType("array"))??;
                values.push(value.to_message()?);
            }
            return Ok(XpcMessage::Array(values));
        }
        if self.is_type(unsafe { &_xpc_type_dictionary as *const _ as *const c_void }) {
            let (sender, receiver) = mpsc::channel();
            let mut block = ConcreteBlock::new(move |key: *const c_char, value: xpc_object_t| {
                let key = unsafe { CStr::from_ptr(key) }.to_string_lossy().into_owned();
                let _ = sender.send((key, Self::retain(value, "dictionary value")));
                true
            });
            unsafe {
                xpc_dictionary_apply(self.raw, &mut *block as *mut Block<_, _> as *mut c_void);
            }
            let mut values = BTreeMap::new();
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
        let value_type = unsafe { xpc_get_type(self.raw) };
        ptr::eq(value_type.cast::<c_void>(), ty)
    }
}

impl Drop for OwnedXpcObject {
    fn drop(&mut self) {
        unsafe { xpc_release(self.raw) };
    }
}
