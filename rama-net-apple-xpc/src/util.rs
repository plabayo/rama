use std::{ffi::CString, ptr};

use crate::{
    error::XpcError,
    ffi::{dispatch_queue_create, dispatch_queue_t},
};

pub(crate) fn make_c_string(value: &str) -> Result<CString, XpcError> {
    CString::new(value).map_err(|_| XpcError::InvalidCString(value.into()))
}

#[derive(Debug)]
pub(crate) struct DispatchQueue {
    pub(crate) raw: dispatch_queue_t,
}

impl DispatchQueue {
    pub(crate) fn new(label: Option<&str>) -> Result<Self, XpcError> {
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
