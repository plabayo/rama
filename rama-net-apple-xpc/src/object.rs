use std::{
    collections::BTreeMap,
    ffi::{CStr, c_char, c_void},
    ptr,
    sync::mpsc,
};

use block2::{Block, StackBlock};

/// Maximum nesting depth accepted by [`OwnedXpcObject::from_message`] and
/// [`OwnedXpcObject::to_message`].
///
/// This guards against stack overflow when encoding or decoding deeply nested
/// XPC arrays/dictionaries (e.g. from an untrusted peer). The limit is
/// intentionally generous — graceful-by-default — and applies uniformly to
/// both directions. Strictness can be tightened by callers if needed.
pub(crate) const MAX_OBJECT_NESTING_DEPTH: usize = 256;

use crate::{
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
        Self::from_message_inner(message, 0)
    }

    fn from_message_inner(message: XpcMessage, depth: usize) -> Result<Self, XpcError> {
        if depth > MAX_OBJECT_NESTING_DEPTH {
            return Err(XpcError::UnsupportedObjectType("nesting too deep"));
        }
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
                    let value = Self::from_message_inner(value, depth + 1)?;
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
                    let value = Self::from_message_inner(value, depth + 1)?;
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
        self.to_message_inner(0)
    }

    fn to_message_inner(&self, depth: usize) -> Result<XpcMessage, XpcError> {
        if depth > MAX_OBJECT_NESTING_DEPTH {
            return Err(XpcError::UnsupportedObjectType("nesting too deep"));
        }
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
            return Ok(XpcMessage::Uint64(unsafe {
                xpc_uint64_get_value(self.raw)
            }));
        }
        if self.is_type(unsafe { &_xpc_type_double as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_DOUBLE above.
            return Ok(XpcMessage::Double(unsafe {
                xpc_double_get_value(self.raw)
            }));
        }
        if self.is_type(unsafe { &_xpc_type_string as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_STRING. xpc_string_get_string_ptr
            // returns a valid, null-terminated C string borrowed from self.raw; it
            // remains valid for the lifetime of self (OwnedXpcObject keeps self.raw
            // retained). We copy to a String before returning.
            let ptr = unsafe { xpc_string_get_string_ptr(self.raw) };
            let value = unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned();
            return Ok(XpcMessage::String(value));
        }
        if self.is_type(unsafe { &_xpc_type_data as *const _ as *const c_void }) {
            // SAFETY: Type confirmed as XPC_TYPE_DATA. xpc_data_get_length is always safe.
            let len = unsafe { xpc_data_get_length(self.raw) };
            let bytes = if len == 0 {
                // xpc_data_get_bytes_ptr returns null for zero-length data objects.
                // slice::from_raw_parts requires a non-null pointer even for len=0, so
                // we must short-circuit here rather than pass null to from_raw_parts.
                vec![]
            } else {
                // SAFETY: len > 0, so xpc_data_get_bytes_ptr returns a non-null pointer
                // to at least `len` initialised bytes, valid for the lifetime of self.raw.
                let ptr = unsafe { xpc_data_get_bytes_ptr(self.raw) }.cast::<u8>();
                unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
            };
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
            // Return u8 (1 = continue, 0 = stop) because bool does not implement
            // objc2's Encode trait. The ABI is identical: XPC reads the 1-byte
            // return value and treats any non-zero as "continue".
            let block = StackBlock::new(move |_idx: usize, value: xpc_object_t| -> u8 {
                _ = sender.send(Self::retain(value, "array element"));
                1
            });
            // SAFETY: self.raw is a valid XPC array. `&*block` derefs the StackBlock
            // to its inner `Block`, whose pointer is documented (block2 stack.rs) to
            // be safe to reinterpret as an Objective-C block pointer. xpc_array_apply
            // is documented as synchronous: it invokes the block once per element and
            // returns only after the final invocation, so the StackBlock cannot outlive
            // this scope and never needs to be `_Block_copy`'d to the heap.
            unsafe {
                xpc_array_apply(
                    self.raw,
                    (&*block as *const Block<_>).cast::<c_void>().cast_mut(),
                );
            }
            let mut values = Vec::new();
            // SAFETY: xpc_array_get_count on a valid XPC array returns the element count.
            // The recv() calls will not block because xpc_array_apply above has already
            // sent exactly xpc_array_get_count items into the channel.
            for _ in 0..unsafe { xpc_array_get_count(self.raw) } {
                let value = receiver
                    .recv()
                    .map_err(|_e| XpcError::UnsupportedObjectType("array"))??;
                values.push(value.to_message_inner(depth + 1)?);
            }
            return Ok(XpcMessage::Array(values));
        }
        if self.is_type(unsafe { &_xpc_type_dictionary as *const _ as *const c_void }) {
            let (sender, receiver) = mpsc::channel();
            // Return u8 (1 = continue, 0 = stop) — same reasoning as the array case above.
            let block = StackBlock::new(move |key: *const c_char, value: xpc_object_t| -> u8 {
                // SAFETY: key is a valid null-terminated C string borrowed from the XPC
                // dictionary for the duration of this callback invocation.
                let key = unsafe { CStr::from_ptr(key) }
                    .to_string_lossy()
                    .into_owned();
                _ = sender.send((key, Self::retain(value, "dictionary value")));
                1
            });
            // SAFETY: self.raw is a valid XPC dictionary. `&*block` yields a pointer to
            // the inner Block, which block2 documents as safe to reinterpret as an
            // Objective-C block pointer. xpc_dictionary_apply is synchronous (see the
            // array case above for the same reasoning).
            unsafe {
                xpc_dictionary_apply(
                    self.raw,
                    (&*block as *const Block<_>).cast::<c_void>().cast_mut(),
                );
            }
            let mut values = BTreeMap::new();
            // SAFETY: xpc_dictionary_get_count on a valid XPC dictionary returns the entry
            // count. recv() will not block for the same reason as the array case above.
            for _ in 0..unsafe { xpc_dictionary_get_count(self.raw) } {
                let (key, value) = receiver
                    .recv()
                    .map_err(|_e| XpcError::UnsupportedObjectType("dictionary"))?;
                values.insert(key, value?.to_message_inner(depth + 1)?);
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use crate::message::XpcMessage;

    use super::OwnedXpcObject;

    fn rt(msg: XpcMessage) -> XpcMessage {
        OwnedXpcObject::from_message(msg)
            .expect("from_message")
            .to_message()
            .expect("to_message")
    }

    // ── primitives ───────────────────────────────────────────────────────────

    #[test]
    fn null() {
        assert_eq!(rt(XpcMessage::Null), XpcMessage::Null);
    }

    #[test]
    fn bool_values() {
        assert_eq!(rt(XpcMessage::Bool(true)), XpcMessage::Bool(true));
        assert_eq!(rt(XpcMessage::Bool(false)), XpcMessage::Bool(false));
    }

    #[test]
    fn int64_boundaries() {
        for v in [0, 1, -1, i64::MIN, i64::MAX] {
            assert_eq!(rt(XpcMessage::Int64(v)), XpcMessage::Int64(v));
        }
    }

    #[test]
    fn uint64_boundaries() {
        for v in [0u64, 1, u64::MAX] {
            assert_eq!(rt(XpcMessage::Uint64(v)), XpcMessage::Uint64(v));
        }
    }

    #[test]
    fn double_values() {
        for v in [
            0.0f64,
            1.0,
            -1.0,
            f64::MIN,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            assert_eq!(rt(XpcMessage::Double(v)), XpcMessage::Double(v));
        }
        // NaN is not equal to itself, so check the type tag separately.
        let nan = rt(XpcMessage::Double(f64::NAN));
        assert!(matches!(nan, XpcMessage::Double(v) if v.is_nan()));
    }

    // ── string ───────────────────────────────────────────────────────────────

    #[test]
    fn string_empty() {
        assert_eq!(
            rt(XpcMessage::String(String::new())),
            XpcMessage::String(String::new())
        );
    }

    #[test]
    fn string_ascii() {
        assert_eq!(
            rt(XpcMessage::String("hello, xpc".into())),
            XpcMessage::String("hello, xpc".into()),
        );
    }

    #[test]
    fn string_unicode() {
        let s = "café 🦀".to_owned();
        assert_eq!(rt(XpcMessage::String(s.clone())), XpcMessage::String(s));
    }

    #[test]
    fn string_interior_nul_is_rejected() {
        let result = OwnedXpcObject::from_message(XpcMessage::String("foo\0bar".into()));
        assert!(result.is_err(), "interior NUL must be rejected");
    }

    // ── data ─────────────────────────────────────────────────────────────────

    #[test]
    fn data_empty() {
        assert_eq!(rt(XpcMessage::Data(vec![])), XpcMessage::Data(vec![]));
    }

    #[test]
    fn data_bytes() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(rt(XpcMessage::Data(bytes.clone())), XpcMessage::Data(bytes));
    }

    // ── fd ───────────────────────────────────────────────────────────────────

    #[test]
    fn fd_is_duped() {
        // xpc_fd_dup returns a *new* file descriptor, not the original.
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let original = file.as_raw_fd();
        let result = rt(XpcMessage::Fd(original));
        let XpcMessage::Fd(duped) = result else {
            panic!("expected Fd variant")
        };
        assert_ne!(
            duped, original,
            "round-tripped fd must be a dup, not the original"
        );
        // Take ownership so the duped fd is closed on drop.
        drop(unsafe { OwnedFd::from_raw_fd(duped) });
    }

    // ── uuid ─────────────────────────────────────────────────────────────────

    #[test]
    fn uuid_all_zeros() {
        let bytes = [0u8; 16];
        assert_eq!(rt(XpcMessage::Uuid(bytes)), XpcMessage::Uuid(bytes));
    }

    #[test]
    fn uuid_all_ones() {
        let bytes = [0xFFu8; 16];
        assert_eq!(rt(XpcMessage::Uuid(bytes)), XpcMessage::Uuid(bytes));
    }

    #[test]
    fn uuid_distinct_bytes() {
        let bytes: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
        assert_eq!(rt(XpcMessage::Uuid(bytes)), XpcMessage::Uuid(bytes));
    }

    // ── date ─────────────────────────────────────────────────────────────────

    #[test]
    fn date_values() {
        for v in [0i64, 1, -1, i64::MIN, i64::MAX] {
            assert_eq!(rt(XpcMessage::Date(v)), XpcMessage::Date(v));
        }
    }

    // ── array ────────────────────────────────────────────────────────────────

    #[test]
    fn array_empty() {
        assert_eq!(rt(XpcMessage::Array(vec![])), XpcMessage::Array(vec![]));
    }

    #[test]
    fn array_of_primitives() {
        let msg = XpcMessage::Array(vec![
            XpcMessage::Int64(1),
            XpcMessage::Bool(true),
            XpcMessage::String("hi".into()),
        ]);
        assert_eq!(rt(msg.clone()), msg);
    }

    #[test]
    fn array_nested() {
        let inner = XpcMessage::Array(vec![XpcMessage::Uint64(99)]);
        let outer = XpcMessage::Array(vec![inner]);
        assert_eq!(rt(outer.clone()), outer);
    }

    // ── dictionary ───────────────────────────────────────────────────────────

    #[test]
    fn dictionary_empty() {
        assert_eq!(
            rt(XpcMessage::Dictionary(BTreeMap::new())),
            XpcMessage::Dictionary(BTreeMap::new()),
        );
    }

    #[test]
    fn dictionary_string_keys() {
        let msg = XpcMessage::Dictionary(BTreeMap::from([
            ("a".into(), XpcMessage::Int64(1)),
            ("b".into(), XpcMessage::Bool(false)),
            ("z".into(), XpcMessage::Null),
        ]));
        assert_eq!(rt(msg.clone()), msg);
    }

    #[test]
    fn dictionary_nested() {
        let inner = XpcMessage::Dictionary(BTreeMap::from([(
            "inner_key".into(),
            XpcMessage::Uint64(42),
        )]));
        let outer = XpcMessage::Dictionary(BTreeMap::from([
            ("nested".into(), inner),
            ("flag".into(), XpcMessage::Bool(true)),
        ]));
        assert_eq!(rt(outer.clone()), outer);
    }

    // ── complex nesting ──────────────────────────────────────────────────────

    #[test]
    fn dict_containing_array_of_dicts() {
        let leaf = XpcMessage::Dictionary(BTreeMap::from([
            ("x".into(), XpcMessage::Int64(-1)),
            ("y".into(), XpcMessage::Double(std::f64::consts::PI)),
        ]));
        let array = XpcMessage::Array(vec![leaf.clone(), leaf]);
        let root = XpcMessage::Dictionary(BTreeMap::from([
            ("items".into(), array),
            ("version".into(), XpcMessage::Uint64(1)),
        ]));
        assert_eq!(rt(root.clone()), root);
    }

    // ── depth limit ──────────────────────────────────────────────────────────

    #[test]
    fn depth_limit_rejects_excessive_array_nesting() {
        use crate::object::MAX_OBJECT_NESTING_DEPTH;

        let mut msg = XpcMessage::Null;
        for _ in 0..(MAX_OBJECT_NESTING_DEPTH + 2) {
            msg = XpcMessage::Array(vec![msg]);
        }
        assert!(
            OwnedXpcObject::from_message(msg).is_err(),
            "encoding past depth limit must error rather than overflow the stack",
        );
    }

    #[test]
    fn depth_limit_rejects_excessive_dictionary_nesting() {
        use crate::object::MAX_OBJECT_NESTING_DEPTH;

        let mut msg = XpcMessage::Null;
        for i in 0..(MAX_OBJECT_NESTING_DEPTH + 2) {
            let mut map = BTreeMap::new();
            map.insert(format!("k{i}"), msg);
            msg = XpcMessage::Dictionary(map);
        }
        assert!(
            OwnedXpcObject::from_message(msg).is_err(),
            "encoding past depth limit must error rather than overflow the stack",
        );
    }

    #[test]
    fn depth_limit_at_boundary_succeeds() {
        use crate::object::MAX_OBJECT_NESTING_DEPTH;

        // exactly at the limit should still encode/decode cleanly
        let mut msg = XpcMessage::Int64(7);
        for _ in 0..MAX_OBJECT_NESTING_DEPTH {
            msg = XpcMessage::Array(vec![msg]);
        }
        let owned = OwnedXpcObject::from_message(msg.clone()).expect("encode at limit");
        let decoded = owned.to_message().expect("decode at limit");
        assert_eq!(decoded, msg);
    }

    // ── note on XpcMessage::Endpoint ─────────────────────────────────────────
    // Endpoint round-trips cannot be tested here: creating an XpcEndpoint requires a
    // live XpcConnection, which requires a launchd-registered service or an existing
    // endpoint passed out-of-band. Cover this in integration tests once an e2e harness
    // exists.
}
