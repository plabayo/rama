use std::{
    collections::BTreeMap,
    ffi::{CStr, c_char, c_void},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr, slice,
    sync::{Arc, mpsc},
};

use block2::StackBlock;

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
        _xpc_type_array, _xpc_type_bool, _xpc_type_connection, _xpc_type_data, _xpc_type_date,
        _xpc_type_dictionary, _xpc_type_double, _xpc_type_endpoint, _xpc_type_fd, _xpc_type_int64,
        _xpc_type_null, _xpc_type_s, _xpc_type_string, _xpc_type_uint64, _xpc_type_uuid,
        xpc_array_append_value, xpc_array_apply, xpc_array_create, xpc_bool_create,
        xpc_bool_get_value, xpc_data_create, xpc_data_get_bytes_ptr, xpc_data_get_length,
        xpc_date_create, xpc_date_get_value, xpc_dictionary_apply, xpc_dictionary_create,
        xpc_dictionary_set_value, xpc_double_create, xpc_double_get_value, xpc_fd_create,
        xpc_fd_dup, xpc_get_type, xpc_int64_create, xpc_int64_get_value, xpc_null_create,
        xpc_object_t, xpc_release, xpc_retain, xpc_string_create, xpc_string_get_string_ptr,
        xpc_uint64_create, xpc_uint64_get_value, xpc_uuid_create, xpc_uuid_get_bytes,
    },
    message::XpcMessage,
    util::{abort_on_unwind, make_c_string},
};

/// One owned reference to a libxpc object that is not a connection.
///
/// Neither `Send` nor `Sync` (raw pointer field): every Rust alias made by
/// [`retain_clone`](Self::retain_clone), and every child owner decoding creates, stays
/// on one thread. Values that cross threads use
/// [`ConnectionObject`](crate::connection::ConnectionObject), [`XpcEndpoint`] or the
/// reply dictionary of a received message, which state their own synchronisation.
///
/// "Graph condition" below: no code other than this value, its clones and the child
/// owners its decoding creates on the same thread mutates, or accesses from another
/// thread, any collection reachable from the object until this value, its clones and
/// those child owners have all been dropped. Endpoints
/// (serialised by [`XpcEndpoint`]) and immutable boxed values (xpc_objects(3)) are
/// exempt.
#[derive(Debug)]
pub(crate) struct OwnedXpcObject {
    // Safety invariant: `raw` is a non-null libxpc object, not of type
    // `XPC_TYPE_CONNECTION`, on which this value owns exactly one reference, released
    // once by `Drop`, and the graph condition (type docs) holds for it. This crate
    // mutates only collections it created and has not cloned.
    raw: xpc_object_t,
}

/// Whether the live object `raw` has type `ty`.
///
/// # Safety
///
/// The caller must ensure `raw` is a non-null libxpc object that is live for the call.
pub(crate) unsafe fn raw_type_is(raw: xpc_object_t, ty: *const _xpc_type_s) -> bool {
    // SAFETY: `xpc_get_type` requires a non-null live object (`XPC_NONNULL_ALL`), which
    // this function's contract provides.
    let value_type = unsafe { xpc_get_type(raw) };
    ptr::eq(value_type, ty)
}

impl OwnedXpcObject {
    /// Wrap the reference returned by a libxpc `XPC_RETURNS_RETAINED` call.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `raw` is null or a live libxpc object on which the caller owns one reference;
    ///   that reference moves into this call and the caller must not release it;
    /// - the graph condition (type docs) holds for `raw` until the result and every
    ///   owner derived from it have been dropped.
    ///
    /// Null returns [`XpcError::NullObject`]. A connection returns
    /// [`XpcError::UnsupportedObjectType`] and its reference is leaked: releasing a
    /// connection is only valid in some lifecycle states (<xpc/connection.h>).
    pub(crate) unsafe fn from_raw(
        raw: xpc_object_t,
        context: &'static str,
    ) -> Result<Self, XpcError> {
        if raw.is_null() {
            return Err(XpcError::NullObject(context));
        }
        // SAFETY: `raw` is non-null (checked) and live (contract).
        if unsafe { raw_type_is(raw, &raw const _xpc_type_connection) } {
            return Err(XpcError::UnsupportedObjectType(
                "connection as plain object",
            ));
        }
        Ok(Self { raw })
    }

    /// Take a new reference on a borrowed libxpc object.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `raw` is null or a libxpc object that is live for the
    /// duration of this call, and that the graph condition (type docs) holds for `raw`
    /// until the result and every owner derived from it have been dropped.
    ///
    /// Null returns [`XpcError::NullObject`]; a connection returns
    /// [`XpcError::UnsupportedObjectType`] without taking a reference.
    pub(crate) unsafe fn retain(
        raw: xpc_object_t,
        context: &'static str,
    ) -> Result<Self, XpcError> {
        if raw.is_null() {
            return Err(XpcError::NullObject(context));
        }
        // SAFETY: `raw` is non-null (checked) and live (contract).
        if unsafe { raw_type_is(raw, &raw const _xpc_type_connection) } {
            return Err(XpcError::UnsupportedObjectType(
                "connection as plain object",
            ));
        }
        // SAFETY: `xpc_retain` requires a live object; `raw` is non-null (checked) and live
        // per this function's contract. The new reference is owned by the returned value.
        unsafe { xpc_retain(raw) };
        Ok(Self { raw })
    }

    /// Another owned reference to the same object.
    pub(crate) fn retain_clone(&self) -> Self {
        // SAFETY: `xpc_retain` requires a live object; `self.raw` is one (field invariant).
        // The new reference is owned by the returned value, and the graph condition already
        // lasts until every clone is dropped, so the clone's field invariant holds.
        unsafe { xpc_retain(self.raw) };
        Self { raw: self.raw }
    }

    /// # Safety-usable invariant
    ///
    /// Returns a non-null libxpc object that stays live at least as long as `self`.
    pub(crate) fn as_raw(&self) -> xpc_object_t {
        self.raw
    }

    pub(crate) fn from_message(message: XpcMessage) -> Result<Self, XpcError> {
        Self::from_message_inner(message, 0)
    }

    fn from_message_inner(message: XpcMessage, depth: usize) -> Result<Self, XpcError> {
        if depth > MAX_OBJECT_NESTING_DEPTH {
            return Err(XpcError::UnsupportedObjectType("nesting too deep"));
        }
        // Each `xpc_*_create` below is `XPC_RETURNS_RETAINED` (<xpc/xpc.h>): it returns a
        // new object with one reference owned by the caller.
        let raw = match message {
            // SAFETY: takes no arguments.
            XpcMessage::Null => unsafe { xpc_null_create() },
            // SAFETY: takes a plain value; no pointer preconditions.
            XpcMessage::Bool(value) => unsafe { xpc_bool_create(value) },
            // SAFETY: takes a plain value; no pointer preconditions.
            XpcMessage::Int64(value) => unsafe { xpc_int64_create(value) },
            // SAFETY: takes a plain value; no pointer preconditions.
            XpcMessage::Uint64(value) => unsafe { xpc_uint64_create(value) },
            // SAFETY: takes a plain value; no pointer preconditions.
            XpcMessage::Double(value) => unsafe { xpc_double_create(value) },
            XpcMessage::String(value) => {
                let value = make_c_string(&value)?;
                // SAFETY: requires a non-null NUL-terminated string (`XPC_NONNULL1`);
                // `value` is a `CString` live for the call, which boxes the contents.
                unsafe { xpc_string_create(value.as_ptr()) }
            }
            XpcMessage::Data(value) => {
                // xpc_data_create: `bytes` may be NULL only with length 0, otherwise it
                // must be readable for `length` bytes; the buffer is copied.
                let bytes = if value.is_empty() {
                    ptr::null()
                } else {
                    value.as_ptr().cast::<c_void>()
                };
                // SAFETY: `bytes` is null with length 0, or points to the `value.len()`
                // initialised bytes of `value`, which is live for the call.
                unsafe { xpc_data_create(bytes, value.len()) }
            }
            // SAFETY: takes a plain integer; an invalid descriptor yields NULL (xpc.h),
            // handled by `from_raw` below. `fd` keeps the descriptor open for the call,
            // and xpc_fd_create dup(2)s it (xpc.h), so ownership stays with `fd`.
            XpcMessage::Fd(fd) => unsafe { xpc_fd_create(fd.as_raw_fd()) },
            XpcMessage::Uuid(bytes) => {
                // SAFETY: requires a non-null pointer to a `uuid_t` (16 bytes); `bytes` is
                // a live `[u8; 16]` for the call and the value is boxed (copied).
                unsafe { xpc_uuid_create(bytes.as_ptr()) }
            }
            // SAFETY: takes a plain value; no pointer preconditions.
            XpcMessage::Date(nanos) => unsafe { xpc_date_create(nanos) },
            XpcMessage::Endpoint(endpoint) => return Ok(endpoint.retain_object()),
            XpcMessage::Array(values) => {
                // SAFETY: NULL objects with count 0 is allowed by xpc_array_create and
                // yields an empty array. Wrapped first so a `?` below releases it.
                let raw = unsafe { xpc_array_create(ptr::null_mut(), 0) };
                // SAFETY: `raw` is null or the +1 array just returned; ownership moves.
                // Graph condition: a new array whose only children are the objects this
                // function creates (or endpoints) and appends.
                let array = unsafe { Self::from_raw(raw, "array encode") }?;
                for value in values {
                    let value = Self::from_message_inner(value, depth + 1)?;
                    // SAFETY: requires a live array and a non-null live value
                    // (`XPC_NONNULL1 XPC_NONNULL2`). `array` is the array created above,
                    // still unshared, so mutating it is allowed by the field invariant;
                    // `value` is live. The array takes its own reference on `value`.
                    unsafe { xpc_array_append_value(array.raw, value.raw) };
                }
                return Ok(array);
            }
            XpcMessage::Dictionary(values) => {
                // SAFETY: NULL keys/values with count 0 yields an empty dictionary.
                // Wrapped first so a `?` below releases it.
                let raw = unsafe { xpc_dictionary_create(ptr::null(), ptr::null_mut(), 0) };
                // SAFETY: `raw` is null or the +1 dictionary just returned; ownership moves.
                // Graph condition: as for the array case.
                let dict = unsafe { Self::from_raw(raw, "dictionary encode") }?;
                for (key, value) in values {
                    let key = make_c_string(&key)?;
                    let value = Self::from_message_inner(value, depth + 1)?;
                    // SAFETY: requires a live dictionary and a non-null NUL-terminated
                    // key (`XPC_NONNULL1 XPC_NONNULL2`). `dict` is the dictionary created
                    // above, still unshared; `key` is a live `CString` (keys are copied,
                    // see xpc_dictionary_create); the dictionary retains `value`.
                    unsafe { xpc_dictionary_set_value(dict.raw, key.as_ptr(), value.raw) };
                }
                return Ok(dict);
            }
        };
        // SAFETY: `raw` is null or the +1 object returned by the `xpc_*_create` call
        // above, a new boxed value; ownership moves into the result.
        unsafe { Self::from_raw(raw, "message encode") }
    }

    pub(crate) fn to_message(&self) -> Result<XpcMessage, XpcError> {
        self.to_message_inner(0)
    }

    fn to_message_inner(&self, depth: usize) -> Result<XpcMessage, XpcError> {
        if depth > MAX_OBJECT_NESTING_DEPTH {
            return Err(XpcError::UnsupportedObjectType("nesting too deep"));
        }
        // Every accessor below is only reached after `is_type` confirmed the object's
        // type: xpc_objects(3) leaves non-getter calls on the wrong type undefined.
        // `self.raw` is live for the whole call (field invariant) and only read here.

        if self.is_type(&raw const _xpc_type_null) {
            return Ok(XpcMessage::Null);
        }
        if self.is_type(&raw const _xpc_type_bool) {
            // SAFETY: live bool object (checked above).
            return Ok(XpcMessage::Bool(unsafe { xpc_bool_get_value(self.raw) }));
        }
        if self.is_type(&raw const _xpc_type_int64) {
            // SAFETY: live int64 object (checked above).
            return Ok(XpcMessage::Int64(unsafe { xpc_int64_get_value(self.raw) }));
        }
        if self.is_type(&raw const _xpc_type_uint64) {
            // SAFETY: live uint64 object (checked above).
            return Ok(XpcMessage::Uint64(unsafe {
                xpc_uint64_get_value(self.raw)
            }));
        }
        if self.is_type(&raw const _xpc_type_double) {
            // SAFETY: live double object (checked above).
            return Ok(XpcMessage::Double(unsafe {
                xpc_double_get_value(self.raw)
            }));
        }
        if self.is_type(&raw const _xpc_type_string) {
            // SAFETY: live string object (checked above). Returns its internal
            // NUL-terminated storage, or NULL (handled below).
            let ptr = unsafe { xpc_string_get_string_ptr(self.raw) };
            if ptr.is_null() {
                return Err(XpcError::NullObject("string contents"));
            }
            // SAFETY: `CStr::from_ptr` needs a non-null pointer to a NUL-terminated buffer
            // that is not mutated while borrowed. `ptr` is non-null (checked) and points
            // to the string object's NUL-terminated storage; string objects are immutable
            // and `self` keeps it alive past the borrow, which ends at `into_owned`.
            let value = unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned();
            return Ok(XpcMessage::String(value));
        }
        if self.is_type(&raw const _xpc_type_data) {
            // SAFETY: live data object (checked above).
            let len = unsafe { xpc_data_get_length(self.raw) };
            if len == 0 {
                return Ok(XpcMessage::Data(Vec::new()));
            }
            if len > isize::MAX.unsigned_abs() {
                return Err(XpcError::UnsupportedObjectType("data too large"));
            }
            // SAFETY: live data object (checked above). Returns its internal storage of
            // `xpc_data_get_length` bytes, or NULL (handled below).
            let ptr = unsafe { xpc_data_get_bytes_ptr(self.raw) }.cast::<u8>();
            if ptr.is_null() {
                return Err(XpcError::NullObject("data contents"));
            }
            // SAFETY: `slice::from_raw_parts` needs a non-null, aligned pointer to `len`
            // initialised bytes in one allocation, unmutated while borrowed, with
            // `len <= isize::MAX`. `ptr` is non-null (checked), `u8` has alignment 1, it is
            // the data object's internal buffer of `len` bytes (xpc.h), data objects are
            // immutable, `self` keeps it alive past the borrow (ends at `to_vec`), and
            // `len` was bounded above.
            let bytes = unsafe { slice::from_raw_parts(ptr, len) }.to_vec();
            return Ok(XpcMessage::Data(bytes));
        }
        if self.is_type(&raw const _xpc_type_fd) {
            // SAFETY: live fd object (checked above). Returns a new descriptor the caller
            // must close, or -1 (handled below).
            let fd = unsafe { xpc_fd_dup(self.raw) };
            if fd < 0 {
                return Err(XpcError::FdDupFailed);
            }
            // SAFETY: `OwnedFd::from_raw_fd` requires an open descriptor, not -1, that
            // nothing else owns or closes and that needs only `close` as cleanup.
            // xpc_fd_dup returned a new descriptor (not -1, checked) that the caller must
            // close (xpc.h), and it is handed to nothing else.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            return Ok(XpcMessage::Fd(Arc::new(fd)));
        }
        if self.is_type(&raw const _xpc_type_uuid) {
            // SAFETY: live uuid object (checked above). Returns its 16 `uuid_t` bytes,
            // or NULL (handled below).
            let ptr = unsafe { xpc_uuid_get_bytes(self.raw) };
            if ptr.is_null() {
                return Err(XpcError::NullObject("uuid bytes"));
            }
            let mut bytes = [0u8; 16];
            // SAFETY: as for the data case: `ptr` is non-null (checked), aligned for `u8`,
            // and points to the immutable object's 16 `uuid_t` bytes, which `self` keeps
            // alive until the copy below completes.
            bytes.copy_from_slice(unsafe { slice::from_raw_parts(ptr, 16) });
            return Ok(XpcMessage::Uuid(bytes));
        }
        if self.is_type(&raw const _xpc_type_date) {
            // SAFETY: live date object (checked above).
            return Ok(XpcMessage::Date(unsafe { xpc_date_get_value(self.raw) }));
        }
        if self.is_type(&raw const _xpc_type_endpoint) {
            return Ok(XpcMessage::Endpoint(XpcEndpoint::from_raw_object(
                self.retain_clone(),
            )?));
        }
        if self.is_type(&raw const _xpc_type_array) {
            let (sender, receiver) = mpsc::channel();
            // Return u8 (1 = continue) because bool does not implement objc2's Encode
            // trait; a 1-byte integer return of 1 is a valid C `bool` true.
            let block = StackBlock::new(move |_idx: usize, value: xpc_object_t| -> u8 {
                abort_on_unwind(|| {
                    // SAFETY: `value` is the current element (`_Nonnull`) of the array
                    // being iterated, which keeps it alive during this invocation. It is
                    // reachable from `self` and its owner is a child owner on this thread,
                    // so `self`'s graph condition covers it.
                    _ = sender.send(unsafe { Self::retain(value, "array element") });
                    1
                })
            });
            // SAFETY: `xpc_array_apply` needs a live array and a block of type
            // `bool (^)(size_t, xpc_object_t)`. `self.raw` is a live array (checked above).
            // `*block` is block2's `Block<dyn Fn(usize, xpc_object_t) -> u8>`, which
            // block2 documents as an Objective-C block pointer with that signature. The
            // applier is `XPC_NOESCAPE`, so the stack block outlives every invocation.
            unsafe {
                xpc_array_apply(self.raw, (&raw const *block).cast::<c_void>().cast_mut());
            }
            // Dropping the block drops its sender, so the drain ends after the last item.
            drop(block);
            let mut values = Vec::new();
            for value in receiver.try_iter() {
                values.push(value?.to_message_inner(depth + 1)?);
            }
            return Ok(XpcMessage::Array(values));
        }
        if self.is_type(&raw const _xpc_type_dictionary) {
            let (sender, receiver) = mpsc::channel();
            // Return u8 (1 = continue) — same reasoning as the array case above.
            let block = StackBlock::new(move |key: *const c_char, value: xpc_object_t| -> u8 {
                abort_on_unwind(|| {
                    // SAFETY: `key` is the current key (`_Nonnull`, NUL-terminated) of the
                    // dictionary being iterated, live and unmutated for this invocation;
                    // the borrow ends at `into_owned`.
                    let key = unsafe { CStr::from_ptr(key) }
                        .to_string_lossy()
                        .into_owned();
                    // SAFETY: `value` is the current value (`_Nonnull`) of the dictionary
                    // being iterated, which keeps it alive during this invocation; graph
                    // condition as for the array case.
                    _ = sender.send((key, unsafe { Self::retain(value, "dictionary value") }));
                    1
                })
            });
            // SAFETY: as for `xpc_array_apply` above, with a live dictionary and a block
            // of type `bool (^)(const char *, xpc_object_t)`.
            unsafe {
                xpc_dictionary_apply(self.raw, (&raw const *block).cast::<c_void>().cast_mut());
            }
            drop(block);
            let mut values = BTreeMap::new();
            for (key, value) in receiver.try_iter() {
                values.insert(key, value?.to_message_inner(depth + 1)?);
            }
            return Ok(XpcMessage::Dictionary(values));
        }

        Err(XpcError::UnsupportedObjectType("xpc object"))
    }

    pub(crate) fn is_type(&self, ty: *const _xpc_type_s) -> bool {
        // SAFETY: `self.raw` is non-null and live (field invariant).
        unsafe { raw_type_is(self.raw, ty) }
    }
}

impl Drop for OwnedXpcObject {
    fn drop(&mut self) {
        // SAFETY: `xpc_release` requires an object the caller holds a reference on; this
        // value owns exactly one (field invariant) and `raw` is not used afterwards. The
        // object is not a connection (field invariant), the only object kind whose
        // release has lifecycle preconditions in <xpc/xpc.h>/<xpc/connection.h>.
        unsafe { xpc_release(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::io::{ErrorKind, Read};
    use std::os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    };
    use std::sync::Arc;
    use std::time::Duration;

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
        assert_matches!(nan, XpcMessage::Double(v) if v.is_nan());
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
        let original = Arc::new(OwnedFd::from(file));
        let result = rt(XpcMessage::Fd(original.clone()));
        let XpcMessage::Fd(duped) = result else {
            panic!("expected Fd variant")
        };
        assert_ne!(
            duped.as_raw_fd(),
            original.as_raw_fd(),
            "round-tripped fd must be a dup, not the original"
        );
        assert_ne!(XpcMessage::Fd(duped), XpcMessage::Fd(original));
    }

    #[test]
    fn received_fd_closes_with_its_last_clone() {
        let (mut reader, writer) = UnixStream::pair().expect("socket pair");
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        // the sent `Arc` is dropped after encoding; only the received dup remains
        let received = rt(XpcMessage::Fd(Arc::new(OwnedFd::from(writer))));
        let clone = received.clone();
        assert_eq!(received, clone);
        drop(received);

        reader.set_nonblocking(true).expect("nonblocking");
        let still_open = reader
            .read(&mut [0; 1])
            .expect_err("a writer is still open");
        assert_eq!(still_open.kind(), ErrorKind::WouldBlock);

        drop(clone);
        reader.set_nonblocking(false).expect("blocking");
        assert_eq!(reader.read(&mut [0; 1]).expect("end of stream"), 0);
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
