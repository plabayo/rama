use std::ffi::c_void;

use rama_core::bytes::Bytes;
use rama_core::error::BoxError;

#[repr(C)]
#[derive(Debug)]
pub struct BytesOwned {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl BytesOwned {
    /// # Safety
    ///
    /// `self` must come from this crate's FFI allocation path and must not have
    /// been freed before.
    pub unsafe fn free(self) {
        let Self { ptr, len, cap } = self;
        if ptr.is_null() || cap == 0 {
            debug_assert!(
                ptr.is_null() && cap == 0,
                "both are expected to be true if we reach this path"
            );
            return;
        }

        // `Vec::from_raw_parts` requires `len <= cap`. We clamp defensively for
        // release builds (matches what the original `Vec` would have upheld),
        // and shout in dev if the caller violated the contract — that means a
        // bug somewhere upstream in the FFI ownership chain.
        if len > cap {
            // Defense in depth: dev panics on the assert; release clamps
            // to keep the dealloc sound, but we'd rather hear about the
            // ownership-chain bug than have it stay hidden until a
            // memory bug surfaces in production. Surface as `error!`
            // (not `warn!`) so it reliably appears in extension logs
            // even at default filter levels.
            tracing::error!(
                target: "rama_apple_ne::ffi",
                len,
                cap,
                "BytesOwned::free: len > cap (clamping for release-build safety) — caller violated Vec invariant somewhere upstream"
            );
        }
        debug_assert!(
            len <= cap,
            "BytesOwned::free: len ({len}) > cap ({cap}) — caller violated Vec invariant"
        );
        let vec_len = len.min(cap);
        let vec_cap = cap;
        // SAFETY: caller contract guarantees pointer/capacity originate from a `Vec<u8>`.
        _ = unsafe { Vec::from_raw_parts(ptr, vec_len, vec_cap) };
    }
}

impl TryFrom<Vec<u8>> for BytesOwned {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Ok(Self {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            });
        }

        let (ptr, vec_len, vec_cap) = bytes.into_raw_parts();
        Ok(Self {
            ptr,
            len: vec_len,
            cap: vec_cap,
        })
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct BytesView {
    pub ptr: *const u8,
    pub len: usize,
}

impl BytesView {
    /// # Safety
    ///
    /// `self.ptr` must be valid for reads of `self.len` bytes for the returned
    /// lifetime.
    pub unsafe fn into_slice<'a>(self) -> &'a [u8] {
        if self.ptr.is_null() || self.len == 0 {
            return &[];
        }
        // SAFETY: caller contract guarantees pointer validity.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// Swift→Rust ingress buffer carrying an ownership-transfer handle, so
/// Rust can hold the bytes across the async bridge without copying them.
///
/// # Ownership contract
///
/// The caller transfers ownership of the buffer to Rust. Rust takes
/// ownership **iff** the corresponding `on_*_bytes_owned` call returns
/// [`Accepted`] — it then invokes `release(owner)` exactly once when the
/// wrapping [`Bytes`] (and all its clones) are dropped, on an arbitrary
/// Tokio worker thread, so `release` MUST be safe to call from any
/// thread. On [`Paused`] or [`Closed`] Rust does NOT take ownership and
/// never calls `release`; the caller still owns the buffer (and must
/// replay it on `Paused`, free it on `Closed`) — exactly the same
/// retain/replay discipline the borrowed [`BytesView`] path already
/// requires.
///
/// [`Accepted`]: crate::tproxy::TcpDeliverStatus::Accepted
/// [`Paused`]: crate::tproxy::TcpDeliverStatus::Paused
/// [`Closed`]: crate::tproxy::TcpDeliverStatus::Closed
#[repr(C)]
#[derive(Debug)]
pub struct BytesOwnedView {
    /// Start of the buffer; must stay valid for `len` bytes until
    /// `release` runs.
    pub ptr: *const u8,
    /// Length of the buffer in bytes.
    pub len: usize,
    /// Opaque owner handle handed back to `release` verbatim.
    pub owner: *mut c_void,
    /// Releases `owner`. Invoked exactly once, from an arbitrary thread.
    pub release: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// Owner stored inside a [`Bytes`] built from a [`BytesOwnedView`]; keeps
/// the foreign buffer alive and releases it on drop.
struct ForeignOwnedBuf {
    ptr: *const u8,
    len: usize,
    owner: *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}

// SAFETY: the buffer is treated as immutable for the owner's lifetime
// (only `as_ref` reads it), and `release` is documented to be callable
// from any thread. `Bytes::from_owner` calls `as_ref` exactly once and
// only ever drops the owner afterwards, so there is no concurrent access
// that would require `Sync`.
unsafe impl Send for ForeignOwnedBuf {}

impl AsRef<[u8]> for ForeignOwnedBuf {
    fn as_ref(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            return &[];
        }
        // SAFETY: the FFI caller guarantees `ptr` is valid for `len`
        // bytes until `release` runs, and Drop defers `release` until
        // the last `Bytes` clone is gone.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for ForeignOwnedBuf {
    fn drop(&mut self) {
        // SAFETY: `release` is invoked exactly once — `Bytes` drops its
        // owner a single time, when the last clone is released.
        unsafe { (self.release)(self.owner) };
    }
}

impl BytesOwnedView {
    /// Take ownership of the buffer and wrap it as a zero-copy [`Bytes`].
    ///
    /// Call this ONLY once Rust has committed to owning the buffer (the
    /// channel slot was reserved). The returned `Bytes` releases the
    /// foreign owner when its last clone drops.
    ///
    /// # Safety
    ///
    /// `ptr`/`len` must be valid until `release` runs, and `release`
    /// (when `Some`) must be safe to call exactly once from any thread.
    #[must_use]
    pub unsafe fn into_bytes(self) -> Bytes {
        let Some(release) = self.release else {
            // Defensive: a caller that omits the releaser cannot transfer
            // ownership, so copy rather than risk a leak / dangling read.
            if self.ptr.is_null() || self.len == 0 {
                return Bytes::new();
            }
            // SAFETY: caller contract on ptr/len for the call duration.
            return Bytes::copy_from_slice(unsafe {
                std::slice::from_raw_parts(self.ptr, self.len)
            });
        };
        if self.ptr.is_null() || self.len == 0 {
            // Empty payload: nothing to wrap, but we own the handle and
            // must release it.
            // SAFETY: `release` is valid and invoked exactly once here.
            unsafe { release(self.owner) };
            return Bytes::new();
        }
        Bytes::from_owner(ForeignOwnedBuf {
            ptr: self.ptr,
            len: self.len,
            owner: self.owner,
            release,
        })
    }

    /// Release the owned buffer immediately without wrapping it — used on
    /// the empty-payload `Accepted` shortcut where there is nothing to
    /// enqueue but Rust has still taken ownership.
    ///
    /// # Safety
    ///
    /// `release` (when `Some`) must be safe to call exactly once.
    pub unsafe fn release_now(self) {
        if let Some(release) = self.release {
            // SAFETY: invoked exactly once per ownership transfer.
            unsafe { release(self.owner) };
        }
    }
}

/// Per-datagram peer endpoint, in the wire-portable shape both
/// sides of the FFI can express.
///
/// `present = false` means the caller does not have endpoint
/// attribution for this datagram (rare; usually a test or a
/// kernel-callback edge case). When `present = true`, `host_utf8`
/// is the textual host (a numeric IP literal in production —
/// kernel `flow.readDatagrams` returns resolved IPs and the per-
/// peer NWConnection's bound endpoint is also an IP); `port` is the
/// 16-bit UDP port.
///
/// The Rust side parses `host_utf8` as an [`std::net::IpAddr`]; if
/// the host isn't IP-parseable, the resulting `Option<SocketAddr>`
/// is `None`, which the rest of the engine treats the same as
/// `present = false`. We deliberately do NOT do DNS resolution
/// here — that'd be hot-path-fatal for UDP.
#[repr(C)]
#[derive(Debug)]
pub struct UdpPeerView {
    /// `true` when host/port are valid for this datagram.
    pub present: bool,
    /// Textual host (UTF-8). Not required to be NUL-terminated.
    /// The textual form does NOT carry a `%zone` suffix — scoping
    /// rides in `scope_id` so a numeric round-trip is exact.
    pub host_utf8: *const u8,
    /// Length of `host_utf8`.
    pub host_utf8_len: usize,
    /// UDP port, host byte order.
    pub port: u16,
    /// IPv6 zone identifier (interface index, `0` = none). Always
    /// `0` for IPv4. See [`std::net::SocketAddrV6::scope_id`].
    pub scope_id: u32,
}

impl UdpPeerView {
    /// Construct an "absent" peer view (host pointer is null).
    #[inline]
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            present: false,
            host_utf8: std::ptr::null(),
            host_utf8_len: 0,
            port: 0,
            scope_id: 0,
        }
    }

    /// Parse the view into a [`std::net::SocketAddr`].
    ///
    /// Returns `None` when the view is absent, when `host_utf8` is
    /// null/empty, when the bytes aren't valid UTF-8, or when the
    /// host is not an IP literal. For IPv6, `scope_id` is applied
    /// to the resulting `SocketAddrV6`; for IPv4 it is ignored.
    ///
    /// # Safety
    ///
    /// When `present` is `true`, `host_utf8` must be valid for reads
    /// of `host_utf8_len` bytes for the duration of this call.
    pub unsafe fn into_socket_addr(self) -> Option<std::net::SocketAddr> {
        if !self.present || self.host_utf8.is_null() || self.host_utf8_len == 0 {
            return None;
        }
        // SAFETY: caller contract guarantees pointer validity.
        let bytes = unsafe { std::slice::from_raw_parts(self.host_utf8, self.host_utf8_len) };
        let host_str = std::str::from_utf8(bytes).ok()?;
        let ip: std::net::IpAddr = host_str.parse().ok()?;
        Some(match ip {
            std::net::IpAddr::V4(v4) => {
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(v4, self.port))
            }
            std::net::IpAddr::V6(v6) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                v6,
                self.port,
                0, // flowinfo unused
                self.scope_id,
            )),
        })
    }
}

/// Stack-resident scratch buffer that holds the textual host of a
/// `SocketAddr` so a [`UdpPeerView`] can be handed to FFI without
/// allocating. `UdpPeerScratch` must outlive any [`UdpPeerView`]
/// borrowed from it; the typical pattern is to keep it on the stack
/// of the closure that issues the C callback.
///
/// Buffer size is 64 — enough for the longest practical textual
/// form of `IpAddr` (IPv6 fully expanded with a zone identifier is
/// under 50 bytes). If `write!` runs out of capacity the peer is
/// silently dropped to `absent`, which the receiving side treats
/// as "no attribution".
pub struct UdpPeerScratch {
    buf: [u8; 64],
    len: usize,
    port: u16,
    scope_id: u32,
    present: bool,
}

impl UdpPeerScratch {
    /// Build a scratch from `Option<SocketAddr>`. `None` yields a
    /// scratch whose `as_view()` is absent. For IPv6 link-local
    /// inputs, the `SocketAddrV6::scope_id` is carried alongside
    /// the textual IP — the textual form itself does NOT include
    /// the `%zone` suffix (Swift handles index↔name conversion).
    #[must_use]
    pub fn new(peer: Option<std::net::SocketAddr>) -> Self {
        let mut buf = [0u8; 64];
        let Some(addr) = peer else {
            return Self {
                buf,
                len: 0,
                port: 0,
                scope_id: 0,
                present: false,
            };
        };
        // Write the IP literal into `buf`. Using `std::io::Write`
        // on a slice avoids any allocation; the IP `Display` impl
        // is the canonical textual form (numeric IPv4, RFC 5952
        // IPv6) — and crucially, `Ipv6Addr::Display` does not
        // include the scope id, which matches the contract here.
        let len_result: Option<usize> = {
            use std::io::Write as _;
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            // `write!` only fails on capacity; we treat any error
            // as "fall back to absent" rather than truncate a
            // partial address. (Unreachable in practice — 64 bytes
            // comfortably exceeds the longest `IpAddr::Display`
            // form, which is 39 chars for fully-expanded IPv6 —
            // but kept as belt-and-suspenders for future-proofing.)
            if write!(&mut cursor, "{}", addr.ip()).is_err() {
                None
            } else {
                Some(cursor.position() as usize)
            }
        };
        let Some(len) = len_result else {
            // Re-use `buf` even though its contents may be partial
            // garbage — `present: false` keeps any reader from
            // touching it.
            return Self {
                buf,
                len: 0,
                port: 0,
                scope_id: 0,
                present: false,
            };
        };
        let scope_id = match addr {
            std::net::SocketAddr::V6(v6) => v6.scope_id(),
            std::net::SocketAddr::V4(_) => 0,
        };
        Self {
            buf,
            len,
            port: addr.port(),
            scope_id,
            present: true,
        }
    }

    /// Borrow a `UdpPeerView` from this scratch. The view is only
    /// valid for the lifetime of `self`.
    #[must_use]
    pub fn as_view(&self) -> UdpPeerView {
        if !self.present {
            return UdpPeerView::absent();
        }
        UdpPeerView {
            present: true,
            host_utf8: self.buf.as_ptr(),
            host_utf8_len: self.len,
            port: self.port,
            scope_id: self.scope_id,
        }
    }
}

#[cfg(test)]
mod udp_peer_scope_id_roundtrip {
    //! Pins the FFI round-trip of `SocketAddrV6::scope_id`. Without
    //! these tests a regression that silently drops the zone
    //! identifier (e.g. `addr.ip()` instead of an explicit
    //! `scope_id` field) would only manifest at runtime for
    //! IPv6 link-local UDP — and only on hardware with multiple
    //! interfaces — which is exactly the class of bug we keep
    //! shipping if we don't pin it.
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    /// `addr → UdpPeerScratch → UdpPeerView → SocketAddr` must be
    /// the identity for IPv6 link-local with a non-zero scope id.
    #[test]
    fn ipv6_link_local_scope_id_roundtrips() {
        let original = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            5353,
            0,
            4, // arbitrary non-zero interface index
        ));
        let scratch = UdpPeerScratch::new(Some(original));
        let view = scratch.as_view();
        assert_eq!(view.scope_id, 4);
        // SAFETY: view borrows from scratch which is still alive.
        let got = unsafe { view.into_socket_addr() }.unwrap();
        assert_eq!(got, original);
        match got {
            SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 4),
            SocketAddr::V4(_) => panic!("expected V6"),
        }
    }

    /// IPv4 must always emit `scope_id = 0` and a `SocketAddrV4`
    /// after the round-trip (no accidental promotion to V6).
    #[test]
    fn ipv4_emits_zero_scope_id() {
        let original = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353));
        let scratch = UdpPeerScratch::new(Some(original));
        let view = scratch.as_view();
        assert_eq!(view.scope_id, 0);
        let got = unsafe { view.into_socket_addr() }.unwrap();
        assert_eq!(got, original);
        assert!(matches!(got, SocketAddr::V4(_)));
    }

    /// IPv6 unicast without a scope id round-trips with
    /// `scope_id = 0` and unscoped equality.
    #[test]
    fn ipv6_unicast_no_scope_roundtrips() {
        let original = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0));
        let scratch = UdpPeerScratch::new(Some(original));
        let view = scratch.as_view();
        assert_eq!(view.scope_id, 0);
        let got = unsafe { view.into_socket_addr() }.unwrap();
        assert_eq!(got, original);
    }

    /// `None` round-trips to `None` regardless of any other field
    /// state.
    #[test]
    fn absent_peer_roundtrips_to_none() {
        let scratch = UdpPeerScratch::new(None);
        let view = scratch.as_view();
        assert!(!view.present);
        let got = unsafe { view.into_socket_addr() };
        assert!(got.is_none());
    }

    /// The textual IPv6 form on the wire must NOT carry a `%zone`
    /// suffix — scoping rides in `scope_id`. Pin the contract so a
    /// well-meaning refactor that adopts `Display` on `SocketAddrV6`
    /// (which includes scope) is caught.
    #[test]
    fn ipv6_textual_form_does_not_include_zone_suffix() {
        let original = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 5353, 0, 7));
        let scratch = UdpPeerScratch::new(Some(original));
        let view = scratch.as_view();
        let bytes = unsafe { std::slice::from_raw_parts(view.host_utf8, view.host_utf8_len) };
        let host = std::str::from_utf8(bytes).unwrap();
        assert!(
            !host.contains('%'),
            "host_utf8 must not include zone suffix; got {host}"
        );
        assert_eq!(host, "fe80::1");
    }
}

#[cfg(test)]
mod owned_view_ownership {
    //! Pins the [`BytesOwnedView`] ownership contract: the foreign
    //! `release` runs exactly once when (and only when) Rust takes
    //! ownership, and never when an un-consumed view is dropped (the
    //! `Paused`/`Closed` path, where Swift keeps the buffer).
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    unsafe extern "C" fn count_release(ctx: *mut c_void) {
        // SAFETY: tests always pass a live `&AtomicUsize` as `ctx`.
        let counter = unsafe { &*(ctx as *const AtomicUsize) };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    fn view(buf: &[u8], counter: &AtomicUsize) -> BytesOwnedView {
        BytesOwnedView {
            ptr: buf.as_ptr(),
            len: buf.len(),
            owner: std::ptr::from_ref(counter) as *mut c_void,
            release: Some(count_release),
        }
    }

    #[test]
    fn into_bytes_releases_once_after_last_clone() {
        let counter = AtomicUsize::new(0);
        let buf = b"hello world".to_vec();
        // SAFETY: `buf` outlives every `Bytes` derived from the view.
        let bytes = unsafe { view(&buf, &counter).into_bytes() };
        assert_eq!(bytes.as_ref(), b"hello world");
        assert_eq!(counter.load(Ordering::SeqCst), 0, "held: not released");
        let clone = bytes.clone();
        drop(bytes);
        assert_eq!(counter.load(Ordering::SeqCst), 0, "clone still holds it");
        drop(clone);
        assert_eq!(counter.load(Ordering::SeqCst), 1, "released exactly once");
        drop(buf);
    }

    #[test]
    fn dropping_unconsumed_view_never_releases() {
        let counter = AtomicUsize::new(0);
        let buf = b"data".to_vec();
        // Simulates the Paused/Closed path: the view falls out of scope
        // without being consumed, so ownership stays with the caller.
        {
            let _unconsumed = view(&buf, &counter);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        drop(buf);
    }

    #[test]
    fn release_now_releases_once() {
        let counter = AtomicUsize::new(0);
        let buf = b"x".to_vec();
        // SAFETY: release is valid and called exactly once.
        unsafe { view(&buf, &counter).release_now() };
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        drop(buf);
    }

    #[test]
    fn empty_into_bytes_still_releases_owned_handle() {
        let counter = AtomicUsize::new(0);
        let v = BytesOwnedView {
            ptr: std::ptr::null(),
            len: 0,
            owner: std::ptr::from_ref(&counter) as *mut c_void,
            release: Some(count_release),
        };
        // SAFETY: empty payload; `into_bytes` releases the handle.
        let bytes = unsafe { v.into_bytes() };
        assert!(bytes.is_empty());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_releaser_falls_back_to_copy() {
        let buf = b"copied".to_vec();
        let v = BytesOwnedView {
            ptr: buf.as_ptr(),
            len: buf.len(),
            owner: std::ptr::null_mut(),
            release: None,
        };
        // SAFETY: ptr/len valid for the call; no releaser → copy.
        let bytes = unsafe { v.into_bytes() };
        assert_eq!(bytes.as_ref(), b"copied");
        // Independent of `buf` now (copied), so dropping buf is safe.
        drop(buf);
        assert_eq!(bytes.as_ref(), b"copied");
    }
}
