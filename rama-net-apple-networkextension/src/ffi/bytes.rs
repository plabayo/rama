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
    pub host_utf8: *const u8,
    /// Length of `host_utf8`.
    pub host_utf8_len: usize,
    /// UDP port, host byte order.
    pub port: u16,
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
        }
    }

    /// Parse the view into a [`std::net::SocketAddr`].
    ///
    /// Returns `None` when the view is absent, when `host_utf8` is
    /// null/empty, when the bytes aren't valid UTF-8, or when the
    /// host is not an IP literal.
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
        Some(std::net::SocketAddr::new(ip, self.port))
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
    present: bool,
}

impl UdpPeerScratch {
    /// Build a scratch from `Option<SocketAddr>`. `None` yields a
    /// scratch whose `as_view()` is absent.
    #[must_use]
    pub fn new(peer: Option<std::net::SocketAddr>) -> Self {
        let mut buf = [0u8; 64];
        let Some(addr) = peer else {
            return Self {
                buf,
                len: 0,
                port: 0,
                present: false,
            };
        };
        // Write the IP literal into `buf`. Using `std::io::Write`
        // on a slice avoids any allocation; the IP `Display` impl
        // is the canonical textual form (numeric IPv4, RFC 5952
        // IPv6).
        let len = {
            use std::io::Write as _;
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            // `write!` only fails on capacity; we treat any error
            // as "fall back to absent" rather than truncate a
            // partial address.
            if write!(&mut cursor, "{}", addr.ip()).is_err() {
                return Self {
                    buf: [0u8; 64],
                    len: 0,
                    port: 0,
                    present: false,
                };
            }
            cursor.position() as usize
        };
        Self {
            buf,
            len,
            port: addr.port(),
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
        }
    }
}
