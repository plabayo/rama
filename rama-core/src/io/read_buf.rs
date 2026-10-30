use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, ready};
use std::io;

use tokio::io::{AsyncRead, ReadBuf};

/// Poll `reader` once for at most `limit` bytes into the unfilled part of `buf`,
/// and advance `buf` past the bytes read, returning their count.
///
/// The reader gets a [`ReadBuf`] of its own over that part, as [`tokio::io::Take`]
/// does, so the result can be trusted whatever `reader` does with it.
///
/// # Panics
///
/// Panics if `reader` replaces the [`ReadBuf`] it is given with one over other
/// memory.
///
/// # Safety-usable invariant
///
/// On `Poll::Ready(Ok(n))`: `n` is at most `limit` and at most `buf.remaining()`
/// at the call, and `buf` was advanced by exactly `n` over bytes of its own buffer
/// that are now initialized. On any other result the filled length of `buf` is
/// unchanged. `buf` is never replaced.
pub fn poll_read_limited<R: AsyncRead + ?Sized>(
    reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    limit: usize,
) -> Poll<io::Result<usize>> {
    let mut limited = buf.take(limit);
    let start = limited.filled().as_ptr();
    let cap = limited.capacity();
    ready!(reader.poll_read(cx, &mut limited))?;

    let filled = limited.filled();
    // A safe reader can assign a `ReadBuf` over its own memory to `limited`.
    assert!(
        ptr::eq(filled.as_ptr(), start) && filled.len() <= cap,
        "AsyncRead::poll_read replaced the ReadBuf it was given"
    );
    let n = filled.len();

    // SAFETY: `ReadBuf::assume_init(n)` needs the first `n` unfilled bytes of `buf`
    // initialized.
    // - `take` built `limited` over the first `cap` unfilled bytes of `buf`, which
    //   start at `start` (tokio docs: `take`, `filled`).
    // - Whatever buffer `limited` wraps now, its filled bytes are initialized
    //   (tokio docs: filled is a subset of initialized), and the assert places them
    //   at `[start, start + n)` with `n <= cap`: the first `n` unfilled bytes of `buf`.
    unsafe { buf.assume_init(n) };
    buf.advance(n);
    Poll::Ready(Ok(n))
}

#[cfg(test)]
mod tests {
    use core::task::Waker;
    use std::sync::atomic::{AtomicPtr, Ordering};

    use super::*;

    /// Keeps the replacement buffers reachable, so leak checkers do not report them.
    static REPLACEMENT: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

    /// A reader that replaces its `ReadBuf` with one over 16 filled bytes of its own.
    struct Replacer;

    impl AsyncRead for Replacer {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let own: &'static mut [u8] = Box::leak(vec![7u8; 64].into_boxed_slice());
            REPLACEMENT.store(own.as_mut_ptr(), Ordering::Relaxed);
            let mut other = ReadBuf::new(own);
            other.advance(16);
            *buf = other;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    #[should_panic(expected = "replaced the ReadBuf")]
    fn poll_read_limited_rejects_replaced_read_buf() {
        let mut storage = [core::mem::MaybeUninit::<u8>::uninit(); 32];
        let mut buf = ReadBuf::uninit(&mut storage);
        let mut cx = Context::from_waker(Waker::noop());
        let res = poll_read_limited(Pin::new(&mut Replacer), &mut cx, &mut buf, usize::MAX);
        assert!(res.is_ready());
        let sum: u32 = buf.filled().iter().copied().map(u32::from).sum();
        assert!(sum < u32::MAX);
    }

    #[test]
    fn poll_read_limited_caps_and_advances() {
        let mut storage = [core::mem::MaybeUninit::<u8>::uninit(); 8];
        let mut buf = ReadBuf::uninit(&mut storage);
        buf.put_slice(b"ab");
        let mut cx = Context::from_waker(Waker::noop());

        let mut src: &[u8] = b"cdefghij";
        let n = poll_read_limited(Pin::new(&mut src), &mut cx, &mut buf, 3);
        assert_eq!(n.map(Result::unwrap), Poll::Ready(3));
        assert_eq!(buf.filled(), b"abcde");

        // capped by the remaining room, not the limit
        let n = poll_read_limited(Pin::new(&mut src), &mut cx, &mut buf, usize::MAX);
        assert_eq!(n.map(Result::unwrap), Poll::Ready(3));
        assert_eq!(buf.filled(), b"abcdefgh");
        assert_eq!(src, b"ij");
    }
}
