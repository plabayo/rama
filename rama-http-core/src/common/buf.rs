use std::collections::VecDeque;
use std::io::IoSlice;

use rama_core::bytes::{Buf, BufMut, Bytes, BytesMut};

pub(crate) struct BufList<T> {
    bufs: VecDeque<T>,
}

impl<T: Buf> BufList<T> {
    pub(crate) fn new() -> Self {
        Self {
            bufs: VecDeque::new(),
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, buf: T) {
        debug_assert!(buf.has_remaining());
        // Holding no empty buffer is what makes a non-empty list one with bytes left.
        if buf.has_remaining() {
            self.bufs.push_back(buf);
        }
    }

    #[inline]
    pub(crate) fn bufs_cnt(&self) -> usize {
        self.bufs.len()
    }
}

impl<T: Buf> Buf for BufList<T> {
    #[inline]
    fn remaining(&self) -> usize {
        self.bufs.iter().map(Buf::remaining).sum()
    }

    #[inline]
    fn has_remaining(&self) -> bool {
        !self.bufs.is_empty()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.bufs.front().map(Buf::chunk).unwrap_or_default()
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            {
                let front = &mut self.bufs[0];
                let rem = front.remaining();
                if rem > cnt {
                    front.advance(cnt);
                    return;
                } else {
                    front.advance(rem);
                    cnt -= rem;
                }
            }
            self.bufs.pop_front();
        }
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        let mut vecs = 0;
        for buf in &self.bufs {
            vecs += buf.chunks_vectored(&mut dst[vecs..]);
            if vecs == dst.len() {
                break;
            }
        }
        vecs
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        // Our inner buffer may have an optimized version of copy_to_bytes, and if the whole
        // request can be fulfilled by the front buffer, we can take advantage.
        match self.bufs.front_mut() {
            Some(front) if front.remaining() == len => {
                let b = front.copy_to_bytes(len);
                self.bufs.pop_front();
                b
            }
            Some(front) if front.remaining() > len => front.copy_to_bytes(len),
            _ => {
                let rem = self.remaining();
                assert!(len <= rem, "`len` greater than remaining");
                let mut bm = BytesMut::with_capacity(len);
                if rem == len {
                    // `take` adds a limit check to every copied chunk.
                    bm.put(self);
                } else {
                    bm.put(self.take(len));
                }
                bm.freeze()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::*;

    fn hello_world_buf() -> BufList<Bytes> {
        BufList {
            bufs: vec![Bytes::from("Hello"), Bytes::from(" "), Bytes::from("World")].into(),
        }
    }

    #[test]
    fn has_remaining_tracks_remaining_through_every_advance() {
        let total = hello_world_buf().remaining();
        for first in 0..=total {
            for second in 0..=total - first {
                let mut bufs = hello_world_buf();
                for step in [first, second] {
                    bufs.advance(step);
                    assert_eq!(bufs.has_remaining(), bufs.remaining() > 0);
                }
                let rest = bufs.remaining();
                assert_eq!(bufs.copy_to_bytes(rest).len(), rest);
                assert!(!bufs.has_remaining());
            }
        }
    }

    #[test]
    fn to_bytes_of_everything_joins_all_buffers() {
        let mut bufs = hello_world_buf();
        assert_eq!(bufs.copy_to_bytes(11), "Hello World");
        assert!(!bufs.has_remaining());
    }

    #[test]
    fn to_bytes_shorter() {
        let mut bufs = hello_world_buf();
        let old_ptr = bufs.chunk().as_ptr();
        let start = bufs.copy_to_bytes(4);
        assert_eq!(start, "Hell");
        assert!(ptr::eq(old_ptr, start.as_ptr()));
        assert_eq!(bufs.chunk(), b"o");
        assert!(ptr::eq(old_ptr.wrapping_add(4), bufs.chunk().as_ptr()));
        assert_eq!(bufs.remaining(), 7);
    }

    #[test]
    fn to_bytes_eq() {
        let mut bufs = hello_world_buf();
        let old_ptr = bufs.chunk().as_ptr();
        let start = bufs.copy_to_bytes(5);
        assert_eq!(start, "Hello");
        assert!(ptr::eq(old_ptr, start.as_ptr()));
        assert_eq!(bufs.chunk(), b" ");
        assert_eq!(bufs.remaining(), 6);
    }

    #[test]
    fn to_bytes_longer() {
        let mut bufs = hello_world_buf();
        let start = bufs.copy_to_bytes(7);
        assert_eq!(start, "Hello W");
        assert_eq!(bufs.remaining(), 4);
    }

    #[test]
    fn one_long_buf_to_bytes() {
        let mut buf = BufList::new();
        buf.push(b"Hello World" as &[_]);
        assert_eq!(buf.copy_to_bytes(5), "Hello");
        assert_eq!(buf.chunk(), b" World");
    }

    #[test]
    #[should_panic(expected = "`len` greater than remaining")]
    fn buf_to_bytes_too_many() {
        hello_world_buf().copy_to_bytes(42);
    }
}
