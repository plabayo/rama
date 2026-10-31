//! Per-lookup view over a positional source.

use std::cell::RefCell;
use std::io;

use rama_core::bytes::Bytes;
use rama_core::io::{BlockCache, ReadAt};

use super::super::decoder::{OFFSET_OUT_OF_BOUNDS, Section, slice_at};
use crate::address::ip::geo::GeoIpError;

/// Blocks a window keeps; a lookup touches about ten, tree blocks first.
const SLOTS: usize = 8;

/// Placeholder returned to the decoder after a source error; [`Window::finish`]
/// swaps in the recorded error.
const READ_FAILED: GeoIpError = GeoIpError::Corrupt("database read failed");

/// Short-lived [`Section`] over a [`BlockCache`], created for one lookup.
///
/// Byte reads hit the blocks held here and only go to the cache on a miss.
/// Offsets are bounds-checked against the size captured at open, with the
/// same errors as the slice source. A source error is recorded, since the
/// record decoder treats unreadable fields as absent; callers pass every
/// result through [`Self::finish`].
pub(super) struct Window<'c, R> {
    cache: &'c BlockCache<R>,
    size: usize,
    block_size: usize,
    slots: RefCell<Slots>,
    error: RefCell<Option<GeoIpError>>,
}

#[derive(Default)]
struct Slots {
    blocks: [Option<(u64, Bytes)>; SLOTS],
    /// Next slot to replace, round robin.
    next: usize,
}

impl<'c, R: ReadAt> Window<'c, R> {
    /// A window over the first `size` bytes of `cache`.
    pub(super) fn new(cache: &'c BlockCache<R>, size: usize) -> Self {
        Self {
            cache,
            size,
            block_size: cache.block_size(),
            slots: RefCell::default(),
            error: RefCell::default(),
        }
    }

    /// `result`, unless a source error was recorded on the way.
    pub(super) fn finish<T>(&self, result: Result<T, GeoIpError>) -> Result<T, GeoIpError> {
        match self.error.borrow_mut().take() {
            Some(err) => Err(err),
            None => result,
        }
    }

    /// Run `f` over the block holding `index`, loading it on a miss.
    fn with_block<T>(&self, index: usize, f: impl FnOnce(&[u8]) -> T) -> Result<T, GeoIpError> {
        let index = index as u64;
        let mut slots = self.slots.borrow_mut();
        let held = slots
            .blocks
            .iter()
            .position(|slot| matches!(slot, Some((held, _)) if *held == index));
        let slot = if let Some(slot) = held {
            slot
        } else {
            let block = self.cache.block(index).map_err(|err| self.fail(err))?;
            let slot = slots.next;
            slots.next = (slot + 1) % SLOTS;
            *slots.blocks.get_mut(slot).ok_or(READ_FAILED)? = Some((index, block));
            slot
        };
        match slots.blocks.get(slot) {
            Some(Some((_, block))) => Ok(f(block)),
            _ => Err(READ_FAILED),
        }
    }

    /// Record the first source error and hand the decoder a placeholder.
    fn fail(&self, err: io::Error) -> GeoIpError {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(source_error(err));
        }
        READ_FAILED
    }

    /// Bounds-check `len` bytes at `off` exactly as [`slice_at`] does.
    fn check_range(&self, off: usize, len: usize) -> Result<usize, GeoIpError> {
        let end = off
            .checked_add(len)
            .ok_or(GeoIpError::Corrupt("length overflow"))?;
        if end > self.size {
            return Err(GeoIpError::Corrupt("slice out of bounds"));
        }
        Ok(end)
    }
}

impl<R: ReadAt> Section for Window<'_, R> {
    fn byte(&self, off: usize) -> Result<u8, GeoIpError> {
        if off >= self.size {
            return Err(OFFSET_OUT_OF_BOUNDS);
        }
        let within = off % self.block_size;
        self.with_block(off / self.block_size, |block| block.get(within).copied())?
            .ok_or_else(|| self.fail(io::ErrorKind::UnexpectedEof.into()))
    }

    fn read_into(&self, off: usize, out: &mut [u8]) -> Result<(), GeoIpError> {
        let end = self.check_range(off, out.len())?;
        let mut pos = off;
        let mut out = out;
        while pos < end {
            let within = pos % self.block_size;
            let n = self.with_block(pos / self.block_size, |block| {
                let src = block.get(within..).unwrap_or_default();
                let n = src.len().min(out.len());
                out[..n].copy_from_slice(&src[..n]);
                n
            })?;
            if n == 0 {
                return Err(self.fail(io::ErrorKind::UnexpectedEof.into()));
            }
            out = &mut core::mem::take(&mut out)[n..];
            pos += n;
        }
        Ok(())
    }

    fn with_slice<T>(
        &self,
        off: usize,
        len: usize,
        f: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, GeoIpError> {
        let end = self.check_range(off, len)?;
        if len == 0 {
            return Ok(f(&[]));
        }
        let first = off / self.block_size;
        if (end - 1) / self.block_size == first {
            let within = off % self.block_size;
            // the block is shorter only if the source shrank under the cache
            return self
                .with_block(first, |block| block.get(within..within + len).map(f))?
                .ok_or_else(|| self.fail(io::ErrorKind::UnexpectedEof.into()));
        }
        let mut bytes = vec![0u8; len];
        self.read_into(off, &mut bytes)?;
        Ok(f(slice_at(&bytes, 0, len)?))
    }
}

/// Map a source error: a short read inside the size captured at open, or a
/// stale handle, means the file changed under the reader.
pub(super) fn source_error(err: io::Error) -> GeoIpError {
    match err.kind() {
        io::ErrorKind::UnexpectedEof | io::ErrorKind::StaleNetworkFileHandle => {
            GeoIpError::SourceChanged
        }
        _ => GeoIpError::Io(err),
    }
}
