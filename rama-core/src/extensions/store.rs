use core::any::TypeId;
use core::hash::{Hash, Hasher};

use rama_utils::collections::AppendOnlyVec;

use super::{Egress, Extension, Extensions, Ingress, TypeErasedExtension};

/// One level of an [`Extensions`] chain, shared by all clones of its handle,
/// so cloning a handle is a reference count and forking one allocation.
// `repr(C)`: a lookup that skips the level reads the links, the boundary flag
// and the filter only, which share the first cache line with the first entries.
#[repr(C)]
pub(super) struct Node {
    /// The level whose entries a [`Extensions::with_base`] view shows instead
    /// of its own (always empty) ones. That level is never a view itself.
    pub(super) view_of: Option<Extensions>,
    pub(super) parent: Option<Extensions>,
    /// Whether this level starts a connection nested on top of its parent, see
    /// [`Extensions::fork_nested_connection`].
    pub(super) nested_connection: bool,
    pub(super) entries: Store,
}

/// Entries an [`Extensions`] level holds without allocating storage of its
/// own: most levels hold no more, and are then a single allocation.
const INLINE_ENTRIES: usize = 6;

/// The first storage a level allocates, once its inline entries are used up,
/// holds `2^SPILL_BIN_OFFSET` entries, every later one double the one before.
const SPILL_BIN_OFFSET: u32 = 4;

/// The entries of one [`Extensions`] level.
///
/// Every entry is pushed with its [`Store::seen_bit`] as tag, which makes the
/// tags of the entries (see [`AppendOnlyVec::push_tagged`]) a tiny bloom
/// filter over the [`TypeId`]s pushed so far. Type lookups are dominated by
/// misses (optional extensions that were never inserted) and each miss walks
/// every level of the chain and every entry in it. A level whose filter has
/// none of the requested bits cannot hold a match, so it is skipped in O(1)
/// instead of scanned.
#[derive(Default)]
pub(super) struct Store {
    pub(super) entries: AppendOnlyVec<TypeErasedExtension, INLINE_ENTRIES, SPILL_BIN_OFFSET>,
}

/// Bit of the [`Store`] filter reserved for [`Egress`] and [`Ingress`] wrappers.
///
/// Lookups recurse into these wrappers, so a level holding one can never be
/// skipped, whatever the requested type. They get their own bit rather than a
/// [`type_bit`] so this holds without any per-type bookkeeping.
const WRAPPER_BIT: usize = 1 << (usize::BITS - 1);

/// Number of slots a [`TypeId`] can hash to: every bit of the [`Store`]
/// filter except [`WRAPPER_BIT`].
const TYPE_SLOTS: usize = usize::BITS as usize - 1;

/// The slot of a [`TypeId`], below [`TYPE_SLOTS`].
///
/// `TypeId` hashes as 64 bits of an already well distributed 128-bit value,
/// so the hash is used as is, without another round of mixing.
#[inline(always)]
pub(super) fn type_slot(id: TypeId) -> usize {
    struct Fold(u64);

    impl Hasher for Fold {
        #[inline(always)]
        fn finish(&self) -> u64 {
            self.0
        }

        #[inline(always)]
        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
            }
        }

        #[inline(always)]
        fn write_u64(&mut self, v: u64) {
            self.0 ^= v;
        }
    }

    let mut hasher = Fold(0);
    id.hash(&mut hasher);
    // a mask is cheaper than a modulo, the one slot left over folds into the last
    ((hasher.finish() as usize) & (usize::BITS as usize - 1)).min(TYPE_SLOTS - 1)
}

/// The bit a [`TypeId`] sets in the [`Store`] filter, never [`WRAPPER_BIT`].
#[inline(always)]
pub(super) fn type_bit(id: TypeId) -> usize {
    1 << type_slot(id)
}

impl Store {
    /// The bit of the filter that an entry of type `T` sets.
    ///
    /// A constant for every `T`, so pushing a typed value needs no hashing.
    #[inline(always)]
    pub(super) fn seen_bit_of<T: Extension>() -> usize {
        Self::seen_bit(TypeId::of::<T>())
    }

    #[inline(always)]
    fn seen_bit(id: TypeId) -> usize {
        if id == TypeId::of::<Egress<Extensions>>() || id == TypeId::of::<Ingress<Extensions>>() {
            WRAPPER_BIT
        } else {
            type_bit(id)
        }
    }

    pub(super) fn push(&self, extension: TypeErasedExtension) -> usize {
        let bit = Self::seen_bit(extension.type_id);
        self.push_with_bit(extension, bit)
    }

    /// Push an entry whose [`Self::seen_bit`] is already known.
    #[inline(always)]
    pub(super) fn push_with_bit(&self, extension: TypeErasedExtension, bit: usize) -> usize {
        self.entries.push_tagged(extension, bit)
    }

    /// Whether this level holds an [`Egress`] or [`Ingress`] wrapper. Read it
    /// after the entries to scan, then no wrapper among them is missed (see
    /// [`AppendOnlyVec::push_tagged`]).
    #[inline(always)]
    pub(super) fn has_wrappers(&self) -> bool {
        self.entries.tags() & WRAPPER_BIT != 0
    }

    /// Whether a lookup for `targets` (the OR of their [`type_bit`]s) has to
    /// scan this level: false only if it can hold neither of them nor a wrapper.
    #[inline(always)]
    pub(super) fn may_contain(&self, targets: usize) -> bool {
        self.entries.tags() & (targets | WRAPPER_BIT) != 0
    }
}
