use std::io;
use std::num::NonZeroUsize;

use ahash::{HashMap, HashMapExt as _};
use bytes::Bytes;
use parking_lot::Mutex;
use rama_utils::{macros::generate_set_and_with, octets::kib};

use super::ReadAt;

/// Default block size: one page on common platforms.
const DEFAULT_BLOCK_SIZE: NonZeroUsize = match NonZeroUsize::new(kib(4)) {
    Some(size) => size,
    None => NonZeroUsize::MIN,
};

/// Smallest automatic shard, so random block placement cannot thrash one shard.
const MIN_AUTO_SHARD_BYTES: usize = kib(512);

/// Configuration of a [`BlockCache`].
///
/// The default budget is zero, which disables caching.
#[derive(Debug, Clone)]
pub struct BlockCacheConfig {
    budget: usize,
    block_size: NonZeroUsize,
    shards: Option<NonZeroUsize>,
}

impl Default for BlockCacheConfig {
    fn default() -> Self {
        Self {
            budget: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            shards: None,
        }
    }
}

impl BlockCacheConfig {
    /// A config with `budget` bytes of cache and default block size and shards.
    #[must_use]
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            ..Self::default()
        }
    }

    generate_set_and_with! {
        /// Bytes of block data the cache may hold; zero disables caching.
        pub fn budget(mut self, budget: usize) -> Self {
            self.budget = budget;
            self
        }
    }

    generate_set_and_with! {
        /// Size of one cached block (default 4 KiB).
        pub fn block_size(mut self, block_size: NonZeroUsize) -> Self {
            self.block_size = block_size;
            self
        }
    }

    generate_set_and_with! {
        /// Number of independently locked shards; `None` derives it from the
        /// available parallelism and the budget.
        pub fn shards(mut self, shards: Option<NonZeroUsize>) -> Self {
            self.shards = shards;
            self
        }
    }

    /// Bytes of block data the cache may hold.
    #[must_use]
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Size of one cached block.
    #[must_use]
    pub fn block_size(&self) -> NonZeroUsize {
        self.block_size
    }
}

/// A [`ReadAt`] wrapper that keeps recently read blocks in memory.
///
/// The source is read in fixed-size blocks, held within a byte budget across
/// sharded locks and evicted with the CLOCK algorithm. A read that spans
/// blocks is assembled from them. Reads larger than a quarter of the budget
/// go straight to the source so one large read cannot flush the cache.
///
/// The cache assumes the source does not change: the size is captured at
/// construction and cached blocks are never revalidated. Wrap a new cache
/// around a new source when the source is replaced.
#[derive(Debug)]
pub struct BlockCache<R> {
    inner: R,
    size: u64,
    block_size: usize,
    bypass_len: usize,
    shards: Box<[Mutex<Shard>]>,
}

#[derive(Debug)]
struct Shard {
    index: HashMap<u64, usize>,
    slots: Vec<Slot>,
    capacity: usize,
    hand: usize,
}

#[derive(Debug)]
struct Slot {
    block: u64,
    data: Bytes,
    referenced: bool,
}

impl<R: ReadAt> BlockCache<R> {
    /// Wrap `inner`, capturing its current size.
    ///
    /// # Errors
    ///
    /// Returns the error of [`ReadAt::size`] on `inner`.
    pub fn new(inner: R, config: &BlockCacheConfig) -> io::Result<Self> {
        let size = inner.size()?;
        let block_size = config.block_size.get();
        let blocks = config.budget / block_size;
        let shard_count = if blocks == 0 {
            0
        } else {
            let wanted = config
                .shards
                .map_or_else(|| auto_shards(config.budget), NonZeroUsize::get);
            wanted.clamp(1, blocks)
        };
        let shards = (0..shard_count)
            .map(|i| {
                // spread the remainder so the shards add up to the budget
                let capacity = blocks / shard_count + usize::from(i < blocks % shard_count);
                Mutex::new(Shard {
                    index: HashMap::with_capacity(capacity),
                    slots: Vec::with_capacity(capacity),
                    capacity,
                    hand: 0,
                })
            })
            .collect();
        Ok(Self {
            inner,
            size,
            block_size,
            bypass_len: config.budget / 4,
            shards,
        })
    }

    /// The wrapped source.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The size of the source captured at construction.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Whether the source was empty at construction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Whether blocks are kept at all (the budget holds at least one block).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.shards.is_empty()
    }

    /// The size of one block.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// The block with index `index`, shorter than the block size only at the
    /// end of the source.
    ///
    /// A cached block is returned without copying. With caching disabled the
    /// block is read from the source on every call.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] for a block past the captured
    /// size, or the error of the source.
    pub fn block(&self, index: u64) -> io::Result<Bytes> {
        let block_size = self.block_size as u64;
        let start = index
            .checked_mul(block_size)
            .filter(|&start| start < self.size)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        // bounded by `block_size`, a usize
        let len = (self.size - start).min(block_size) as usize;

        let Some(shard) = self.shard(index) else {
            return self.read_block(start, len);
        };
        if let Some(data) = shard.lock().get(index) {
            return Ok(data);
        }
        let data = self.read_block(start, len)?;
        shard.lock().insert(index, data.clone());
        Ok(data)
    }

    fn read_block(&self, start: u64, len: usize) -> io::Result<Bytes> {
        let mut buf = vec![0u8; len];
        self.inner.read_exact_at(&mut buf, start)?;
        Ok(Bytes::from(buf))
    }

    fn shard(&self, index: u64) -> Option<&Mutex<Shard>> {
        if self.shards.is_empty() {
            return None;
        }
        // Fibonacci hashing spreads neighbouring blocks over the shards
        let hash = index.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32;
        self.shards.get(hash as usize % self.shards.len())
    }
}

/// `4 × available_parallelism` rounded up to a power of two, while every
/// shard keeps at least [`MIN_AUTO_SHARD_BYTES`].
fn auto_shards(budget: usize) -> usize {
    let parallelism = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let by_budget = (budget / MIN_AUTO_SHARD_BYTES).max(1);
    parallelism
        .saturating_mul(4)
        .next_power_of_two()
        .min(by_budget)
}

impl Shard {
    fn get(&mut self, block: u64) -> Option<Bytes> {
        let &slot = self.index.get(&block)?;
        let slot = self.slots.get_mut(slot)?;
        slot.referenced = true;
        Some(slot.data.clone())
    }

    fn insert(&mut self, block: u64, data: Bytes) {
        if self.index.contains_key(&block) || self.capacity == 0 {
            // a concurrent miss on the same block already filled it
            return;
        }
        if self.slots.len() < self.capacity {
            self.index.insert(block, self.slots.len());
            self.slots.push(Slot {
                block,
                data,
                referenced: false,
            });
            return;
        }
        // CLOCK: clear reference bits until an unreferenced slot comes up
        let victim = loop {
            let hand = self.hand;
            self.hand = (hand + 1) % self.slots.len();
            let Some(slot) = self.slots.get_mut(hand) else {
                return;
            };
            if !slot.referenced {
                break hand;
            }
            slot.referenced = false;
        };
        if let Some(slot) = self.slots.get_mut(victim) {
            self.index.remove(&slot.block);
            *slot = Slot {
                block,
                data,
                referenced: false,
            };
            self.index.insert(block, victim);
        }
    }
}

impl<R: ReadAt> ReadAt for BlockCache<R> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.size)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        if buf.is_empty() {
            return Ok(());
        }
        if !self.is_enabled() || buf.len() > self.bypass_len {
            return self.inner.read_exact_at(buf, offset);
        }

        let block_size = self.block_size as u64;
        let mut pos = offset;
        let mut out = buf;
        while pos < end {
            let block = self.block(pos / block_size)?;
            // within one block, so it fits a usize
            let within = (pos % block_size) as usize;
            let src = block
                .get(within..)
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let n = src.len().min(out.len());
            let (head, tail) = out.split_at_mut(n);
            head.copy_from_slice(&src[..n]);
            out = tail;
            pos += n as u64;
        }
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.size)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Counts reads that reach the source.
    struct Counting {
        data: Vec<u8>,
        reads: AtomicUsize,
    }

    impl Counting {
        fn new(len: usize) -> Self {
            Self {
                data: (0..len).map(|i| (i * 7 % 256) as u8).collect(),
                reads: AtomicUsize::new(0),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
        }
    }

    impl ReadAt for Counting {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.data.read_exact_at(buf, offset)
        }

        fn size(&self) -> io::Result<u64> {
            self.data.size()
        }
    }

    fn config(budget: usize, block: usize, shards: usize) -> BlockCacheConfig {
        BlockCacheConfig::new(budget)
            .with_block_size(NonZeroUsize::new(block).unwrap())
            .with_shards(NonZeroUsize::new(shards).unwrap())
    }

    fn cached_blocks<R>(cache: &BlockCache<R>) -> usize {
        cache.shards.iter().map(|s| s.lock().slots.len()).sum()
    }

    #[test]
    fn disabled_by_default() {
        let cache = BlockCache::new(Counting::new(1000), &BlockCacheConfig::default()).unwrap();
        assert!(!cache.is_enabled());
        let mut buf = [0u8; 10];
        cache.read_exact_at(&mut buf, 5).unwrap();
        cache.read_exact_at(&mut buf, 5).unwrap();
        assert_eq!(cache.get_ref().reads(), 2);
        assert_eq!(&buf[..], &cache.get_ref().data[5..15]);
    }

    #[test]
    fn reads_straddling_blocks() {
        let cache = BlockCache::new(Counting::new(1000), &config(1024, 64, 2)).unwrap();
        let mut buf = [0u8; 150];
        cache.read_exact_at(&mut buf, 60).unwrap();
        assert_eq!(&buf[..], &cache.get_ref().data[60..210]);
        // blocks 0..=3 were read once each
        assert_eq!(cache.get_ref().reads(), 4);
        cache.read_exact_at(&mut buf, 60).unwrap();
        assert_eq!(cache.get_ref().reads(), 4);
        assert_eq!(&buf[..], &cache.get_ref().data[60..210]);
    }

    #[test]
    fn last_block_is_short_and_eof_is_reported() {
        let cache = BlockCache::new(Counting::new(1000), &config(kib(4), 64, 1)).unwrap();
        let last = cache.block(1000 / 64).unwrap();
        assert_eq!(last.len(), 1000 % 64);
        assert_eq!(&last[..], &cache.get_ref().data[960..]);
        let err = cache.block(1000 / 64 + 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let err = cache.block(u64::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let mut buf = [0u8; 41];
        cache.read_exact_at(&mut buf[..40], 960).unwrap();
        let err = cache.read_exact_at(&mut buf, 960).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let err = cache.read_exact_at(&mut buf, u64::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        cache.read_exact_at(&mut [], 1000).unwrap();
        assert_eq!(cache.size().unwrap(), 1000);
    }

    #[test]
    fn eviction_stays_within_budget() {
        // 4 blocks of budget over 2 shards
        let cache = BlockCache::new(Counting::new(64 * 100), &config(256, 64, 2)).unwrap();
        for block in 0..100u64 {
            let data = cache.block(block).unwrap();
            let start = block as usize * 64;
            assert_eq!(&data[..], &cache.get_ref().data[start..start + 64]);
            assert!(cached_blocks(&cache) <= 4);
        }
        assert_eq!(cached_blocks(&cache), 4);
    }

    #[test]
    fn clock_keeps_referenced_blocks() {
        let cache = BlockCache::new(Counting::new(64 * 100), &config(256, 64, 1)).unwrap();
        for block in 0..4u64 {
            cache.block(block).unwrap();
        }
        // touch block 0 between every new block so CLOCK keeps it
        for block in 4..20u64 {
            cache.block(0).unwrap();
            cache.block(block).unwrap();
        }
        let reads = cache.get_ref().reads();
        cache.block(0).unwrap();
        assert_eq!(cache.get_ref().reads(), reads, "block 0 stayed cached");
    }

    #[test]
    fn oversize_reads_bypass_the_cache() {
        let cache = BlockCache::new(Counting::new(10_000), &config(1024, 64, 1)).unwrap();
        let mut big = vec![0u8; 1024 / 4 + 1];
        cache.read_exact_at(&mut big, 100).unwrap();
        assert_eq!(cache.get_ref().reads(), 1);
        assert_eq!(cached_blocks(&cache), 0);
        assert_eq!(&big[..], &cache.get_ref().data[100..100 + big.len()]);
    }

    #[test]
    fn budget_below_one_block_disables() {
        let cache = BlockCache::new(Counting::new(100), &config(63, 64, 4)).unwrap();
        assert!(!cache.is_enabled());
        assert_eq!(cache.block(0).unwrap().len(), 64);
    }

    #[test]
    fn shards_never_exceed_blocks() {
        let cache = BlockCache::new(Counting::new(100), &config(128, 64, 16)).unwrap();
        assert_eq!(cache.shards.len(), 2);
        let auto = BlockCache::new(Counting::new(100), &BlockCacheConfig::new(kib(4))).unwrap();
        assert_eq!(auto.shards.len(), 1);
    }

    #[test]
    fn concurrent_random_reads() {
        let len = kib(64);
        let cache = BlockCache::new(Counting::new(len), &config(kib(8), 256, 4)).unwrap();
        let rounds = if cfg!(miri) { 20 } else { 2000 };
        std::thread::scope(|s| {
            for t in 0..8u64 {
                let cache = &cache;
                s.spawn(move || {
                    let mut state = 0x2545_F491_4F6C_DD1D ^ (t + 1);
                    for _ in 0..rounds {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        let n = (state % 700) as usize;
                        let offset = (state >> 24) as usize % (len - n);
                        let mut buf = vec![0u8; n];
                        cache.read_exact_at(&mut buf, offset as u64).unwrap();
                        assert_eq!(buf, cache.get_ref().data[offset..offset + n]);
                    }
                });
            }
        });
        assert!(cached_blocks(&cache) <= kib(8) / 256);
    }
}
