use core::cell::Cell;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

const BLOCK_SIZE: u64 = 1024;

static NEXT_BLOCK: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static BLOCK: Cell<Block> = const { Cell::new(Block { next: 0, end: 0 }) };
}

#[derive(Clone, Copy)]
struct Block {
    next: u64,
    end: u64,
}

/// Take the next id of this process.
///
/// Ids are unique within the process, with no ordering and no promise that
/// there are no gaps. Threads hand out blocks of their own, so they do not
/// contend.
#[doc(hidden)]
#[must_use]
pub fn next_id() -> NonZeroU64 {
    let id = BLOCK.with(|block| {
        let mut current = block.get();
        if current.next == current.end {
            let start = NEXT_BLOCK.fetch_add(BLOCK_SIZE, Ordering::Relaxed);
            current = Block {
                next: start,
                end: start + BLOCK_SIZE,
            };
        }
        block.set(Block {
            next: current.next + 1,
            end: current.end,
        });
        current.next
    });
    #[expect(
        clippy::expect_used,
        reason = "ids start at one, and the space is not exhausted in the lifetime of a process"
    )]
    let id = NonZeroU64::new(id).expect("an id is never zero");
    id
}

/// Define the id of one unit: `define_id! { pub struct ConnectionId; }`.
///
/// It is `Copy`, `Display` and an [`Extension`](crate::extensions::Extension).
#[macro_export]
macro_rules! define_id {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis struct $name(::core::num::NonZeroU64);

        impl $name {
            /// Take the next id of this process.
            #[must_use]
            $vis fn next() -> Self {
                Self($crate::telemetry::event::next_id())
            }

            /// The numeric value of this id.
            #[must_use]
            $vis const fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl $crate::extensions::Extension for $name {}
    };
}
