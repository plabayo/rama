use slab::Slab;

/// Buffers frames for multiple streams.
#[derive(Debug)]
pub(super) struct Buffer<T> {
    slab: Slab<Slot<T>>,
}

/// A sequence of frames in a `Buffer`
#[derive(Debug)]
pub(super) struct Deque {
    indices: Option<Indices>,
}

/// Tracks the head & tail for a sequence of frames in a `Buffer`.
#[derive(Debug, Default, Copy, Clone)]
struct Indices {
    head: usize,
    tail: usize,
}

#[derive(Debug)]
struct Slot<T> {
    value: T,
    next: Option<usize>,
}

impl<T> Buffer<T> {
    pub(super) fn new() -> Self {
        Self { slab: Slab::new() }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.slab.is_empty()
    }
}

impl Deque {
    pub(super) fn new() -> Self {
        Self { indices: None }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.indices.is_none()
    }

    pub(super) fn push_back<T>(&mut self, buf: &mut Buffer<T>, value: T) {
        let key = buf.slab.insert(Slot { value, next: None });

        match self.indices {
            Some(ref mut idxs) => {
                buf.slab[idxs.tail].next = Some(key);
                idxs.tail = key;
            }
            None => {
                self.indices = Some(Indices {
                    head: key,
                    tail: key,
                });
            }
        }
    }

    pub(super) fn push_front<T>(&mut self, buf: &mut Buffer<T>, value: T) {
        let key = buf.slab.insert(Slot { value, next: None });

        match self.indices {
            Some(ref mut idxs) => {
                buf.slab[key].next = Some(idxs.head);
                idxs.head = key;
            }
            None => {
                self.indices = Some(Indices {
                    head: key,
                    tail: key,
                });
            }
        }
    }

    pub(super) fn pop_front<T>(&mut self, buf: &mut Buffer<T>) -> Option<T> {
        match self.indices {
            Some(mut idxs) => {
                let mut slot = buf.slab.remove(idxs.head);

                if idxs.head == idxs.tail {
                    assert!(slot.next.is_none());
                    self.indices = None;
                } else {
                    idxs.head = slot.next.take().unwrap();
                    self.indices = Some(idxs);
                }

                Some(slot.value)
            }
            None => None,
        }
    }
}
