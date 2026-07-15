use std::collections::BTreeMap;

// Use `tokio`'s `unbounded_channel` channel instead of `std`'s channel as they implement `Sync`
use tokio::sync::mpsc::{
    UnboundedReceiver as Receiver, UnboundedSender as Sender, unbounded_channel as unbounded,
};

pub(crate) struct IdPool<T: Send + Sync> {
    used: BTreeMap<u32, T>,
    tx: Sender<u32>,
    rx: Receiver<u32>,
}

pub struct IdPoolGuard {
    id: u32,
    tx: Sender<u32>,
}

impl<T: Send + Sync> Default for IdPool<T> {
    fn default() -> Self {
        let (tx, rx) = unbounded();
        Self {
            used: BTreeMap::default(),
            tx,
            rx,
        }
    }
}

impl<T: Send + Sync> IdPool<T> {
    fn recycle(&mut self) {
        while let Ok(id) = self.rx.try_recv() {
            self.used.remove(&id);
        }
    }

    pub(crate) fn claim(&mut self, id: u32, value: T) -> Option<IdPoolGuard> {
        self.recycle();
        if self.used.contains_key(&id) {
            return None;
        }
        self.used.insert(id, value);
        Some(IdPoolGuard {
            id,
            tx: self.tx.clone(),
        })
    }

    pub(crate) fn get(&mut self, id: u32) -> Option<&mut T> {
        self.recycle();
        self.used.get_mut(&id)
    }
}

impl<T: Send + Sync> Drop for IdPool<T> {
    fn drop(&mut self) {
        self.recycle();
    }
}

impl IdPoolGuard {
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl Drop for IdPoolGuard {
    fn drop(&mut self) {
        _ = self.tx.send(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::IdPool;

    #[test]
    fn claimed_ids_are_exclusive_until_the_guard_drops() {
        let mut pool = IdPool::<u8>::default();

        let guard = pool.claim(1, 10).expect("fresh id claims");
        assert_eq!(guard.id(), 1);
        assert_eq!(pool.get(1).copied(), Some(10));
        assert!(pool.claim(1, 11).is_none(), "id in use must not re-claim");

        drop(guard);
        assert!(pool.get(1).is_none(), "dropping the guard recycles the id");
        let reguard = pool.claim(1, 12).expect("recycled id claims again");
        assert_eq!(pool.get(1).copied(), Some(12));
        drop(reguard);
    }
}
