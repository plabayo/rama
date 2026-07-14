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
