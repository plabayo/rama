use core_foundation::runloop::{CFRunLoop, CFRunLoopRunResult, kCFRunLoopDefaultMode};
use parking_lot::Mutex;
use rama_core::telemetry::tracing::warn;
use std::{
    ffi::c_void,
    ptr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

type KeychainCallback = extern "C" fn(u32, *mut c_void, *mut c_void) -> i32;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainAddCallback(callback: KeychainCallback, mask: u32, context: *mut c_void) -> i32;
    fn SecKeychainRemoveCallback(callback: KeychainCallback) -> i32;
}

// Security identifies callbacks by function address. All policies share one
// registration and observe changes independently through their own cursor.
static SUBSCRIPTION: Mutex<Weak<AtomicBool>> = Mutex::new(Weak::new());
static CHANGE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct StoreNotifications {
    available: Arc<AtomicBool>,
    seen: u64,
}

impl StoreNotifications {
    pub(crate) fn new() -> Self {
        let seen = CHANGE.load(Ordering::Relaxed);
        let mut subscription = SUBSCRIPTION.lock();
        let available = subscription.upgrade().unwrap_or_else(|| {
            let available = Arc::new(AtomicBool::new(false));
            let watch = available.clone();
            let (ready, registered) = mpsc::sync_channel(0);
            match std::thread::Builder::new()
                .name("rama-native-trust".into())
                .spawn(move || watch_keychain(&watch, &ready))
            {
                Ok(_) => {
                    _ = registered.recv();
                }
                Err(error) => warn!(%error, "could not start keychain notification thread"),
            }
            *subscription = Arc::downgrade(&available);
            available
        });
        Self { available, seen }
    }

    pub(crate) fn poll(&mut self) -> Option<bool> {
        if !self.available.load(Ordering::Relaxed) {
            return None;
        }
        let current = CHANGE.load(Ordering::Relaxed);
        Some(std::mem::replace(&mut self.seen, current) != current)
    }
}

fn watch_keychain(available: &Arc<AtomicBool>, ready: &mpsc::SyncSender<()>) {
    // SecKeychain.h: add, delete, update, keychain list and trust settings.
    const MASK: u32 = (1 << 3) | (1 << 4) | (1 << 5) | (1 << 11) | (1 << 12);
    // SAFETY: the callback and its atomic state live for the entire process.
    let status = unsafe { SecKeychainAddCallback(keychain_changed, MASK, ptr::null_mut()) };
    available.store(status == 0, Ordering::Relaxed);
    _ = ready.send(());
    if status != 0 {
        warn!(status, "could not register keychain change callback");
        return;
    }
    loop {
        // Deliver events immediately and retire the thread after the last subscriber drops.
        let result = CFRunLoop::run_in_mode(
            // SAFETY: Core Foundation supplies this process-lifetime default mode.
            unsafe { kCFRunLoopDefaultMode },
            Duration::from_secs(30),
            false,
        );
        let mut subscription = SUBSCRIPTION.lock();
        let unused = Arc::strong_count(available) == 1;
        if unused || !matches!(result, CFRunLoopRunResult::TimedOut) {
            available.store(false, Ordering::Relaxed);
            // SAFETY: this thread owns the one registration of this function.
            unsafe { SecKeychainRemoveCallback(keychain_changed) };
            if unused {
                *subscription = Weak::new();
            }
            break;
        }
    }
}

extern "C" fn keychain_changed(_: u32, _: *mut c_void, _: *mut c_void) -> i32 {
    CHANGE.fetch_add(1, Ordering::Relaxed);
    0
}

#[cfg(test)]
mod tests;
