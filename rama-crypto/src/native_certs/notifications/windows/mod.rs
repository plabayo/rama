use rama_core::telemetry::tracing::warn;
use std::{
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::Cryptography::{
        CERT_STORE_CTRL_NOTIFY_CHANGE, CERT_STORE_CTRL_RESYNC, CERT_STORE_OPEN_EXISTING_FLAG,
        CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER_ID,
        CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, CertCloseStore, CertControlStore, CertOpenStore,
        HCERTSTORE,
    },
    System::Threading::{CreateEventW, WaitForSingleObject},
};

pub(crate) struct StoreNotifications(Vec<StoreWatch>);

impl StoreNotifications {
    pub(crate) fn new() -> Self {
        let store_locations = [
            CERT_SYSTEM_STORE_CURRENT_USER_ID,
            CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
        ];
        Self(
            store_locations
                .into_iter()
                .filter_map(|location| match StoreWatch::open(location) {
                    Ok(watch) => Some(watch),
                    Err(error) => {
                        warn!(%error, location, "could not watch Windows ROOT certificate store");
                        None
                    }
                })
                .collect(),
        )
    }

    pub(crate) fn poll(&mut self) -> Option<bool> {
        let mut changed = false;
        self.0.retain(|watch| {
            // SAFETY: the event is owned by the watch, which lives for this call.
            match unsafe { WaitForSingleObject(watch.event.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => return true,
                WAIT_OBJECT_0 => (),
                _ => {
                    let error = io::Error::last_os_error();
                    warn!(%error, "could not poll Windows ROOT store change event");
                    return false;
                }
            }
            changed = true;
            if let Err(error) = watch.control(CERT_STORE_CTRL_RESYNC) {
                warn!(%error, "could not rearm Windows ROOT certificate store notification");
                return false;
            }
            true
        });
        // Partial coverage still requires a periodic reread of both ROOT stores.
        (changed || self.0.len() == 2).then_some(changed)
    }
}

struct StoreWatch {
    store: HCERTSTORE,
    event: OwnedHandle,
}

// SAFETY: Windows permits these store and event handles to be moved across
// threads. Only the owning watch accesses them and closes the store.
unsafe impl Send for StoreWatch {}

impl StoreWatch {
    fn open(location: u32) -> io::Result<Self> {
        // SAFETY: null addresses request default security and an unnamed event.
        // The handle is checked before OwnedHandle takes ownership.
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the live event is a new owned handle.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let root = [
            u16::from(b'R'),
            u16::from(b'O'),
            u16::from(b'O'),
            u16::from(b'T'),
            0,
        ];
        // SAFETY: the selected provider accepts a NUL-terminated UTF-16 store
        // name and the predefined certificate store locations.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                (location << 16) | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                root.as_ptr().cast(),
            )
        };
        if store.is_null() {
            return Err(io::Error::last_os_error());
        }
        let watch = Self { store, event };
        watch.control(CERT_STORE_CTRL_NOTIFY_CHANGE)?;
        Ok(watch)
    }

    fn control(&self, operation: u32) -> io::Result<()> {
        let event = self.event.as_raw_handle();
        // SAFETY: the store is live and both supported operations take a
        // pointer to the live event handle.
        let result =
            unsafe { CertControlStore(self.store, 0, operation, (&raw const event).cast()) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for StoreWatch {
    fn drop(&mut self) {
        // SAFETY: this uniquely owned store closes before its event handle.
        unsafe { CertCloseStore(self.store, 0) };
    }
}
