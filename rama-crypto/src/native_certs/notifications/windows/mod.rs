use rama_core::telemetry::tracing::warn;
use std::{
    io,
    os::windows::io::{
        AsHandle as _, AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle,
    },
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
    /// Watch the current user and local machine ROOT stores.
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

    /// Poll the native notification source.
    pub(crate) fn poll(&mut self) -> Option<bool> {
        let mut changed = false;
        self.0.retain(|watch| {
            // SAFETY: `watch.event` is an event with `SYNCHRONIZE` (field invariant), open
            // while `retain` borrows `watch`.
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

    /// Borrow the store change events.
    ///
    /// # Safety-usable invariant
    ///
    /// Each yielded handle is a distinct `CreateEventW` event handle (`EVENT_ALL_ACCESS`).
    pub(crate) fn wait_handles(&self) -> impl Iterator<Item = BorrowedHandle<'_>> + '_ {
        self.0.iter().map(|watch| watch.event.as_handle())
    }
}

// The ROOT system store name, `'static` so its pointer outlives any use by `CertOpenStore`.
static ROOT: [u16; 5] = [b'R' as u16, b'O' as u16, b'O' as u16, b'T' as u16, 0];

struct StoreWatch {
    // Safety invariant: an open certificate store handle, closed only by `Drop`.
    store: HCERTSTORE,
    // Safety invariant: an unnamed auto-reset event from `CreateEventW` (`EVENT_ALL_ACCESS`).
    event: OwnedHandle,
}

// SAFETY: Windows permits these store and event handles to be moved across
// threads. Only the owning watch accesses them and closes the store.
unsafe impl Send for StoreWatch {}

impl StoreWatch {
    fn open(location: u32) -> io::Result<Self> {
        // SAFETY: both pointer parameters are optional and null: default security, no name.
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `event` is non-null, so it is the open handle to a new unnamed event that
        // nothing else owns; `CloseHandle` is its only cleanup (CreateEvent docs).
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        // SAFETY: `CERT_STORE_PROV_SYSTEM_W` takes `pvPara` as a NUL-terminated UTF-16
        // store name; `ROOT` is one and is `'static`. No other pointer is passed.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                (location << 16) | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                ROOT.as_ptr().cast(),
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
        // SAFETY: `self.store` is open (field invariant). For `NOTIFY_CHANGE` and `RESYNC`
        // `pvCtrlPara` is the address of a `CreateEvent` handle, here the local `event`
        // (field invariant), and `dwFlags` must be 0 (CertControlStore docs).
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
        // SAFETY: `self.store` is open and closed only here (field invariant); nothing
        // uses it afterwards.
        unsafe { CertCloseStore(self.store, 0) };
    }
}
