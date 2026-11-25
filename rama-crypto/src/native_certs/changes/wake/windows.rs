use std::{
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    ptr,
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{WAIT_FAILED, WAIT_OBJECT_0},
    System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects},
};

use crate::native_certs::notifications::StoreNotifications;

pub(crate) struct Wake(
    // Safety invariant: an unnamed auto-reset event from `CreateEventW` (`EVENT_ALL_ACCESS`).
    OwnedHandle,
);

impl Wake {
    /// A wake that no wait has consumed yet.
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: both pointer parameters are optional and null: default security, no name.
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `event` is non-null, so it is the open handle to a new unnamed event that
        // nothing else owns; `CloseHandle` is its only cleanup (CreateEvent docs).
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(event) }))
    }

    /// End the current or next wait early.
    pub(super) fn wake(&self) {
        // SAFETY: the handle is an event with `EVENT_MODIFY_STATE` (field invariant), open
        // while `&self` borrows its `OwnedHandle`.
        unsafe { SetEvent(self.0.as_raw_handle()) };
    }

    /// Returns whether a wake ended the wait, or an error when it could not block at all.
    pub(crate) fn wait(
        &self,
        notifications: Option<&StoreNotifications>,
        timeout: Duration,
    ) -> io::Result<bool> {
        let mut handles = [self.0.as_raw_handle(); 3];
        let mut count = 1;
        if let Some(notifications) = notifications {
            for (slot, event) in handles[1..].iter_mut().zip(notifications.wait_handles()) {
                *slot = event.as_raw_handle();
                count += 1;
            }
        }
        let millis = super::windows_wait_millis(timeout);
        // SAFETY: WaitForMultipleObjects needs `1 <= nCount <= MAXIMUM_WAIT_OBJECTS`, `nCount`
        // distinct handles with `SYNCHRONIZE`, none closed mid-wait (undefined behaviour).
        // - `count` is 1 plus at most `handles[1..].len()`, so `1..=3`, readable in `handles`.
        // - The wake event (field invariant) and the store events (`wait_handles`
        //   safety-usable invariant) are distinct `CreateEventW` handles (`EVENT_ALL_ACCESS`).
        // - All are borrowed from `self` and `notifications`, which outlive the call.
        let status = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, millis) };
        if status == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        if let Some(index) = status.checked_sub(WAIT_OBJECT_0)
            && (1..count).contains(&index)
            && let Some(&event) = usize::try_from(index).ok().and_then(|i| handles.get(i))
        {
            // The wait consumed the auto-reset store signal; restore it for the next poll.
            // SAFETY: `index` is in `1..count`, so `event` is a store event with
            // `EVENT_MODIFY_STATE` (`wait_handles`), still borrowed from `notifications`.
            unsafe { SetEvent(event) };
        }
        Ok(status == WAIT_OBJECT_0)
    }
}
