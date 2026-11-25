use std::{
    ffi::{CStr, c_char, c_int},
    io,
    os::fd::{BorrowedFd, RawFd},
    time::{Duration, Instant},
};

use rama_core::telemetry::tracing::warn;

// Apple's securityd posts this name for changes to trust settings, the default
// keychain/search list, and X.509 certificate items. Security.framework uses
// the same notification to invalidate its trust caches. The name comes from
// Apple's Security sources (SecItemInternal.h); notify(3) is a public API.
const CERTIFICATE_TRUST: &CStr = c"com.apple.security.certificatetrust";

unsafe extern "C" {
    fn notify_register_check(name: *const c_char, token: *mut c_int) -> u32;
    fn notify_check(token: c_int, changed: *mut c_int) -> u32;
    fn notify_cancel(token: c_int) -> u32;

    fn notify_register_file_descriptor(
        name: *const c_char,
        notify_fd: *mut c_int,
        flags: c_int,
        token: *mut c_int,
    ) -> u32;
}

/// How often a missing wait descriptor is registered again.
const WAIT_RETRY: Duration = Duration::from_secs(5);

pub(crate) type RegisterWait = fn(&CStr) -> Result<WaitToken, WaitError>;

pub(crate) struct StoreNotifications {
    token: Option<Token>,
    // Readable on each notification, so a waiting thread needs no polling.
    wait: Option<WaitToken>,
    name: Box<CStr>,
    register_wait: RegisterWait,
    wait_attempted_at: Instant,
    wait_warned: bool,
}

impl StoreNotifications {
    /// Create an unregistered native trust observer.
    pub(crate) fn new() -> Self {
        Self::watch(CERTIFICATE_TRUST, WaitToken::register)
    }

    /// Watch the platform trust settings for changes.
    pub(crate) fn watch(name: &CStr, register_wait: RegisterWait) -> Self {
        let token = Token::register(name)
            .inspect_err(|status| warn!(status, "could not watch macOS certificate trust"))
            .ok();
        let mut notifications = Self {
            token,
            wait: None,
            name: name.into(),
            register_wait,
            wait_attempted_at: Instant::now(),
            wait_warned: false,
        };
        notifications.register_wait();
        notifications
    }

    /// Whether notifications are watched but cannot end a blocking wait.
    pub(crate) fn wait_degraded(&self) -> bool {
        self.token.is_some() && self.wait.is_none()
    }

    /// Register a missing wait descriptor again, at most once per [`WAIT_RETRY`].
    pub(crate) fn retry_wait(&mut self) {
        if self.wait_degraded() && self.wait_attempted_at.elapsed() >= WAIT_RETRY {
            self.register_wait();
        }
    }

    /// Register the native wait descriptor.
    fn register_wait(&mut self) {
        if self.token.is_none() {
            return;
        }
        self.wait_attempted_at = Instant::now();
        match (self.register_wait)(&self.name) {
            Ok(wait) => {
                self.wait = Some(wait);
                self.wait_warned = false;
            }
            Err(error) if !self.wait_warned => {
                self.wait_warned = true;
                match error {
                    WaitError::Register(status) => warn!(
                        status,
                        "could not wait on macOS certificate trust notifications; polling until registration succeeds"
                    ),
                    WaitError::CloseOnExec(error) => warn!(
                        %error,
                        "could not make the macOS certificate trust descriptor close-on-exec; polling until registration succeeds"
                    ),
                }
            }
            Err(_) => (),
        }
    }

    /// Borrow the registered wait descriptor, if available.
    pub(crate) fn wait_fd(&self) -> Option<BorrowedFd<'_>> {
        self.wait.as_ref().map(WaitToken::fd)
    }

    /// Consume pending native wait notifications.
    pub(crate) fn drain_wait_fd(&mut self) {
        let Some(wait) = &self.wait else {
            return;
        };
        let mut buffer = [0_u8; 64];
        // SAFETY: `buffer` is writable for the 64 bytes passed; `wait.fd` is open by
        // the `WaitToken` invariants, as `&mut self` keeps `wait` alive for the call.
        let read = unsafe { libc::read(wait.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            return;
        }
        // A broken descriptor would keep every wait returning at once.
        if read <= 0 {
            warn!("could not read macOS certificate trust notification descriptor");
            self.wait = None;
            self.wait_attempted_at = Instant::now();
        }
    }

    /// Poll the native notification source.
    pub(crate) fn poll(&mut self) -> Option<bool> {
        match self.token.as_ref()?.check() {
            Ok(changed) => Some(changed),
            Err(status) => {
                warn!(
                    status,
                    "could not poll macOS certificate trust notification"
                );
                self.token = None;
                None
            }
        }
    }
}

struct Token {
    // Safety invariant: `token` is a notify(3) token that no other code cancels.
    token: c_int,
    // Safety invariant: `name` holds the string `token` was registered with.
    _name: Box<CStr>,
}

impl Token {
    fn register(name: &CStr) -> Result<Self, u32> {
        // notify(3) does not say whether it keeps the name pointer, so the registration owns it.
        let name: Box<CStr> = name.into();
        let mut token = -1;
        // SAFETY: `name` is NUL-terminated and, owned by the returned value, outlives the
        // registration; `token` is a writable `int` out-parameter (`<notify.h>`).
        let status = unsafe { notify_register_check(name.as_ptr(), &raw mut token) };
        if status != 0 {
            return Err(status);
        }
        let token = Self { token, _name: name };
        // notify_check always reports a change on the first call for a token.
        token.check()?;
        Ok(token)
    }

    fn check(&self) -> Result<bool, u32> {
        let mut changed = 0;
        // SAFETY: `changed` is a writable `int` out-parameter; an invalid token only
        // yields an error status (`<notify.h>`).
        let status = unsafe { notify_check(self.token, &raw mut changed) };
        if status == 0 {
            Ok(changed != 0)
        } else {
            Err(status)
        }
    }
}

pub(crate) enum WaitError {
    Register(u32),
    CloseOnExec(io::Error),
}

pub(crate) struct WaitToken {
    // Safety invariant: a live notify(3) registration, cancelled only when this value drops.
    token: c_int,
    // Safety invariant: `fd` is the descriptor notify(3) created for `token`, not -1 and open
    // until `token` is cancelled (assumed: notify(3) documents no other close).
    fd: RawFd,
    // Safety invariant: `name` holds the string `token` was registered with.
    _name: Box<CStr>,
}

impl WaitToken {
    pub(crate) fn register(name: &CStr) -> Result<Self, WaitError> {
        // notify(3) does not say whether it keeps the name pointer, so the registration owns it.
        let name: Box<CStr> = name.into();
        let mut fd = -1;
        let mut token = -1;
        // SAFETY: `name` is NUL-terminated and, owned by the returned value, outlives the
        // registration; `fd` and `token` are writable `int` out-parameters. With `flags = 0`
        // notify(3) creates a new descriptor ("By default, a new file descriptor is created").
        let status = unsafe {
            notify_register_file_descriptor(name.as_ptr(), &raw mut fd, 0, &raw mut token)
        };
        if status != 0 {
            return Err(WaitError::Register(status));
        }
        // A new descriptor is non-negative (POSIX), so the field invariants hold.
        let wait = Self {
            token,
            fd,
            _name: name,
        };
        // notify(3) cannot create the descriptor close-on-exec, so a concurrent fork can still inherit it.
        // SAFETY: `wait.fd` is open and owned by `wait`'s registration (`WaitToken` invariants);
        // `F_SETFD` only changes its descriptor flags.
        if unsafe { libc::fcntl(wait.fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            // Dropping the registration cancels it, so no child keeps consuming its tokens.
            return Err(WaitError::CloseOnExec(io::Error::last_os_error()));
        }
        Ok(wait)
    }

    /// Borrow the registration's descriptor.
    fn fd(&self) -> BorrowedFd<'_> {
        // SAFETY: by the `WaitToken` invariants `self.fd` is not -1 and stays open until
        // `self` drops, which the returned borrow of `self` excludes.
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl Drop for WaitToken {
    fn drop(&mut self) {
        // SAFETY: `self.token` is live and cancelled only here. notify(3) closes `self.fd`
        // once its last token is cancelled, so this drop must not close it too; `_name`
        // drops after this call.
        unsafe { notify_cancel(self.token) };
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: no other code cancels `self.token` (field invariant), and `_name` drops
        // after this call; an invalid token only yields an error status.
        unsafe { notify_cancel(self.token) };
    }
}

#[cfg(test)]
mod tests;
