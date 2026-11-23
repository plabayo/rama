use rama_core::telemetry::tracing::warn;
use std::ffi::{CStr, c_char, c_int};

// Apple's securityd posts this name for changes to trust settings, the default
// keychain/search list, and X.509 certificate items. Security.framework uses
// the same notification to invalidate its trust caches. The name comes from
// Apple's Security sources (SecItemInternal.h); notify(3) is a public API.
const CERTIFICATE_TRUST: &CStr = c"com.apple.security.certificatetrust";

unsafe extern "C" {
    fn notify_register_check(name: *const c_char, token: *mut c_int) -> u32;
    fn notify_check(token: c_int, changed: *mut c_int) -> u32;
    fn notify_cancel(token: c_int) -> u32;
}

pub(crate) struct StoreNotifications {
    token: Option<Token>,
}

impl StoreNotifications {
    pub(crate) fn new() -> Self {
        Self {
            token: Token::register(CERTIFICATE_TRUST)
                .inspect_err(|status| warn!(status, "could not watch macOS certificate trust"))
                .ok(),
        }
    }

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

struct Token(c_int);

impl Token {
    fn register(name: &CStr) -> Result<Self, u32> {
        let mut token = -1;
        // SAFETY: name is NUL-terminated and the output is writable.
        let status = unsafe { notify_register_check(name.as_ptr(), &raw mut token) };
        if status != 0 {
            return Err(status);
        }
        let token = Self(token);
        // notify_check always reports a change on the first call for a token.
        token.check()?;
        Ok(token)
    }

    fn check(&self) -> Result<bool, u32> {
        let mut changed = 0;
        // SAFETY: this token owns the registration and the output is writable.
        let status = unsafe { notify_check(self.0, &raw mut changed) };
        if status == 0 {
            Ok(changed != 0)
        } else {
            Err(status)
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: this token owns one successful registration.
        unsafe { notify_cancel(self.0) };
    }
}

#[cfg(test)]
mod tests;
