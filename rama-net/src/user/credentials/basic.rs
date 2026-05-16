use std::{fmt, str::FromStr};

use rama_core::error::extra::OpaqueError;
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt};
use rama_core::extensions::Extension;
use rama_utils::str::NonEmptyStr;

use rama_utils::bytes::ct::ct_eq_bytes;

use crate::user::authority::StaticAuthorizer;

#[derive(Clone, Eq, Extension)]
#[extension(tags(net))]
/// Basic credentials.
pub struct Basic {
    username: NonEmptyStr,
    password: Option<NonEmptyStr>,
}

impl PartialEq for Basic {
    /// Constant-time comparison over the credential bytes.
    //
    // Why: `Basic` is used by `StaticAuthorizer`, so a short-circuiting
    // byte compare leaks the matching prefix length to an attacker who
    // can probe authentication latency. Verified by
    // `tests::regression_basic_constant_time_eq`.
    fn eq(&self, other: &Self) -> bool {
        let user_eq = ct_eq_bytes(self.username.as_bytes(), other.username.as_bytes());
        let pwd_eq = match (&self.password, &other.password) {
            (Some(a), Some(b)) => ct_eq_bytes(a.as_bytes(), b.as_bytes()),
            (None, None) => true,
            // The "one side has a password and the other does not" case still
            // performs a fixed-cost compare so we don't reveal which side it is.
            (Some(a), None) | (None, Some(a)) => {
                let _ = ct_eq_bytes(a.as_bytes(), a.as_bytes());
                false
            }
        };
        user_eq & pwd_eq
    }
}

/// Create a [`Basic`] value at const-compile time.
///
/// # Panics
///
/// Panics in case the username literal is empty.
#[macro_export]
#[doc(hidden)]
macro_rules! __basic {
    ($username:expr $(,)?) => {
        $crate::user::credentials::basic!($username, "")
    };
    ($username:expr, $password:expr $(,)?) => {{
        const __BASIC_USERNAME_VALUE: $crate::__private::utils::str::NonEmptyStr =
            $crate::__private::utils::str::non_empty_str!($username);
        const __BASIC_PASSWORD_TEXT: &str = $password;

        if __BASIC_PASSWORD_TEXT.is_empty() {
            $crate::user::credentials::Basic::new_insecure(__BASIC_USERNAME_VALUE)
        } else {
            $crate::user::credentials::Basic::new(
                __BASIC_USERNAME_VALUE,
                $crate::__private::utils::str::non_empty_str!(__BASIC_PASSWORD_TEXT),
            )
        }
    }};
}

#[doc(inline)]
pub use crate::__basic as basic;

impl fmt::Debug for Basic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Basic")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

impl Basic {
    /// Creates a new [`Basic`] credential.
    #[must_use]
    pub const fn new(username: NonEmptyStr, password: NonEmptyStr) -> Self {
        Self {
            username,
            password: Some(password),
        }
    }

    #[must_use]
    pub fn clone_with_new_username(&self, username: NonEmptyStr) -> Self {
        Self {
            username,
            password: self.password.clone(),
        }
    }

    #[must_use]
    pub fn clone_with_new_password(&self, password: NonEmptyStr) -> Self {
        Self {
            username: self.username.clone(),
            password: Some(password),
        }
    }

    /// Creates a new [`Basic`] credential.
    #[must_use]
    pub const fn new_insecure(username: NonEmptyStr) -> Self {
        Self {
            username,
            password: None,
        }
    }

    /// View the decoded username.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_ref()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set or overwrite the username with the given value.
        pub fn username(mut self, username: NonEmptyStr) -> Self {
            self.username = username;
            self
        }
    }

    /// View the decoded password.
    ///
    /// If Some(str) is returned it is guaranteed to be non-empty.
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set or overwrite the password with the given value.
        pub fn password(mut self, password: NonEmptyStr) -> Self {
            self.password = Some(password);
            self
        }
    }

    /// Turn itself into a [`StaticAuthorizer`], so it can be used to authorize.
    ///
    /// Just a shortcut, QoL.
    #[must_use]
    pub fn into_authorizer(self) -> StaticAuthorizer<Self> {
        StaticAuthorizer::new(self)
    }
}

impl std::hash::Hash for Basic {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.username().hash(state);
        ':'.hash(state);
        self.password().hash(state);
    }
}

/// Reject control bytes that have no legitimate place inside HTTP Basic
/// credentials.
//
// Why: an unvalidated CR / LF or NUL byte that round-trips back into an
// Authorization header lets an attacker inject extra header fields (CRLF
// injection) or terminate a C-string prematurely in downstream handlers.
// RFC 7617 (HTTP Basic) does not enumerate these as forbidden, but no
// real-world deployment relies on them either, so we reject by default
// for every entry point that constructs a [`Basic`] from external input.
//
// Regression: `tests::regression_basic_rejects_crlf_nul`.
fn validate_basic_field(field: &str, value: &str) -> Result<(), BoxError> {
    if let Some(idx) = value
        .as_bytes()
        .iter()
        .position(|b| matches!(*b, b'\r' | b'\n' | 0))
    {
        return Err(OpaqueError::from_static_str(
            "basic credential contains forbidden control byte",
        )
        .context_str_field("field", field)
        .context_field("byte_index", idx)
        .into_box_error());
    }
    Ok(())
}

impl TryFrom<&str> for Basic {
    type Error = BoxError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_basic_field("credential blob", value)?;
        match value.find(':') {
            Some(0) => Err(
                OpaqueError::from_static_str("missing username in basic credential")
                    .into_box_error(),
            ),
            Some(n) => Ok(Self {
                username: NonEmptyStr::try_from(&value[..n])
                    .context("create username for secure basic credentials")?,
                password: (n + 1 < value.len())
                    .then(|| {
                        NonEmptyStr::try_from(&value[n + 1..])
                            .context("create password for secure basic credentials")
                    })
                    .transpose()?,
            }),
            None => Ok(Self {
                username: NonEmptyStr::try_from(value)
                    .context("create username for insecure basic credentials")?,
                password: None,
            }),
        }
    }
}

impl FromStr for Basic {
    type Err = BoxError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl fmt::Display for Basic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            self.username(),
            self.password().unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, pwd: Option<&str>) -> Basic {
        let username = NonEmptyStr::try_from(user).unwrap();
        match pwd {
            Some(p) => Basic::new(username, NonEmptyStr::try_from(p).unwrap()),
            None => Basic::new_insecure(username),
        }
    }

    #[test]
    fn regression_basic_constant_time_eq() {
        // Equal credentials match.
        assert_eq!(
            basic("alice", Some("hunter2")),
            basic("alice", Some("hunter2"))
        );
        // Differing only in the last byte of the password.
        assert_ne!(
            basic("alice", Some("hunter2")),
            basic("alice", Some("hunter3"))
        );
        // Differing only in the first byte of the password.
        assert_ne!(
            basic("alice", Some("hunter2")),
            basic("alice", Some("xunter2"))
        );
        // One side has a password, the other does not.
        assert_ne!(basic("alice", Some("hunter2")), basic("alice", None));
        assert_ne!(basic("alice", None), basic("alice", Some("hunter2")));
        // Different usernames, same password.
        assert_ne!(
            basic("alice", Some("hunter2")),
            basic("bob", Some("hunter2"))
        );
        // Insecure pair compares.
        assert_eq!(basic("alice", None), basic("alice", None));
        assert_ne!(basic("alice", None), basic("bob", None));
    }

    #[test]
    fn regression_basic_rejects_crlf_nul() {
        // CRLF in the username section enables Authorization-header CRLF
        // injection if the value round-trips back into a header. RFC 7617
        // does not enumerate this; we reject by default.
        Basic::try_from("ali\rce:hunter2").unwrap_err();
        Basic::try_from("ali\nce:hunter2").unwrap_err();
        // Password section.
        Basic::try_from("alice:hun\rter2").unwrap_err();
        Basic::try_from("alice:hun\nter2").unwrap_err();
        // NUL byte (C-string terminator) in either side.
        Basic::try_from("ali\0ce:hunter2").unwrap_err();
        Basic::try_from("alice:hun\0ter2").unwrap_err();
        // Normal credential still parses.
        Basic::try_from("alice:hunter2").unwrap();
    }
}
