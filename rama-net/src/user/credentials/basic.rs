use std::{fmt, str::FromStr};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_utils::str::NonEmptyStr;

use crate::user::authority::StaticAuthorizer;

#[derive(Clone, PartialEq, Eq)]
/// Basic credentials.
pub struct Basic {
    username: NonEmptyStr,
    password: Option<NonEmptyStr>,
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

impl TryFrom<&str> for Basic {
    type Error = BoxError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.find(':') {
            Some(0) => Err(BoxError::from("missing username in basic credential")),
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
