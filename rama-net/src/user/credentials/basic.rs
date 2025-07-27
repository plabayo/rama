use std::{borrow::Cow, fmt, str::FromStr};

use rama_core::error::OpaqueError;

use crate::user::authority::StaticAuthorizer;

#[derive(Clone)]
/// Basic credentials.
pub struct Basic {
    username: Cow<'static, str>,
    password: Option<Cow<'static, str>>,
}

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
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: Cow::Owned(username.into()),
            password: {
                let password = password.into();
                (!password.is_empty()).then_some(password.into())
            },
        }
    }

    /// Creates a new [`Basic`] credential.
    #[must_use]
    pub fn new_static(username: &'static str, password: &'static str) -> Self {
        Self {
            username: username.into(),
            password: (!password.is_empty()).then_some(password.into()),
        }
    }

    /// Creates a new [`Basic`] credential.
    pub fn new_insecure(username: impl Into<String>) -> Self {
        Self {
            username: Cow::Owned(username.into()),
            password: None,
        }
    }

    /// Creates a new [`Basic`] credential.
    #[must_use]
    pub fn new_static_insecure(username: &'static str) -> Self {
        Self {
            username: username.into(),
            password: None,
        }
    }

    /// View the decoded username.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_ref()
    }

    /// View the decoded password.
    #[must_use]
    pub fn password(&self) -> &str {
        self.password.as_deref().unwrap_or_default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set or overwrite the password with the given heap allocated password.
        pub fn password(mut self, password: impl Into<String>) -> Self {
            self.password = Some(Cow::Owned(password.into()));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set or overwrite the password with the given static password.
        pub fn static_password(mut self, password: &'static str) -> Self {
            self.password = Some(password.into());
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

impl PartialEq<Self> for Basic {
    fn eq(&self, other: &Self) -> bool {
        self.username() == other.username() && self.password() == other.password()
    }
}

impl Eq for Basic {}

impl TryFrom<&str> for Basic {
    type Error = OpaqueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.find(':') {
            Some(0) => Err(OpaqueError::from_display(
                "missing username in basic credential",
            )),
            Some(n) => Ok(Self {
                username: Cow::Owned(value[..n].to_owned()),
                password: Some(Cow::Owned(value[n + 1..].to_owned())),
            }),
            None => Ok(Self {
                username: Cow::Owned(value.to_owned()),
                password: None,
            }),
        }
    }
}

impl FromStr for Basic {
    type Err = OpaqueError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl fmt::Display for Basic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.username(), self.password())
    }
}
