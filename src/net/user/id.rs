#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// The identifier of a user.
///
/// Usually created by the layer which authenticates the user.
pub enum UserId {
    /// User identified by a username.
    ///
    /// E.g. the username of a Basic Auth user.
    Username(String),
    /// User identified by a token.
    ///
    /// E.g. the token of a Bearer Auth user.
    Token(Vec<u8>),
}

impl PartialEq<str> for UserId {
    fn eq(&self, other: &str) -> bool {
        match self {
            UserId::Username(username) => username == other,
            UserId::Token(token) => {
                let other = other.as_bytes();
                token == other
            }
        }
    }
}

impl PartialEq<UserId> for str {
    fn eq(&self, other: &UserId) -> bool {
        other == self
    }
}

impl PartialEq<[u8]> for UserId {
    fn eq(&self, other: &[u8]) -> bool {
        match self {
            UserId::Username(username) => {
                let username_bytes = username.as_bytes();
                username_bytes == other
            }
            UserId::Token(token) => token == other,
        }
    }
}

impl PartialEq<UserId> for [u8] {
    fn eq(&self, other: &UserId) -> bool {
        other == self
    }
}

impl PartialEq<String> for UserId {
    fn eq(&self, other: &String) -> bool {
        match self {
            UserId::Username(username) => username == other,
            UserId::Token(token) => {
                let other = other.as_bytes();
                token == other
            }
        }
    }
}

impl PartialEq<UserId> for String {
    fn eq(&self, other: &UserId) -> bool {
        other == self
    }
}

impl PartialEq<Vec<u8>> for UserId {
    fn eq(&self, other: &Vec<u8>) -> bool {
        match self {
            UserId::Username(username) => {
                let username_bytes = username.as_bytes();
                username_bytes == other
            }
            UserId::Token(token) => token == other,
        }
    }
}

impl PartialEq<UserId> for Vec<u8> {
    fn eq(&self, other: &UserId) -> bool {
        other == self
    }
}
