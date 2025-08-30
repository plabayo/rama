#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestComment(pub String);

impl RequestComment {
    #[must_use]
    pub fn new(comment: &str) -> Self {
        Self(comment.to_owned())
    }
}
