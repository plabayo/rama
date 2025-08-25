#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestComment(pub String);

impl RequestComment {
    pub fn new(comment: &str) -> Self {
        Self(comment.to_owned())
    }
}
