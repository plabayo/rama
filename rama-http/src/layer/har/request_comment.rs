#[derive(Clone)]
pub struct RequestComment {
    pub comment: String,
}

impl RequestComment {
    pub fn new(comment: &str) -> Self {
        Self {
            comment: comment.to_owned(),
        }
    }
}
