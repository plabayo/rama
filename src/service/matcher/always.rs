use crate::service::{context::Extensions, Context};

use super::Matcher;

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
/// Matches any request.
pub struct Always;

impl Always {
    /// Create a new instance of `Always`.
    pub fn new() -> Self {
        Self
    }
}

impl<State, Request> Matcher<State, Request> for Always {
    fn matches(&self, _: Option<&mut Extensions>, _: &Context<State>, _: &Request) -> bool {
        true
    }
}
