use crate::service::{context::Extensions, Context};

use super::Matcher;

#[derive(Debug, Default, Hash)]
#[non_exhaustive]
/// Matches any request.
pub struct Any;

impl Any {
    /// Create a new instance of `Any`.
    pub fn new() -> Self {
        Self
    }
}

impl<State, Request> Matcher<State, Request> for Any {
    fn matches(&self, _: Option<&mut Extensions>, _: &Context<State>, _: &Request) -> bool {
        true
    }
}
