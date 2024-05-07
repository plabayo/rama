use crate::service::Context;

use super::{eq_origin, Action, Attempt, Policy};
use std::fmt;

/// A redirection [`Policy`] that stops cross-origin redirections.
#[derive(Default, Clone)]
pub struct SameOrigin {
    _priv: (),
}

impl SameOrigin {
    /// Create a new [`SameOrigin`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for SameOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SameOrigin").finish()
    }
}

impl<S, B, E> Policy<S, B, E> for SameOrigin {
    fn redirect(&mut self, _: &Context<S>, attempt: &Attempt<'_>) -> Result<Action, E> {
        if eq_origin(attempt.previous(), attempt.location()) {
            Ok(Action::Follow)
        } else {
            Ok(Action::Stop)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, Uri};

    #[test]
    fn works() {
        let mut policy = SameOrigin::default();

        let initial = Uri::from_static("http://example.com/old");
        let same_origin = Uri::from_static("http://example.com/new");
        let cross_origin = Uri::from_static("https://example.com/new");

        let mut ctx = Context::default();

        let mut request = Request::builder().uri(initial).body(()).unwrap();
        Policy::<(), (), ()>::on_request(&mut policy, &mut ctx, &mut request);

        let attempt = Attempt {
            status: Default::default(),
            location: &same_origin,
            previous: request.uri(),
        };
        assert!(Policy::<(), (), ()>::redirect(&mut policy, &ctx, &attempt)
            .unwrap()
            .is_follow());

        let mut request = Request::builder().uri(same_origin).body(()).unwrap();
        Policy::<(), (), ()>::on_request(&mut policy, &mut ctx, &mut request);

        let attempt = Attempt {
            status: Default::default(),
            location: &cross_origin,
            previous: request.uri(),
        };
        assert!(Policy::<(), (), ()>::redirect(&mut policy, &ctx, &attempt)
            .unwrap()
            .is_stop());
    }
}
