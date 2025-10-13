use super::{Action, Attempt, Policy};
use crate::Request;
use std::fmt::Debug;

/// A redirection [`Policy`] that combines the results of two `Policy`s.
///
/// See [`PolicyExt::and`][super::PolicyExt::and] for more details.
#[derive(Clone)]
pub struct And<A, B> {
    a: A,
    b: B,
}

impl<A, B> And<A, B> {
    pub(crate) fn new<Bd, E>(a: A, b: B) -> Self
    where
        A: Policy<Bd, E>,
        B: Policy<Bd, E>,
    {
        Self { a, b }
    }
}

impl<A, B> Debug for And<A, B>
where
    A: Debug,
    B: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("And")
            .field("a", &self.a)
            .field("b", &self.b)
            .finish()
    }
}

impl<A, B> Default for And<A, B>
where
    A: Default,
    B: Default,
{
    fn default() -> Self {
        Self {
            a: Default::default(),
            b: Default::default(),
        }
    }
}

impl<Bd, E, A, B> Policy<Bd, E> for And<A, B>
where
    A: Policy<Bd, E>,
    B: Policy<Bd, E>,
{
    fn redirect(&mut self, attempt: &Attempt<'_>) -> Result<Action, E> {
        match self.a.redirect(attempt) {
            Ok(Action::Follow) => self.b.redirect(attempt),
            a => a,
        }
    }

    fn on_request(&mut self, request: &mut Request<Bd>) {
        self.a.on_request(request);
        self.b.on_request(request);
    }

    fn clone_body(&mut self, body: &Bd) -> Option<Bd> {
        self.a.clone_body(body).or_else(|| self.b.clone_body(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Uri;

    struct Taint<P> {
        policy: P,
        used: bool,
    }

    impl<P> Taint<P> {
        fn new(policy: P) -> Self {
            Self {
                policy,
                used: false,
            }
        }
    }

    impl<B, E, P> Policy<B, E> for Taint<P>
    where
        P: Policy<B, E>,
    {
        fn redirect(&mut self, attempt: &Attempt<'_>) -> Result<Action, E> {
            self.used = true;
            self.policy.redirect(attempt)
        }
    }

    #[test]
    fn redirect() {
        let attempt = Attempt {
            status: Default::default(),
            location: &Uri::from_static("*"),
            previous: &Uri::from_static("*"),
        };

        let a = Taint::new(Action::Follow);
        let b = Taint::new(Action::Follow);
        let mut policy = And::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_follow()
        );
        assert!(policy.a.used);
        assert!(policy.b.used);

        let a = Taint::new(Action::Stop);
        let b = Taint::new(Action::Follow);
        let mut policy = And::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_stop()
        );
        assert!(policy.a.used);
        assert!(!policy.b.used); // short-circuiting

        let a = Taint::new(Action::Follow);
        let b = Taint::new(Action::Stop);
        let mut policy = And::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_stop()
        );
        assert!(policy.a.used);
        assert!(policy.b.used);

        let a = Taint::new(Action::Stop);
        let b = Taint::new(Action::Stop);
        let mut policy = And::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_stop()
        );
        assert!(policy.a.used);
        assert!(!policy.b.used);
    }
}
