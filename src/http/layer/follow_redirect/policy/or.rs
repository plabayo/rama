use super::{Action, Attempt, Policy};
use crate::{http::Request, service::Context};

/// A redirection [`Policy`] that combines the results of two `Policy`s.
///
/// See [`PolicyExt::or`][super::PolicyExt::or] for more details.
#[derive(Clone)]
pub struct Or<A, B> {
    a: A,
    b: B,
}

impl<A, B> Or<A, B> {
    pub(crate) fn new<S, Bd, E>(a: A, b: B) -> Self
    where
        A: Policy<S, Bd, E>,
        B: Policy<S, Bd, E>,
    {
        Or { a, b }
    }
}

impl<A, B> std::fmt::Debug for Or<A, B>
where
    A: std::fmt::Debug,
    B: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Or")
            .field("a", &self.a)
            .field("b", &self.b)
            .finish()
    }
}

impl<A, B> Default for Or<A, B>
where
    A: Default,
    B: Default,
{
    fn default() -> Self {
        Or {
            a: Default::default(),
            b: Default::default(),
        }
    }
}

impl<S, Bd, E, A, B> Policy<S, Bd, E> for Or<A, B>
where
    A: Policy<S, Bd, E>,
    B: Policy<S, Bd, E>,
{
    fn redirect(&mut self, ctx: &Context<S>, attempt: &Attempt<'_>) -> Result<Action, E> {
        match self.a.redirect(ctx, attempt) {
            Ok(Action::Stop) | Err(_) => self.b.redirect(ctx, attempt),
            a => a,
        }
    }

    fn on_request(&mut self, ctx: &mut Context<S>, request: &mut Request<Bd>) {
        self.a.on_request(ctx, request);
        self.b.on_request(ctx, request);
    }

    fn clone_body(&mut self, ctx: &Context<S>, body: &Bd) -> Option<Bd> {
        self.a
            .clone_body(ctx, body)
            .or_else(|| self.b.clone_body(ctx, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{http::Uri, service::Context};

    struct Taint<P> {
        policy: P,
        used: bool,
    }

    impl<P> Taint<P> {
        fn new(policy: P) -> Self {
            Taint {
                policy,
                used: false,
            }
        }
    }

    impl<S, B, E, P> Policy<S, B, E> for Taint<P>
    where
        P: Policy<S, B, E>,
    {
        fn redirect(&mut self, ctx: &Context<S>, attempt: &Attempt<'_>) -> Result<Action, E> {
            self.used = true;
            self.policy.redirect(ctx, attempt)
        }
    }

    #[test]
    fn redirect() {
        let attempt = Attempt {
            status: Default::default(),
            location: &Uri::from_static("*"),
            previous: &Uri::from_static("*"),
        };

        let ctx = Context::default();

        let a = Taint::new(Action::Follow);
        let b = Taint::new(Action::Follow);
        let mut policy = Or::new::<(), (), ()>(a, b);
        assert!(Policy::<(), (), ()>::redirect(&mut policy, &ctx, &attempt)
            .unwrap()
            .is_follow());
        assert!(policy.a.used);
        assert!(!policy.b.used); // short-circuiting

        let a = Taint::new(Action::Stop);
        let b = Taint::new(Action::Follow);
        let mut policy = Or::new::<(), (), ()>(a, b);
        assert!(Policy::<(), (), ()>::redirect(&mut policy, &ctx, &attempt)
            .unwrap()
            .is_follow());
        assert!(policy.a.used);
        assert!(policy.b.used);

        let a = Taint::new(Action::Follow);
        let b = Taint::new(Action::Stop);
        let mut policy = Or::new::<(), (), ()>(a, b);
        assert!(Policy::<(), (), ()>::redirect(&mut policy, &ctx, &attempt)
            .unwrap()
            .is_follow());
        assert!(policy.a.used);
        assert!(!policy.b.used);

        let a = Taint::new(Action::Stop);
        let b = Taint::new(Action::Stop);
        let mut policy = Or::new::<(), (), ()>(a, b);
        assert!(Policy::<(), (), ()>::redirect(&mut policy, &ctx, &attempt)
            .unwrap()
            .is_stop());
        assert!(policy.a.used);
        assert!(policy.b.used);
    }
}
