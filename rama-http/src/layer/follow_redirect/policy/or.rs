use super::{Action, Attempt, Policy};
use crate::Request;

/// A redirection [`Policy`] that combines the results of two `Policy`s.
///
/// See [`PolicyExt::or`][super::PolicyExt::or] for more details.
#[derive(Clone)]
pub struct Or<A, B> {
    a: A,
    b: B,
}

impl<A, B> Or<A, B> {
    pub(crate) fn new<Bd, E>(a: A, b: B) -> Self
    where
        A: Policy<Bd, E>,
        B: Policy<Bd, E>,
    {
        Self { a, b }
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
        Self {
            a: Default::default(),
            b: Default::default(),
        }
    }
}

impl<Bd, E, A, B> Policy<Bd, E> for Or<A, B>
where
    A: Policy<Bd, E>,
    B: Policy<Bd, E>,
{
    fn redirect(&mut self, attempt: &Attempt<'_>) -> Result<Action, E> {
        let a_result = self.a.redirect(attempt);
        let b_result = self.b.redirect(attempt);
        match a_result {
            Ok(Action::Stop) | Err(_) => b_result,
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
    use crate::{Method, Uri};

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
            method: &Method::GET,
            location: &Uri::from_static("*"),
            previous_method: &Method::GET,
            previous: &Uri::from_static("*"),
        };

        let a = Taint::new(Action::Follow);
        let b = Taint::new(Action::Follow);
        let mut policy = Or::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_follow()
        );
        assert!(policy.a.used);
        assert!(policy.b.used); // both policies are always invoked

        let a = Taint::new(Action::Stop);
        let b = Taint::new(Action::Follow);
        let mut policy = Or::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_follow()
        );
        assert!(policy.a.used);
        assert!(policy.b.used);

        let a = Taint::new(Action::Follow);
        let b = Taint::new(Action::Stop);
        let mut policy = Or::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_follow()
        );
        assert!(policy.a.used);
        assert!(policy.b.used); // both policies are always invoked

        let a = Taint::new(Action::Stop);
        let b = Taint::new(Action::Stop);
        let mut policy = Or::new::<(), ()>(a, b);
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_stop()
        );
        assert!(policy.a.used);
        assert!(policy.b.used);
    }

    #[test]
    fn stateful_policies_are_invoked() {
        use super::super::FilterCredentials;
        use crate::header;

        // Test that FilterCredentials state is properly updated even when
        // the first policy in Or returns Follow (preventing credential leakage)
        let initial = Uri::from_static("http://example.com/old");
        let cross_origin = Uri::from_static("http://attacker.com/new");

        let attempt = Attempt {
            status: Default::default(),
            method: &Method::GET,
            location: &cross_origin,
            previous_method: &Method::GET,
            previous: &initial,
        };

        // Create Or policy with Action::Follow as first policy and FilterCredentials as second
        let mut policy = Or::new::<(), ()>(Action::Follow, FilterCredentials::default());

        // Call redirect - both policies should be invoked
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &attempt)
                .unwrap()
                .is_follow()
        );

        // Create a request with credentials
        let mut request = Request::builder()
            .uri(cross_origin)
            .header(header::AUTHORIZATION, "Bearer secret")
            .header(header::COOKIE, "session=42")
            .body(())
            .unwrap();

        // Call on_request - credentials should be stripped because FilterCredentials
        // was properly invoked during redirect() and set its blocked flag
        Policy::<(), ()>::on_request(&mut policy, &mut request);

        // Verify credentials were stripped (security fix)
        assert!(!request.headers().contains_key(header::AUTHORIZATION));
        assert!(!request.headers().contains_key(header::COOKIE));
    }
}
