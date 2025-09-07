use super::{Action, Attempt, Policy, eq_origin};
use crate::{
    Request,
    header::{self, HeaderName},
};
use rama_core::Context;

/// A redirection [`Policy`] that removes credentials from requests in redirections.
#[derive(Debug)]
pub struct FilterCredentials {
    block_cross_origin: bool,
    block_any: bool,
    remove_blocklisted: bool,
    remove_all: bool,
    blocked: bool,
}

const BLOCKLIST: &[HeaderName] = &[
    header::AUTHORIZATION,
    header::COOKIE,
    header::PROXY_AUTHORIZATION,
];

impl FilterCredentials {
    /// Create a new [`FilterCredentials`] that removes blocklisted request headers in cross-origin
    /// redirections.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            block_cross_origin: true,
            block_any: false,
            remove_blocklisted: true,
            remove_all: false,
            blocked: false,
        }
    }

    /// Configure `self` to mark cross-origin redirections as "blocked".
    #[must_use]
    pub fn block_cross_origin(mut self, enable: bool) -> Self {
        self.block_cross_origin = enable;
        self
    }

    /// Configure `self` to mark cross-origin redirections as "blocked".
    pub fn set_block_cross_origin(&mut self, enable: bool) -> &mut Self {
        self.block_cross_origin = enable;
        self
    }

    /// Configure `self` to mark every redirection as "blocked".
    #[must_use]
    pub fn block_any(mut self, enable: bool) -> Self {
        self.block_any = enable;
        self
    }

    /// Configure `self` to mark every redirection as "blocked".
    pub fn set_block_any(&mut self, enable: bool) -> &mut Self {
        self.block_any = enable;
        self
    }

    /// Configure `self` to remove blocklisted headers in "blocked" redirections.
    ///
    /// The blocklist includes the following headers:
    ///
    /// - `Authorization`
    /// - `Cookie`
    /// - `Proxy-Authorization`
    #[must_use]
    pub fn remove_blocklisted(mut self, enable: bool) -> Self {
        self.remove_blocklisted = enable;
        self
    }

    /// Configure `self` to remove blocklisted headers in "blocked" redirections.
    ///
    /// The blocklist includes the following headers:
    ///
    /// - `Authorization`
    /// - `Cookie`
    /// - `Proxy-Authorization`
    pub fn set_remove_blocklisted(&mut self, enable: bool) -> &mut Self {
        self.remove_blocklisted = enable;
        self
    }

    /// Configure `self` to remove all headers in "blocked" redirections.
    #[must_use]
    pub fn remove_all(mut self, enable: bool) -> Self {
        self.remove_all = enable;
        self
    }

    /// Configure `self` to remove all headers in "blocked" redirections.
    pub fn set_remove_all(&mut self, enable: bool) -> &mut Self {
        self.remove_all = enable;
        self
    }
}

impl Default for FilterCredentials {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for FilterCredentials {
    fn clone(&self) -> Self {
        Self {
            block_cross_origin: self.block_cross_origin,
            block_any: self.block_any,
            remove_blocklisted: self.remove_blocklisted,
            remove_all: self.remove_all,
            blocked: false,
        }
    }
}

impl<B, E> Policy<B, E> for FilterCredentials {
    fn redirect(&mut self, _: &Context, attempt: &Attempt<'_>) -> Result<Action, E> {
        self.blocked = self.block_any
            || (self.block_cross_origin && !eq_origin(attempt.previous(), attempt.location()));
        Ok(Action::Follow)
    }

    fn on_request(&mut self, _: &mut Context, request: &mut Request<B>) {
        if self.blocked {
            let headers = request.headers_mut();
            if self.remove_all {
                headers.clear();
            } else if self.remove_blocklisted {
                for key in BLOCKLIST {
                    headers.remove(key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Uri;

    #[test]
    fn works() {
        let mut policy = FilterCredentials::default();

        let initial = Uri::from_static("http://example.com/old");
        let same_origin = Uri::from_static("http://example.com/new");
        let cross_origin = Uri::from_static("https://example.com/new");

        let mut ctx = Context::default();

        let mut request = Request::builder()
            .uri(initial)
            .header(header::COOKIE, "42")
            .body(())
            .unwrap();
        Policy::<(), ()>::on_request(&mut policy, &mut ctx, &mut request);
        assert!(request.headers().contains_key(header::COOKIE));

        let attempt = Attempt {
            status: Default::default(),
            location: &same_origin,
            previous: request.uri(),
        };
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &ctx, &attempt)
                .unwrap()
                .is_follow()
        );

        let mut request = Request::builder()
            .uri(same_origin)
            .header(header::COOKIE, "42")
            .body(())
            .unwrap();
        Policy::<(), ()>::on_request(&mut policy, &mut ctx, &mut request);
        assert!(request.headers().contains_key(header::COOKIE));

        let attempt = Attempt {
            status: Default::default(),
            location: &cross_origin,
            previous: request.uri(),
        };
        assert!(
            Policy::<(), ()>::redirect(&mut policy, &ctx, &attempt)
                .unwrap()
                .is_follow()
        );

        let mut request = Request::builder()
            .uri(cross_origin)
            .header(header::COOKIE, "42")
            .body(())
            .unwrap();
        Policy::<(), ()>::on_request(&mut policy, &mut ctx, &mut request);
        assert!(!request.headers().contains_key(header::COOKIE));
    }
}
