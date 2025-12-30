use std::{fmt, marker::PhantomData};

use rama_core::{
    Layer, Service,
    extensions::{Extensions, ExtensionsMut},
    telemetry::tracing,
    username::{UsernameLabelParser, parse_username},
};

use crate::user::UserId;

/// Layer which can be used to add parser capabilities to any service
/// stack which injects a [`UserId`] into the input.
///
/// For most use-cases you do not need this layer at all.
/// Http and socks5 support by rama already can handle parsers out of the box:
///
/// - for the http proxy you can do it directly within the proxy acceptor layer;
/// - for the socks5 proxy you would do the parsing as part of your authorizer implementation.
///
/// If this is not the case you will have to add username label capabilities
/// to your authorizer. Sadly not all authorizer traits allow
/// adding extensions. This is probably a shortcoming which should be fixed at some point.
/// Feel free to feature request this.
#[derive(Default)]
pub struct UsernameLabelParserLayer<P> {
    _parser: PhantomData<fn() -> P>,
}

impl<P> UsernameLabelParserLayer<P> {
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            _parser: PhantomData,
        }
    }
}

impl<P> fmt::Debug for UsernameLabelParserLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsernameLabelParserLayer")
            .field("parser", &std::any::type_name::<P>())
            .finish()
    }
}

impl<P> Clone for UsernameLabelParserLayer<P> {
    fn clone(&self) -> Self {
        Self {
            _parser: PhantomData,
        }
    }
}

impl<S, P> Layer<S> for UsernameLabelParserLayer<P> {
    type Service = UsernameLabelParserService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            _parser: PhantomData,
        }
    }
}

/// [`Service`] which can be used to add parser capabilities to any service
/// stack which injects a [`UserId`] into the input.
///
/// See [`UsernameLabelParserLayer`] for more info.
pub struct UsernameLabelParserService<S, P> {
    inner: S,
    _parser: PhantomData<fn() -> P>,
}

impl<S: fmt::Debug, P> fmt::Debug for UsernameLabelParserService<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsernameLabelParserService")
            .field("inner", &self.inner)
            .field("parser", &std::any::type_name::<P>())
            .finish()
    }
}

impl<S: Clone, P> Clone for UsernameLabelParserService<S, P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _parser: PhantomData,
        }
    }
}

impl<S, P, Input> Service<Input> for UsernameLabelParserService<S, P>
where
    S: Service<Input>,
    P: UsernameLabelParser,
    Input: ExtensionsMut,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        mut input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let extensions = input.extensions_mut();
        match extensions.get() {
            Some(UserId::Username(username)) => {
                let mut label_extensions = Extensions::new();
                match parse_username(&mut label_extensions, P::default(), username) {
                    Ok(new_username) => {
                        tracing::debug!(
                            "username label parser: success: overwrite id username '{username}' with '{new_username}'"
                        );
                        extensions.insert(UserId::Username(new_username));
                        extensions.extend(label_extensions);
                    }
                    Err(err) => {
                        tracing::debug!(
                            "failed to parse username labels, keep existing username: '{username}'; err = {err}"
                        );
                    }
                }
            }
            Some(UserId::Token(_)) => {
                tracing::debug!("no parsing to do, incompatible user id in input: token");
            }
            None | Some(UserId::Anonymous) => {
                tracing::debug!("no parsing to do, incompatible user id in input: none/anonymous");
            }
        }

        self.inner.serve(input)
    }
}
