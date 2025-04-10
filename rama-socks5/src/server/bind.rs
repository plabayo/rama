use rama_core::Context;
use rama_net::{address::Authority, stream::Stream};

use crate::proto::{ReplyKind, server::Reply};

use super::Error;

/// Types which can be used as socks5 bind drivers on the server side.
pub trait Socks5Binder: Socks5BinderSeal {}

impl<C> Socks5Binder for C where C: Socks5BinderSeal {}

pub trait Socks5BinderSeal: Send + Sync + 'static {
    fn accept_bind<S, State>(
        &self,
        ctx: Context<State>,
        stream: S,
        destination: Authority,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_
    where
        S: Stream + Unpin,
        State: Clone + Send + Sync + 'static;
}

impl Socks5BinderSeal for () {
    async fn accept_bind<S, State>(
        &self,
        _ctx: Context<State>,
        mut stream: S,
        destination: Authority,
    ) -> Result<(), Error>
    where
        S: Stream + Unpin,
        State: Clone + Send + Sync + 'static,
    {
        tracing::debug!(
            %destination,
            "socks5 server: abort: command not supported: Bind",
        );

        Reply::error_reply(ReplyKind::CommandNotSupported)
            .write_to(&mut stream)
            .await
            .map_err(|err| {
                Error::io(err).with_context("write server reply: command not supported (bind)")
            })?;
        Err(Error::aborted("command not supported: Bind"))
    }
}
