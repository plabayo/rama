use super::*;

#[derive(Debug)]
pub(crate) struct MockUdpAssociator {
    reply: MockReply,
}

#[derive(Debug)]
enum MockReply {
    Success { local_addr: Authority },
    Error(ReplyKind),
}

impl MockUdpAssociator {
    pub(crate) fn new(local_addr: Authority) -> Self {
        Self {
            reply: MockReply::Success { local_addr },
        }
    }
    pub(crate) fn new_err(reply: ReplyKind) -> Self {
        Self {
            reply: MockReply::Error(reply),
        }
    }
}

impl<S, State> Socks5UdpAssociatorSeal<S, State> for MockUdpAssociator
where
    S: Stream + Unpin,
    State: Clone + Send + Sync + 'static,
{
    async fn accept_udp_associate(
        &self,
        _ctx: Context<State>,
        mut stream: S,
        _destination: Authority,
    ) -> Result<(), Error> {
        match &self.reply {
            MockReply::Success { local_addr } => {
                Reply::new(local_addr.clone())
                    .write_to(&mut stream)
                    .await
                    .map_err(Error::io)?;
                Ok(())
            }
            MockReply::Error(reply_kind) => {
                Reply::error_reply(*reply_kind)
                    .write_to(&mut stream)
                    .await
                    .map_err(Error::io)?;
                Err(Error::aborted("mock abort").with_context(*reply_kind))
            }
        }
    }
}
