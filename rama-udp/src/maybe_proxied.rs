use std::{
    io::IoSliceMut,
    task::{Context, Poll},
};

use rama_net::client::MaybeProxied;

use crate::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    SendDatagram,
};

impl<A: DatagramSocket, B: DatagramSocket> DatagramSocket for MaybeProxied<A, B> {
    type Sender = MaybeProxied<A::Sender, B::Sender>;

    fn create_sender(&self) -> Self::Sender {
        match self {
            Self::Direct { conn } => MaybeProxied::Direct {
                conn: conn.create_sender(),
            },
            Self::Proxied { conn } => MaybeProxied::Proxied {
                conn: conn.create_sender(),
            },
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        match self {
            Self::Direct { conn } => conn.poll_recv(cx, buffers, metadata),
            Self::Proxied { conn } => conn.poll_recv(cx, buffers, metadata),
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        match self {
            Self::Direct { conn } => conn.capabilities(),
            Self::Proxied { conn } => conn.capabilities(),
        }
    }
}

impl<A: DatagramSender, B: DatagramSender> DatagramSender for MaybeProxied<A, B> {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        match self {
            Self::Direct { conn } => conn.poll_send(cx, datagram),
            Self::Proxied { conn } => conn.poll_send(cx, datagram),
        }
    }

    fn poll_send_batch(
        &mut self,
        cx: &mut Context<'_>,
        datagrams: &[SendDatagram<'_>],
    ) -> Poll<Result<usize, DatagramError>> {
        match self {
            Self::Direct { conn } => conn.poll_send_batch(cx, datagrams),
            Self::Proxied { conn } => conn.poll_send_batch(cx, datagrams),
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        match self {
            Self::Direct { conn } => conn.capabilities(),
            Self::Proxied { conn } => conn.capabilities(),
        }
    }
}
