//! Hold all server output, so a client cannot complete its handshake.

use parking_lot::Mutex;
use rama_net::{address::SocketAddress, stream::Socket};
use rama_udp::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    SendDatagram,
};
use std::{
    io::{self, IoSliceMut},
    sync::Arc,
    task::{Context, Poll, Waker},
};

#[derive(Debug, Default)]
pub(super) struct Gate(Mutex<State>);

#[derive(Debug, Default)]
struct State {
    held: bool,
    wakers: Vec<Waker>,
}

impl Gate {
    pub(super) fn hold(&self) {
        self.0.lock().held = true;
    }

    pub(super) fn release(&self) {
        let waiters = {
            let mut state = self.0.lock();
            state.held = false;
            std::mem::take(&mut state.wakers)
        };
        for waker in waiters {
            waker.wake();
        }
    }

    fn pending(&self, cx: &Context<'_>) -> bool {
        let mut state = self.0.lock();
        if !state.held {
            return false;
        }
        if !state.wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
            state.wakers.push(cx.waker().clone());
        }
        true
    }
}

#[derive(Debug)]
pub(super) struct GatedSocket<S> {
    pub(super) inner: S,
    pub(super) gate: Arc<Gate>,
}

impl<S: DatagramSocket> Socket for GatedSocket<S> {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.inner.peer_addr()
    }
}

impl<S: DatagramSocket> DatagramSocket for GatedSocket<S> {
    type Sender = GatedSender<S::Sender>;

    fn create_sender(&self) -> Self::Sender {
        GatedSender {
            inner: self.inner.create_sender(),
            gate: self.gate.clone(),
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        self.inner.poll_recv(cx, buffers, metadata)
    }

    fn capabilities(&self) -> DatagramCapabilities {
        self.inner.capabilities()
    }
}

#[derive(Debug)]
pub(super) struct GatedSender<S> {
    inner: S,
    gate: Arc<Gate>,
}

impl<S: DatagramSender> DatagramSender for GatedSender<S> {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        if self.gate.pending(cx) {
            return Poll::Pending;
        }
        self.inner.poll_send(cx, datagram)
    }

    fn capabilities(&self) -> DatagramCapabilities {
        self.inner.capabilities()
    }
}
