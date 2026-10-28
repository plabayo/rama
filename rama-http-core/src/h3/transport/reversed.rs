use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};
use rama_quic::{
    ClosedStream, ConnectionError, ReadError, StoppedError, WriteError, qlog::ConnectionQlogControl,
};
use rama_quic_proto::{Dir, Side, StreamId, VarInt};
use rama_utils::reactive::ChangeListener;
use std::{
    sync::Weak,
    task::{Context, Poll},
    time::Duration,
};

use super::{
    BiReservation, BoxedStreamHandle, Connection, EarlyData, RecvStream, ReserveBiStreams,
    SendStream,
};

/// Run HTTP/3 in the opposite role of the QUIC connection it wraps.
///
/// The QUIC client can then serve HTTP/3 and the QUIC server send the requests, for example a
/// device behind NAT that dials out and serves what the other end asks. Both ends must wrap
/// their connection: the stream IDs HTTP/3 sees have their initiator flipped, which only agrees
/// when the peer flips them too.
///
/// It wraps the connection, its streams and its reservations alike.
#[derive(Clone, Debug)]
pub struct Reversed<T>(T);

impl<T> Reversed<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn get_ref(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

fn reverse(id: StreamId) -> StreamId {
    StreamId::new(!id.initiator(), id.dir(), id.index())
}

fn reverse_bi<S, R>((send, recv): (S, R)) -> (Reversed<S>, Reversed<R>) {
    (Reversed(send), Reversed(recv))
}

impl<C: ExtensionsRef> ExtensionsRef for Reversed<C> {
    fn extensions(&self) -> &Extensions {
        self.0.extensions()
    }
}

impl<C: Connection> Connection for Reversed<C> {
    type SendStream = Reversed<C::SendStream>;
    type RecvStream = Reversed<C::RecvStream>;
    type CloseLease = C::CloseLease;

    async fn open_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), ConnectionError> {
        self.0.open_bi().await.map(reverse_bi)
    }

    async fn open_uni(&self) -> Result<Self::SendStream, ConnectionError> {
        self.0.open_uni().await.map(Reversed)
    }

    async fn accept_bi(&self) -> Result<(Self::SendStream, Self::RecvStream), ConnectionError> {
        self.0.accept_bi().await.map(reverse_bi)
    }

    async fn accept_uni(&self) -> Result<Self::RecvStream, ConnectionError> {
        self.0.accept_uni().await.map(Reversed)
    }

    fn side(&self) -> Side {
        !self.0.side()
    }

    fn handshake_confirmed(&self) -> impl Future<Output = Result<(), ConnectionError>> + Send {
        self.0.handshake_confirmed()
    }

    fn is_handshake_confirmed(&self) -> bool {
        self.0.is_handshake_confirmed()
    }

    fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.0.close(error_code, reason);
    }

    fn closed(&self) -> impl Future<Output = ConnectionError> + Send {
        self.0.closed()
    }

    fn close_reason(&self) -> Option<ConnectionError> {
        self.0.close_reason()
    }

    fn available_streams(&self, dir: Dir) -> u64 {
        self.0.available_streams(dir)
    }

    fn max_concurrent_streams(&self, dir: Dir) -> u64 {
        self.0.max_concurrent_streams(dir)
    }

    fn remote_stream_limit(&self, dir: Dir) -> u64 {
        self.0.remote_stream_limit(dir)
    }

    fn local_stream_limit(&self, dir: Dir) -> u64 {
        self.0.local_stream_limit(dir)
    }

    /// 0-RTT is the QUIC client's, which serves HTTP/3 here: no request is early.
    fn early_data(&self) -> EarlyData {
        EarlyData::Unavailable
    }

    fn qlog_control(&self) -> Option<ConnectionQlogControl> {
        self.0.qlog_control()
    }

    fn read_datagram(&self) -> impl Future<Output = Result<Bytes, ConnectionError>> + Send {
        self.0.read_datagram()
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.0.max_datagram_size()
    }

    fn datagram_receive_enabled(&self) -> bool {
        self.0.datagram_receive_enabled()
    }

    fn received_datagrams(&self) -> usize {
        self.0.received_datagrams()
    }

    fn datagram_send_ready(&self) -> impl Future<Output = ()> + Send + 'static + use<C> {
        self.0.datagram_send_ready()
    }

    fn close_lease(&self) -> C::CloseLease {
        self.0.close_lease()
    }

    fn rtt(&self) -> Duration {
        self.0.rtt()
    }
}

impl<C: ReserveBiStreams> ReserveBiStreams for Reversed<C> {
    type Reservation = Reversed<C::Reservation>;

    fn try_reserve_bi(&self) -> Result<Option<Self::Reservation>, ConnectionError> {
        self.0
            .try_reserve_bi()
            .map(|reservation| reservation.map(Reversed))
    }

    fn subscribe_bi_stream_budget(&self, listener: Weak<dyn ChangeListener>) {
        self.0.subscribe_bi_stream_budget(listener);
    }
}

impl<R: BiReservation> BiReservation for Reversed<R> {
    type SendStream = Reversed<R::SendStream>;
    type RecvStream = Reversed<R::RecvStream>;

    fn open(self) -> Result<(Self::SendStream, Self::RecvStream), ConnectionError> {
        self.0.open().map(reverse_bi)
    }
}

impl<S: SendStream> SendStream for Reversed<S> {
    type Handle = S::Handle;

    fn id(&self) -> StreamId {
        reverse(self.0.id())
    }

    fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
        reserve: u64,
    ) -> Poll<Result<(), WriteError>> {
        self.0.poll_write_chunks(cx, chunks, reserve)
    }

    fn try_write_generated(
        &mut self,
        reserve: u64,
        generate: impl FnOnce(usize) -> Bytes,
    ) -> Result<(), WriteError> {
        self.0.try_write_generated(reserve, generate)
    }

    fn finish(&mut self) -> Result<(), ClosedStream> {
        self.0.finish()
    }

    fn reset(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        self.0.reset(error_code)
    }

    fn set_priority(&self, priority: i32) -> Result<(), ClosedStream> {
        self.0.set_priority(priority)
    }

    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<VarInt>, StoppedError>> + Send + Sync + 'static + use<S>
    {
        self.0.stopped()
    }

    fn handle(&self) -> Self::Handle {
        self.0.handle()
    }

    fn boxed_handle(&self) -> BoxedStreamHandle {
        self.0.boxed_handle()
    }
}

impl<R: RecvStream> RecvStream for Reversed<R> {
    fn id(&self) -> StreamId {
        reverse(self.0.id())
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_length: usize,
    ) -> Poll<Result<Option<Bytes>, ReadError>> {
        self.0.poll_read_chunk(cx, max_length)
    }

    fn stop(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        self.0.stop(error_code)
    }

    fn is_0rtt(&self) -> bool {
        self.0.is_0rtt()
    }
}
