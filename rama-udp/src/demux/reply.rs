//! Sockets bound at original destinations, so that a redirected association's replies leave
//! from where its client sent to.
//!
//! One socket per destination is shared by every association addressed there, lives as long as
//! the last of them, and is read as well: a host whose redirection matches local sockets
//! delivers the client's next datagrams to it rather than to the listener.

use std::sync::{Arc, atomic::Ordering};

use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::{
    Service, bytes::Bytes, error::BoxError, rt::Executor, service::BoxService, telemetry::tracing,
};
use rama_net::address::SocketAddress;
use tokio::sync::{mpsc, oneshot};

use super::{Charge, Counters, Queued};
use crate::{DatagramSocket, DatagramSocketExt as _, RetainedDatagram};

struct Bound<T> {
    sender: T,
    users: usize,
    /// Dropped with the entry, which ends the socket's reader.
    _stop: oneshot::Sender<()>,
}

type BoundSockets<T> = Arc<Mutex<HashMap<SocketAddress, Bound<T>>>>;

pub(super) struct ReplySockets<S: DatagramSocket> {
    bind: BoxService<SocketAddress, S, BoxError>,
    bound: BoundSockets<S::Sender>,
    reader: Reader,
}

/// What a reply socket's reader needs to hand its datagrams to the demux.
#[derive(Clone)]
pub(super) struct Reader {
    pub(super) incoming: mpsc::Sender<Queued>,
    pub(super) counters: Arc<Counters>,
    pub(super) queued_bytes: usize,
    pub(super) receive_bytes: usize,
}

impl<S> ReplySockets<S>
where
    S: DatagramSocket<Sender: Clone> + Send + 'static,
{
    pub(super) fn new(bind: BoxService<SocketAddress, S, BoxError>, reader: Reader) -> Self {
        Self {
            bind,
            bound: Arc::default(),
            reader,
        }
    }

    /// A sender bound at `local` and the lease that keeps it, binding a socket there when no
    /// association holds one yet.
    pub(super) async fn lease(
        &self,
        local: SocketAddress,
        exec: &Executor,
    ) -> Result<(S::Sender, ReplyLease<S::Sender>), BoxError> {
        let lease = ReplyLease {
            bound: self.bound.clone(),
            local,
        };
        if let Some(bound) = self.bound.lock().get_mut(&local) {
            bound.users += 1;
            return Ok((bound.sender.clone(), lease));
        }
        let socket = self.bind.serve(local).await?;
        let sender = socket.create_sender();
        let (stop, stopped) = oneshot::channel();
        exec.spawn_task(read(socket, local, self.reader.clone(), stopped));
        self.bound.lock().insert(
            local,
            Bound {
                sender: sender.clone(),
                users: 1,
                _stop: stop,
            },
        );
        Ok((sender, lease))
    }
}

/// One association's use of the reply socket at `local`: the socket closes with its last lease.
pub(super) struct ReplyLease<T> {
    bound: BoundSockets<T>,
    local: SocketAddress,
}

impl<T> Drop for ReplyLease<T> {
    fn drop(&mut self) {
        let mut bound = self.bound.lock();
        if let Some(entry) = bound.get_mut(&self.local) {
            entry.users -= 1;
            if entry.users == 0 {
                bound.remove(&self.local);
            }
        }
    }
}

/// Hand what the socket at `local` receives to the demux, as sent to `local`, until its last
/// lease ends, the demux stops, or the socket fails.
async fn read<S: DatagramSocket>(
    mut socket: S,
    local: SocketAddress,
    reader: Reader,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut buffer = vec![0; reader.receive_bytes];
    loop {
        let received = tokio::select! {
            received = socket.recv(&mut buffer) => received,
            _ = &mut stopped => return,
        };
        let mut metadata = match received {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::debug!(%error, %local, "datagram reply socket stopped reading");
                return;
            }
        };
        if metadata.validate(buffer.len()).is_err() {
            reader.counters.invalid.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let Some(charge) = Charge::try_new(&reader.counters, metadata.len, reader.queued_bytes)
        else {
            reader.counters.queue_full.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        metadata.local = local;
        metadata.original_destination = Some(local);
        let datagram = Queued {
            datagram: RetainedDatagram {
                payload: Bytes::copy_from_slice(&buffer[..metadata.len]),
                metadata,
            },
            _charge: charge,
        };
        if reader.incoming.send(datagram).await.is_err() {
            return;
        }
    }
}
