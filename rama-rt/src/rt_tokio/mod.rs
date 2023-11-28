pub use tokio::pin;
pub use tokio::runtime::{Builder, Runtime};
pub use tokio::{select, spawn};

pub mod sync {
    //! Synchronization primitives for use in asynchronous contexts.
    pub use tokio::sync::Mutex;

    pub mod oneshot {
        //! A one-shot channel is used for sending a single message between
        //! asynchronous tasks. The [`channel`] function is used to create a
        //! [`Sender`] and [`Receiver`] handle pair that form the channel.

        pub use tokio::sync::oneshot::{channel, Receiver, Sender};

        pub mod error {
            //! oneshot error types

            pub use tokio::sync::oneshot::error::{RecvError, TryRecvError};
        }
    }

    pub mod mpsc {
        //! A multi-producer, single-consumer queue for sending values between
        //! asynchronous tasks.

        pub use tokio::sync::mpsc::{channel, OwnedPermit, Permit, Receiver, Sender, WeakSender};

        pub mod error {
            //! mpsc error types

            pub use tokio::sync::mpsc::error::{SendError, TryRecvError, TrySendError};
        }
    }

    pub mod broadcast {
        //! A multi-producer, multi-consumer broadcast queue. Each sent value is seen by
        //! all consumers.

        pub use tokio::sync::broadcast::{channel, Receiver, Sender};

        pub mod error {
            //! Broadcast error types

            pub use tokio::sync::broadcast::error::{RecvError, SendError};
        }
    }
}

pub mod io {
    //! Traits, helpers, and type definitions for asynchronous I/O functionality.

    pub use tokio::io::{
        copy, copy_bidirectional, copy_buf, duplex, empty, repeat, sink, split, AsyncBufReadExt,
        AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader, BufStream,
        BufWriter, DuplexStream, Empty, Lines, ReadBuf, ReadHalf, Repeat, Sink, Split, Take,
        WriteHalf,
    };
}

pub mod net {
    //! TCP/UDP/Unix bindings.
    pub use tokio::net::{
        lookup_host, TcpListener, TcpSocket, TcpStream, ToSocketAddrs, UdpSocket,
    };

    pub mod tcp {
        //! TCP utility types.

        pub use tokio::net::tcp::{
            OwnedReadHalf, OwnedWriteHalf, ReadHalf, ReuniteError, WriteHalf,
        };
    }
}

pub mod tls;

pub mod task {
    //! Asynchronous green-threads.

    pub use tokio::task::{spawn, spawn_blocking, spawn_local, JoinHandle};
}

pub mod time {
    //! Utilities for tracking time.

    pub use tokio::time::{sleep, Duration, Instant};
}

pub mod graceful {
    //! Shutdown management for graceful shutdown of async-first applications.
    pub use tokio_graceful::{Shutdown, ShutdownGuard, WeakShutdownGuard};
}

pub mod test {
    //! Tokio and Futures based testing utilities

    pub mod io {
        //! mock type implementing `AsyncRead`` and `AsyncWrite``.

        pub use tokio_test::io::{Builder, Mock};
    }
}
