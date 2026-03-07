pub mod json;

pub mod codec {
    //! Adaptors from `AsyncRead`/`AsyncWrite` to Stream/Sink
    //!
    //! Raw I/O objects work with byte sequences, but higher-level code usually
    //! wants to batch these into meaningful chunks, called "frames".
    //!
    //! Re-export of [`tokio_util::codec`].

    pub use tokio_util::codec::*;
}

pub mod io {
    //! Helpers for IO related tasks.
    //!
    //! Re-export of [`tokio_util::io`].

    pub use tokio_util::io::*;
}

pub use ::tokio_stream::*;
