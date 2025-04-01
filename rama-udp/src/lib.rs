//! UDP module for Rama.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

mod socket;
pub use socket::UdpSocket;

#[doc(inline)]
pub use tokio_util::udp::UdpFramed;

pub mod codec {
    //! Adaptors from `AsyncRead`/`AsyncWrite` to Stream/Sink
    //!
    //! Raw I/O objects work with byte sequences, but higher-level code usually
    //! wants to batch these into meaningful chunks, called "frames".
    //!
    //! Re-export of [`tokio_util::codec`].

    pub use tokio_util::codec::*;
}
