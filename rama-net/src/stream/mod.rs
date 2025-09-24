//! Utilities that operate on a [`Stream`]
//!
//! [`Stream`]: rama_core::stream::Stream

pub mod matcher;

pub mod layer;
pub mod service;

mod socket;
#[doc(inline)]
pub use socket::{ClientSocketInfo, Socket, SocketInfo};

pub mod dep {
    //! Dependencies for rama stream modules.
    //!
    //! Exported for your convenience.

    pub mod ipnet {
        //! Re-export of the [`ipnet`] crate.
        //!
        //! Types for IPv4 and IPv6 network addresses.
        //!
        //! [`ipnet`]: https://docs.rs/ipnet

        #[doc(inline)]
        pub use ipnet::*;
    }
}
