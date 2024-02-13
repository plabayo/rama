//! TLS module for Rama.

pub mod rustls;

pub mod dep {
    //! Dependencies for rama tls modules.
    //!
    //! Exported for your convenience.

    pub mod rcgen {
        //! Re-export of the [`rcgen`] crate.
        //!
        //! [`rcgen`]: https://docs.rs/rcgen

        pub use rcgen::*;
    }
}
