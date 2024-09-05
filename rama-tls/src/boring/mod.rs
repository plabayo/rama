//! boring based TLS support for rama.

pub mod client;
pub mod server;

pub mod dep {
    //! Dependencies for rama boring modules.
    //!
    //! Exported for your convenience.

    pub mod boring {
        //! Re-export of the [`boring`] crate.
        //!
        //! [`boring`]: https://docs.rs/boring

        #[doc(inline)]
        pub use boring::*;
    }

    pub mod tokio_boring {
        //! Full Re-export of the [`tokio-boring`] crate.
        //!
        //! [`tokio-boring`]: https://docs.rs/tokio-boring
        #[doc(inline)]
        pub use tokio_boring::*;
    }
}
