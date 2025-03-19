//! boring based TLS support for rama.

pub mod client;
pub mod server;

pub mod dep {
    //! Dependencies for rama boring modules.
    //!
    //! Exported for your convenience.

    pub mod boring {
        //! Re-export of the [`rama-boring`] crate.
        //!
        //! [`rama-boring`]: https://docs.rs/rama-boring

        #[doc(inline)]
        pub use rama_boring::*;
    }

    pub mod boring_tokio {
        //! Full Re-export of the [`rama-tokio-boring`] crate.
        //!
        //! [`rama-tokio-boring`]: https://docs.rs/rama-tokio-boring
        #[doc(inline)]
        pub use rama_boring_tokio::*;
    }
}
