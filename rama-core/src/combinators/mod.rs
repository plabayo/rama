//! Combinators for working with or in function of services.
//!
//! See [`Either`] for an example.

mod either;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[doc(inline)]
pub use either::impl_async_read_write_either;
#[doc(inline)]
pub use either::{
    Either, Either3, Either4, Either5, Either6, Either7, Either8, Either9, define_either,
    impl_either, impl_iterator_either,
};
