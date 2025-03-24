//! Everything that we need from boring ssl
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

// In the future we will probably make custom bindings but for now we use this as a dependency
// and add extra logic here when we need to

pub mod dep {
    //! Dependencies for rama boring modules.
    //!
    //! Exported for your convenience (and so we centralize this).

    pub mod boring {
        //! Re-export of the [`boring`] crate.
        //!
        //! [`boring`]: https://docs.rs/boring

        #[doc(inline)]
        pub use boring::*;
    }
}
