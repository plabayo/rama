//! ttRPC codegen support for Rama.
//!
//! Compiles `.proto` service definitions into Rust ttRPC stubs (a service trait, a
//! [`rama_ttrpc::Client`] impl and server dispatch) for use with [`rama-ttrpc`]. Drive it
//! from a `build.rs` and include the output with `rama_ttrpc::include_proto!`.
//!
//! The API mirrors [`rama-grpc-build`]: use [`compile_protos`] for the simple case, or
//! [`configure`] for a [`RamaTtrpcProtoBuilder`] when you need options such as a custom
//! output directory.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! [`rama_ttrpc::Client`]: https://docs.rs/rama-ttrpc
//! [`rama-ttrpc`]: https://crates.io/crates/rama-ttrpc
//! [`rama-grpc-build`]: https://crates.io/crates/rama-grpc-build

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![expect(
    clippy::unwrap_used,
    reason = "build-time codegen helper (tonic-build style): type/path strings come from prost and are always valid Rust, so panic-on-bad-input is the standard pattern"
)]

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

#[doc(hidden)]
pub mod prost_build {
    pub use prost_build::*;
}

mod root_crate;
mod service_generator;

pub use service_generator::TtrpcServiceGenerator;

/// Configure `rama-ttrpc-build` code generation, returning a [`RamaTtrpcProtoBuilder`].
///
/// Use this instead of [`compile_protos`] when you need to set options, e.g. a custom
/// output directory:
///
/// ```rust,no_run
/// # fn main() -> std::io::Result<()> {
/// let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("ttrpc");
/// rama_ttrpc_build::configure()
///     .with_out_dir(out)
///     .compile_protos(&["proto/greeter.proto"], &["proto"])?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub fn configure() -> RamaTtrpcProtoBuilder {
    RamaTtrpcProtoBuilder::default()
}

/// Compile `.proto` files into Rust ttRPC stubs during a Cargo build.
///
/// The generated `.rs` files are written to the Cargo `OUT_DIR` directory, suitable for use
/// with the [`include!`] macro (or `rama_ttrpc::include_proto!`). This should be called from
/// a project's `build.rs`. Use [`configure`] instead when you need more options.
///
/// # Arguments
///
/// **`protos`** - Paths to `.proto` files to compile. Any transitively imported `.proto`
/// files are automatically included.
///
/// **`includes`** - Paths to directories in which to search for imports.
///
/// # Errors
///
/// Fails if `protoc` cannot be located, the `.proto`s cannot be parsed or compiled, or the
/// output cannot be written. It is expected to be `unwrap`ed in a `build.rs`.
///
/// # Example `build.rs`
///
/// ```rust,no_run
/// fn main() -> std::io::Result<()> {
///     rama_ttrpc_build::compile_protos(&["src/frontend.proto", "src/backend.proto"], &["src"])?;
///     Ok(())
/// }
/// ```
pub fn compile_protos<P: AsRef<Path>>(protos: &[P], includes: &[P]) -> io::Result<()> {
    configure().compile_protos(protos, includes)
}

/// Builder for configuring and generating ttRPC code from `.proto` files.
///
/// Analogous to `rama-grpc-build`'s builder.
#[derive(Debug, Clone, Default)]
pub struct RamaTtrpcProtoBuilder {
    out_dir: Option<PathBuf>,
    extern_path: Vec<(String, String)>,
    protoc_args: Vec<OsString>,
    skip_protoc_run: bool,
    file_descriptor_set_path: Option<PathBuf>,
}

impl RamaTtrpcProtoBuilder {
    rama_utils::macros::generate_set_and_with! {
        /// Set the output directory for generated code.
        ///
        /// Defaults to the Cargo `OUT_DIR`. A build script that generates code for multiple
        /// RPC flavours can point each at its own subdirectory to avoid file-name collisions.
        pub fn out_dir(mut self, out_dir: impl AsRef<Path>) -> Self {
            self.out_dir = Some(out_dir.as_ref().to_path_buf());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Declare an externally provided Protobuf package or type.
        ///
        /// Passed directly to `prost_build::Config::extern_path`. Useful to share generated
        /// message types with another codegen (e.g. `rama-grpc-build`) instead of
        /// regenerating them.
        pub fn extern_path(mut self, proto_path: impl AsRef<str>, rust_path: impl AsRef<str>) -> Self {
            self.extern_path
                .push((proto_path.as_ref().to_owned(), rust_path.as_ref().to_owned()));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add an argument to the `protoc` invocation.
        ///
        /// Passed directly to `prost_build::Config::protoc_arg`.
        pub fn protoc_arg(mut self, arg: impl AsRef<str>) -> Self {
            self.protoc_args.push(arg.as_ref().into());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Skip running `protoc` and instead use a pre-generated file descriptor set.
        ///
        /// Passed directly to `prost_build::Config::skip_protoc_run`. This requires a file
        /// descriptor set to be available, so [`with_file_descriptor_set_path`] /
        /// [`set_file_descriptor_set_path`] must also be set — otherwise codegen fails.
        ///
        /// [`with_file_descriptor_set_path`]: Self::with_file_descriptor_set_path
        /// [`set_file_descriptor_set_path`]: Self::set_file_descriptor_set_path
        pub fn skip_protoc_run(mut self) -> Self {
            self.skip_protoc_run = true;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the path to the protobuf file descriptor set.
        ///
        /// Passed directly to `prost_build::Config::file_descriptor_set_path`. When `protoc`
        /// runs, the descriptor set is written to this path; when [`with_skip_protoc_run`] /
        /// [`set_skip_protoc_run`] is enabled, prost reads a pre-generated descriptor set from
        /// it instead of invoking `protoc`. It must therefore be provided whenever `protoc` is
        /// skipped.
        ///
        /// [`with_skip_protoc_run`]: Self::with_skip_protoc_run
        /// [`set_skip_protoc_run`]: Self::set_skip_protoc_run
        pub fn file_descriptor_set_path(mut self, path: impl AsRef<Path>) -> Self {
            self.file_descriptor_set_path = Some(path.as_ref().to_path_buf());
            self
        }
    }

    /// Compile `.proto` files into ttRPC stubs and execute code generation.
    ///
    /// # Errors
    ///
    /// See [`compile_protos`].
    pub fn compile_protos<P: AsRef<Path>>(self, protos: &[P], includes: &[P]) -> io::Result<()> {
        let mut config = prost_build::Config::new();
        config.service_generator(Box::new(TtrpcServiceGenerator));

        let root_crate = crate::root_crate::root_crate_name_ts();
        config.prost_path(format!("{root_crate}::protobuf::prost"));
        config.prost_types_path(format!("{root_crate}::protobuf::prost::types"));

        let out_dir = match self.out_dir {
            Some(out_dir) => out_dir,
            None => std::env::var_os("OUT_DIR")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    io::Error::other(
                        "OUT_DIR is not set (run from a build script or set `out_dir`)",
                    )
                })?,
        };
        config.out_dir(out_dir);

        for (proto_path, rust_path) in &self.extern_path {
            config.extern_path(proto_path, rust_path);
        }

        for arg in &self.protoc_args {
            config.protoc_arg(arg);
        }

        if let Some(path) = &self.file_descriptor_set_path {
            config.file_descriptor_set_path(path);
        }

        if self.skip_protoc_run {
            config.skip_protoc_run();
        }

        #[cfg(feature = "vendor-protoc")]
        match protoc_bin_vendored::protoc_bin_path() {
            Ok(path) => {
                config.protoc_executable(path);
            }
            Err(err) => {
                eprintln!(
                    "failed to get vendored protoc bin path (falling back to system install): {err}"
                )
            }
        }

        config.compile_protos(protos, includes)
    }
}
