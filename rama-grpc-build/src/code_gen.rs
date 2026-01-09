//! Generic code generation for gRPC services.
//!
//! This module provides the generic infrastructure for generating
//! client and server code from service definitions.

use std::collections::HashSet;

use proc_macro2::TokenStream;

use crate::{Attributes, Service};

/// Builder for the generic code generation of server and clients.
#[derive(Debug)]
pub(crate) struct CodeGenBuilder {
    emit_package: bool,
    compile_well_known_types: bool,
    attributes: Attributes,
    disable_comments: HashSet<String>,
    root_crate_name: TokenStream,
}

impl CodeGenBuilder {
    /// Create a new code gen builder with default options.
    #[must_use]
    pub(crate) fn new() -> Self {
        Default::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable code generation to emit the package name.
        pub(crate) fn emit_package(mut self, enable: bool) -> Self {
            self.emit_package = enable;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Attributes that will be added to `mod` and `struct` items.
        ///
        /// Reference [`Attributes`] for more information.
        pub(crate) fn attributes(mut self, attributes: Attributes) -> Self {
            self.attributes = attributes;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable compiling well known types, this will force codegen to not
        /// use the well known types from `prost-types`.
        pub(crate) fn compile_well_known_types(mut self, enable: bool) -> Self {
            self.compile_well_known_types = enable;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Disable comments based on a proto path.
        pub(crate) fn disable_comments(mut self, disable_comments: HashSet<String>) -> Self {
            self.disable_comments = disable_comments;
            self
        }
    }

    /// Generate client code based on `Service`.
    ///
    /// This takes some `Service` and will generate a `TokenStream` that contains
    /// a public module with the generated client.
    pub(crate) fn generate_client(&self, service: &impl Service, proto_path: &str) -> TokenStream {
        crate::client::generate_internal(
            service,
            self.emit_package,
            proto_path,
            self.compile_well_known_types,
            &self.attributes,
            &self.disable_comments,
            &self.root_crate_name,
        )
    }

    /// Generate server code based on `Service`.
    ///
    /// This takes some `Service` and will generate a `TokenStream` that contains
    /// a public module with the generated client.
    pub(crate) fn generate_server(&self, service: &impl Service, proto_path: &str) -> TokenStream {
        crate::server::generate_internal(
            service,
            self.emit_package,
            proto_path,
            self.compile_well_known_types,
            &self.attributes,
            &self.disable_comments,
            &self.root_crate_name,
        )
    }
}

impl Default for CodeGenBuilder {
    fn default() -> Self {
        Self {
            emit_package: true,
            compile_well_known_types: false,
            attributes: Attributes::default(),
            disable_comments: HashSet::default(),
            root_crate_name: crate::root_crate::root_crate_name_ts(),
        }
    }
}
