use rama_utils::macros::generate_set_and_with;

/// Resource limits applied while copying values out of the JavaScript engine.
///
/// These limits cover evaluation results, function results, thrown values, and
/// arguments passed from JavaScript into host functions. They bound the Rust-side
/// work performed after (or during) script execution, which is separate from the
/// JavaScript runtime's loop, recursion, and stack limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsSnapshotLimits {
    max_depth: usize,
    max_nodes: usize,
    max_array_length: usize,
    max_object_properties: usize,
    max_string_bytes: usize,
}

impl JsSnapshotLimits {
    /// Default maximum nesting depth.
    pub const DEFAULT_MAX_DEPTH: usize = 64;

    /// Default maximum number of values and container edges visited.
    pub const DEFAULT_MAX_NODES: usize = 100_000;

    /// Default maximum number of entries in one array.
    pub const DEFAULT_MAX_ARRAY_LENGTH: usize = 65_536;

    /// Default maximum number of own properties in one object.
    pub const DEFAULT_MAX_OBJECT_PROPERTIES: usize = 16_384;

    /// Default maximum cumulative UTF-8 bytes copied for strings and keys.
    pub const DEFAULT_MAX_STRING_BYTES: usize = 8 * 1024 * 1024;

    /// Maximum nesting depth, where the top-level value has depth zero.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Maximum number of values and container edges visited in one conversion.
    #[must_use]
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }

    /// Maximum number of entries accepted from one array.
    #[must_use]
    pub const fn max_array_length(&self) -> usize {
        self.max_array_length
    }

    /// Maximum number of own properties accepted from one object.
    #[must_use]
    pub const fn max_object_properties(&self) -> usize {
        self.max_object_properties
    }

    /// Maximum cumulative UTF-8 bytes copied for strings and property keys.
    #[must_use]
    pub const fn max_string_bytes(&self) -> usize {
        self.max_string_bytes
    }

    generate_set_and_with! {
        /// Set the maximum nesting depth.
        pub fn max_depth(mut self, max_depth: usize) -> Self {
            self.max_depth = max_depth;
            self
        }
    }

    generate_set_and_with! {
        /// Set the maximum number of values and container edges visited.
        pub fn max_nodes(mut self, max_nodes: usize) -> Self {
            self.max_nodes = max_nodes;
            self
        }
    }

    generate_set_and_with! {
        /// Set the maximum number of entries accepted from one array.
        pub fn max_array_length(mut self, max_array_length: usize) -> Self {
            self.max_array_length = max_array_length;
            self
        }
    }

    generate_set_and_with! {
        /// Set the maximum number of own properties accepted from one object.
        pub fn max_object_properties(mut self, max_object_properties: usize) -> Self {
            self.max_object_properties = max_object_properties;
            self
        }
    }

    generate_set_and_with! {
        /// Set the maximum cumulative UTF-8 bytes copied for strings and keys.
        pub fn max_string_bytes(mut self, max_string_bytes: usize) -> Self {
            self.max_string_bytes = max_string_bytes;
            self
        }
    }
}

impl Default for JsSnapshotLimits {
    fn default() -> Self {
        Self {
            max_depth: Self::DEFAULT_MAX_DEPTH,
            max_nodes: Self::DEFAULT_MAX_NODES,
            max_array_length: Self::DEFAULT_MAX_ARRAY_LENGTH,
            max_object_properties: Self::DEFAULT_MAX_OBJECT_PROPERTIES,
            max_string_bytes: Self::DEFAULT_MAX_STRING_BYTES,
        }
    }
}
