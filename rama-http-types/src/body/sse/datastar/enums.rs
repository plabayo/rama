rama_utils::macros::enums::enum_builder! {
    #[derive(Default)]
    /// The mode in which elements are patched into the DOM.
    ///
    /// Spec: <https://github.com/starfederation/datastar/blob/main/sdk/ADR.md#elementpatchmode>
    @String
    pub enum ElementPatchMode {
        #[default]
        /// Morph entire element, preserving state
        ///
        /// Morphed: ✅
        Outer => "outer",

        /// Morph inner HTML only, preserving state
        ///
        /// Morphed: ✅
        Inner => "inner",

        /// Replace entire element, reset state
        ///
        /// Morphed: 🚫
        Replace => "replace",

        /// Insert at beginning inside target
        ///
        /// Morphed: 🚫
        Prepend => "prepend",

        /// Insert at end inside target
        ///
        /// Morphed: 🚫
        Append => "append",

        /// Insert before target element
        ///
        /// Morphed: 🚫
        Before => "before",

        /// Insert after target element
        ///
        /// Morphed: 🚫
        After => "after",

        /// Remove target element from DOM
        ///
        /// Morphed: 🚫
        Remove => "remove",
    }
}

rama_utils::macros::enums::enum_builder! {
    /// The type protocol on top of SSE which allows for core
    /// pushed based communication between the server and the client.
    ///
    /// Spec: <https://github.com/starfederation/datastar/blob/main/sdk/ADR.md#eventtype>
    @String
    pub enum EventType {
        /// Patches HTML elements into the DOM
        PatchElements => "datastar-patch-elements",
        /// Patches signals into the signal store
        PatchSignals => "datastar-patch-signals",
    }
}
