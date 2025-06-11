rama_utils::macros::enums::enum_builder! {
    #[derive(Default)]
    /// The mode in which a fragment is merged into the DOM.
    @String
    pub enum FragmentMergeMode {
        /// Morphs the fragment into the existing element using idiomorph.
        #[default]
        Morph => "morph",
        /// Replaces the inner HTML of the existing element.
        Inner => "inner",
        /// Replaces the outer HTML of the existing element.
        Outer => "outer",
        /// Prepends the fragment to the existing element.
        Prepend => "prepend",
        /// Appends the fragment to the existing element.
        Append => "append",
        /// Inserts the fragment before the existing element.
        Before => "before",
        /// Inserts the fragment after the existing element.
        After => "after",
        /// Upserts the attributes of the existing element.
        UpsertAttributes => "upsertAttributes",
    }
}

rama_utils::macros::enums::enum_builder! {
    /// The type protocol on top of SSE which allows for core
    /// pushed based communication between the server and the client.
    @String
    pub enum EventType {
        /// An event for merging HTML fragments into the DOM.
        MergeFragments => "datastar-merge-fragments",
        /// An event for merging signals.
        MergeSignals => "datastar-merge-signals",
        /// An event for removing HTML fragments from the DOM.
        RemoveFragments => "datastar-remove-fragments",
        /// An event for removing signals.
        RemoveSignals => "datastar-remove-signals",
        /// An event for executing <script/> elements in the browser.
        ExecuteScript => "datastar-execute-script",
    }
}
