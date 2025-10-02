rama_utils::macros::enums::enum_builder! {
    /// The maximum size of an image preview for this page in a search results.
    /// If omitted, search engines may show an image preview of the default size.
    /// If you don't want search engines to use larger thumbnail images,
    /// specify a max-image-preview value of standard or none. [^source]
    ///
    /// [^source]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Robots-Tag#max-image-preview_setting
    @String
    pub enum MaxImagePreviewSetting {
        /// No image preview is to be shown.
        None => "none",
        /// A default image preview may be shown.
        Standard => "standard",
        /// A larger image preview, up to the width of the viewport, may be shown.
        Large => "large",
    }
}
