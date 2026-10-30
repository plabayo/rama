rama_utils::macros::enums::enum_builder! {
    /// The `Sec-Fetch-Dest` [fetch metadata request header][mdn].
    ///
    /// Sent by browsers to indicate the request's destination: how the fetched
    /// data will be used, such as a document navigation, a script or an image.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Dest
    ///
    /// # Example values
    ///
    /// * `document`
    /// * `empty`
    /// * `image`
    /// * `script`
    @String
    pub enum SecFetchDest {
        /// Audio data, e.g. from an HTML `<audio>` element.
        Audio => "audio",
        /// Data fetched for an audio worklet.
        AudioWorklet => "audioworklet",
        /// A top-level navigation.
        Document => "document",
        /// Data for an HTML `<embed>` element.
        Embed => "embed",
        /// No destination, e.g. `fetch()`, `XMLHttpRequest`, `EventSource` or a beacon.
        Empty => "empty",
        /// A navigation in a fenced frame.
        FencedFrame => "fencedframe",
        /// A font, e.g. from CSS `@font-face`.
        Font => "font",
        /// A navigation in an HTML `<frame>`.
        Frame => "frame",
        /// A navigation in an HTML `<iframe>`.
        Iframe => "iframe",
        /// An image, e.g. from an HTML `<img>` element or a CSS `background-image`.
        Image => "image",
        /// A JSON module import.
        Json => "json",
        /// A web application manifest.
        Manifest => "manifest",
        /// Data for an HTML `<object>` element.
        Object => "object",
        /// Data fetched for a CSS paint worklet.
        PaintWorklet => "paintworklet",
        /// A report, e.g. a Content Security Policy report.
        Report => "report",
        /// A script, other than a worker or worklet script.
        Script => "script",
        /// A service worker script.
        ServiceWorker => "serviceworker",
        /// A shared worker script.
        SharedWorker => "sharedworker",
        /// A style sheet, e.g. from `<link rel="stylesheet">` or CSS `@import`.
        Style => "style",
        /// A text track, e.g. from an HTML `<track>` element.
        Track => "track",
        /// Video data, e.g. from an HTML `<video>` element.
        Video => "video",
        /// A Federated Credential Management request.
        WebIdentity => "webidentity",
        /// A dedicated worker script.
        Worker => "worker",
        /// An XSLT transform.
        Xslt => "xslt",
    }
}

token_header!(SecFetchDest, SEC_FETCH_DEST);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    const KNOWN: &[(&str, SecFetchDest)] = &[
        ("audio", SecFetchDest::Audio),
        ("audioworklet", SecFetchDest::AudioWorklet),
        ("document", SecFetchDest::Document),
        ("embed", SecFetchDest::Embed),
        ("empty", SecFetchDest::Empty),
        ("fencedframe", SecFetchDest::FencedFrame),
        ("font", SecFetchDest::Font),
        ("frame", SecFetchDest::Frame),
        ("iframe", SecFetchDest::Iframe),
        ("image", SecFetchDest::Image),
        ("json", SecFetchDest::Json),
        ("manifest", SecFetchDest::Manifest),
        ("object", SecFetchDest::Object),
        ("paintworklet", SecFetchDest::PaintWorklet),
        ("report", SecFetchDest::Report),
        ("script", SecFetchDest::Script),
        ("serviceworker", SecFetchDest::ServiceWorker),
        ("sharedworker", SecFetchDest::SharedWorker),
        ("style", SecFetchDest::Style),
        ("track", SecFetchDest::Track),
        ("video", SecFetchDest::Video),
        ("webidentity", SecFetchDest::WebIdentity),
        ("worker", SecFetchDest::Worker),
        ("xslt", SecFetchDest::Xslt),
    ];

    #[test]
    fn known_values_round_trip() {
        for (raw, dest) in KNOWN {
            assert_eq!(test_decode::<SecFetchDest>(&[raw]).as_ref(), Some(dest));
            assert_eq!(test_encode(dest.clone())["sec-fetch-dest"], *raw);
        }
    }

    #[test]
    fn unknown_value_round_trips() {
        let dest = test_decode::<SecFetchDest>(&["speculationrules"]).unwrap();
        assert_eq!(dest, SecFetchDest::Unknown("speculationrules".into()));
        assert_eq!(test_encode(dest)["sec-fetch-dest"], "speculationrules");
    }

    #[test]
    fn rejects_empty_and_multiple_lines() {
        assert_eq!(test_decode::<SecFetchDest>(&[""]), None);
        assert_eq!(test_decode::<SecFetchDest>(&["image", "image"]), None);
        assert_eq!(test_decode::<SecFetchDest>(&["image", "script"]), None);
    }
}
