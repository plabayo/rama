rama_utils::macros::enums::enum_builder! {
    /// The `Sec-Fetch-Mode` [fetch metadata request header][mdn].
    ///
    /// Sent by browsers to indicate the request's mode: a navigation, or one of
    /// the CORS modes a subresource request is made in.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Mode
    ///
    /// # Example values
    ///
    /// * `cors`
    /// * `navigate`
    /// * `no-cors`
    /// * `same-origin`
    /// * `websocket`
    @String
    pub enum SecFetchMode {
        /// A CORS protocol request.
        Cors => "cors",
        /// A navigation between HTML documents.
        Navigate => "navigate",
        /// A no-cors request, e.g. an image or a classic script.
        NoCors => "no-cors",
        /// A request to the same origin as the initiator.
        SameOrigin => "same-origin",
        /// A WebSocket connection.
        WebSocket => "websocket",
    }
}

token_header!(SecFetchMode, SEC_FETCH_MODE);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    const KNOWN: &[(&str, SecFetchMode)] = &[
        ("cors", SecFetchMode::Cors),
        ("navigate", SecFetchMode::Navigate),
        ("no-cors", SecFetchMode::NoCors),
        ("same-origin", SecFetchMode::SameOrigin),
        ("websocket", SecFetchMode::WebSocket),
    ];

    #[test]
    fn known_values_round_trip() {
        for (raw, mode) in KNOWN {
            assert_eq!(test_decode::<SecFetchMode>(&[raw]).as_ref(), Some(mode));
            assert_eq!(test_encode(mode.clone())["sec-fetch-mode"], *raw);
        }
    }

    #[test]
    fn unknown_value_round_trips() {
        let mode = test_decode::<SecFetchMode>(&["webtransport"]).unwrap();
        assert_eq!(mode, SecFetchMode::Unknown("webtransport".into()));
        assert_eq!(test_encode(mode)["sec-fetch-mode"], "webtransport");
    }

    #[test]
    fn rejects_empty_and_multiple_lines() {
        assert_eq!(test_decode::<SecFetchMode>(&[""]), None);
        assert_eq!(test_decode::<SecFetchMode>(&["cors", "cors"]), None);
        assert_eq!(test_decode::<SecFetchMode>(&["navigate", "cors"]), None);
    }
}
