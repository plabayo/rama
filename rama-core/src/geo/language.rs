//! Language and script subtags, as used in BCP 47 language tags (see
//! [`super::Locale`]).
//!
//! - Languages are keyed by their ISO 639-1 two-letter code.
//!   Source: ISO 639-1 (<https://www.loc.gov/standards/iso639-2/php/code_list.php>).
//! - Scripts are keyed by their ISO 15924 four-letter code.
//!   Source: ISO 15924 (<https://www.unicode.org/iso15924/iso15924-codes.html>).
//!
//! These are common subsets; any other code round-trips through the
//! `Unknown` variant.

use super::builder::geo_enum;

geo_enum! {
    /// A language, keyed by its ISO 639-1 two-letter code.
    pub enum Language / LanguageRef {
        Arabic => "ar", "Arabic",
        Bengali => "bn", "Bengali",
        Czech => "cs", "Czech",
        Danish => "da", "Danish",
        German => "de", "German",
        Greek => "el", "Greek",
        English => "en", "English",
        Spanish => "es", "Spanish",
        Persian => "fa", "Persian",
        Finnish => "fi", "Finnish",
        French => "fr", "French",
        Hebrew => "he", "Hebrew",
        Hindi => "hi", "Hindi",
        Hungarian => "hu", "Hungarian",
        Indonesian => "id", "Indonesian",
        Italian => "it", "Italian",
        Japanese => "ja", "Japanese",
        Korean => "ko", "Korean",
        Dutch => "nl", "Dutch",
        Norwegian => "no", "Norwegian",
        Polish => "pl", "Polish",
        Portuguese => "pt", "Portuguese",
        Romanian => "ro", "Romanian",
        Russian => "ru", "Russian",
        Swedish => "sv", "Swedish",
        Thai => "th", "Thai",
        Turkish => "tr", "Turkish",
        Ukrainian => "uk", "Ukrainian",
        Vietnamese => "vi", "Vietnamese",
        Chinese => "zh", "Chinese",
    }
}

geo_enum! {
    /// A writing system, keyed by its ISO 15924 four-letter code.
    pub enum Script / ScriptRef {
        Arabic => "Arab", "Arabic",
        Cyrillic => "Cyrl", "Cyrillic",
        Devanagari => "Deva", "Devanagari",
        Greek => "Grek", "Greek",
        HanSimplified => "Hans", "Han (Simplified)",
        HanTraditional => "Hant", "Han (Traditional)",
        Hebrew => "Hebr", "Hebrew",
        Japanese => "Jpan", "Japanese",
        Korean => "Kore", "Korean",
        Latin => "Latn", "Latin",
        Thai => "Thai", "Thai",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_codes() {
        assert_eq!(Language::from_code("pt"), Language::Portuguese);
        assert_eq!(Language::Portuguese.name(), Some("Portuguese"));
        assert_eq!(Language::from_code("xx"), Language::Unknown("xx".into()));
    }

    #[test]
    fn script_codes() {
        assert_eq!(Script::from_code("Hant"), Script::HanTraditional);
        assert_eq!(Script::Latin.code(), "Latn");
    }
}
