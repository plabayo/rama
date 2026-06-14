//! Writing-system identity, keyed by ISO 15924 four-letter codes (BCP 47
//! script subtags; see [`super::Locale`]).
//!
//! The set is the complete list of ISO 15924 script codes, including the
//! special `Z*` codes (e.g. `Zyyy` undetermined, `Zzzz` uncoded) and the
//! private-use range endpoints. Each carries its ISO 15924 numeric code via
//! [`Script::numeric`]. Any other code round-trips through `Unknown`.
//!
//! Source (cross-verified): ISO 15924 (Unicode Consortium registration
//! authority), <https://www.unicode.org/iso15924/>.

use super::builder::geo_enum;

impl Script {
    /// Look up a script by its ISO 15924 numeric code, e.g. `215` (Latin).
    /// Returns `None` for an unrecognised code.
    #[must_use]
    pub fn from_numeric(numeric: u16) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|s| s.numeric() == Some(numeric))
            .cloned()
    }
}

geo_enum! {
    meta ScriptMeta {
        numeric: Option<u16>,
    }

    /// A writing system, keyed by its ISO 15924 four-letter code.
    pub enum Script / ScriptRef {
        /// Adlam (ISO 15924 `Adlm`, numeric `166`)
        Adlam => "Adlm", "Adlam", { numeric: Some(166) },
        /// Afaka (ISO 15924 `Afak`, numeric `439`)
        Afaka => "Afak", "Afaka", { numeric: Some(439) },
        /// Caucasian Albanian (ISO 15924 `Aghb`, numeric `239`)
        CaucasianAlbanian => "Aghb", "Caucasian Albanian", { numeric: Some(239) },
        /// Ahom, Tai Ahom (ISO 15924 `Ahom`, numeric `338`)
        Ahom => "Ahom", "Ahom", { numeric: Some(338) },
        /// Arabic (ISO 15924 `Arab`, numeric `160`)
        Arabic => "Arab", "Arabic", { numeric: Some(160) },
        /// Arabic (Nastaliq variant) (ISO 15924 `Aran`, numeric `161`)
        ArabicNastaliq => "Aran", "Arabic (Nastaliq variant)", { numeric: Some(161) },
        /// Imperial Aramaic (ISO 15924 `Armi`, numeric `124`)
        ImperialAramaic => "Armi", "Imperial Aramaic", { numeric: Some(124) },
        /// Armenian (ISO 15924 `Armn`, numeric `230`)
        Armenian => "Armn", "Armenian", { numeric: Some(230) },
        /// Avestan (ISO 15924 `Avst`, numeric `134`)
        Avestan => "Avst", "Avestan", { numeric: Some(134) },
        /// Balinese (ISO 15924 `Bali`, numeric `360`)
        Balinese => "Bali", "Balinese", { numeric: Some(360) },
        /// Bamum (ISO 15924 `Bamu`, numeric `435`)
        Bamum => "Bamu", "Bamum", { numeric: Some(435) },
        /// Bassa Vah (ISO 15924 `Bass`, numeric `259`)
        BassaVah => "Bass", "Bassa Vah", { numeric: Some(259) },
        /// Batak (ISO 15924 `Batk`, numeric `365`)
        Batak => "Batk", "Batak", { numeric: Some(365) },
        /// Bengali (Bangla) (ISO 15924 `Beng`, numeric `325`)
        Bengali => "Beng", "Bengali (Bangla)", { numeric: Some(325) },
        /// Beria Erfe (ISO 15924 `Berf`, numeric `258`)
        BeriaErfe => "Berf", "Beria Erfe", { numeric: Some(258) },
        /// Bhaiksuki (ISO 15924 `Bhks`, numeric `334`)
        Bhaiksuki => "Bhks", "Bhaiksuki", { numeric: Some(334) },
        /// Blissymbols (ISO 15924 `Blis`, numeric `550`)
        Blissymbols => "Blis", "Blissymbols", { numeric: Some(550) },
        /// Bopomofo (ISO 15924 `Bopo`, numeric `285`)
        Bopomofo => "Bopo", "Bopomofo", { numeric: Some(285) },
        /// Brahmi (ISO 15924 `Brah`, numeric `300`)
        Brahmi => "Brah", "Brahmi", { numeric: Some(300) },
        /// Braille (ISO 15924 `Brai`, numeric `570`)
        Braille => "Brai", "Braille", { numeric: Some(570) },
        /// Buginese (ISO 15924 `Bugi`, numeric `367`)
        Buginese => "Bugi", "Buginese", { numeric: Some(367) },
        /// Buhid (ISO 15924 `Buhd`, numeric `372`)
        Buhid => "Buhd", "Buhid", { numeric: Some(372) },
        /// Chakma (ISO 15924 `Cakm`, numeric `349`)
        Chakma => "Cakm", "Chakma", { numeric: Some(349) },
        /// Unified Canadian Aboriginal Syllabics (ISO 15924 `Cans`, numeric `440`)
        UnifiedCanadianAboriginalSyllabics => "Cans", "Unified Canadian Aboriginal Syllabics", { numeric: Some(440) },
        /// Carian (ISO 15924 `Cari`, numeric `201`)
        Carian => "Cari", "Carian", { numeric: Some(201) },
        /// Cham (ISO 15924 `Cham`, numeric `358`)
        Cham => "Cham", "Cham", { numeric: Some(358) },
        /// Cherokee (ISO 15924 `Cher`, numeric `445`)
        Cherokee => "Cher", "Cherokee", { numeric: Some(445) },
        /// Chisoi (ISO 15924 `Chis`, numeric `298`)
        Chisoi => "Chis", "Chisoi", { numeric: Some(298) },
        /// Chorasmian (ISO 15924 `Chrs`, numeric `109`)
        Chorasmian => "Chrs", "Chorasmian", { numeric: Some(109) },
        /// Cirth (ISO 15924 `Cirt`, numeric `291`)
        Cirth => "Cirt", "Cirth", { numeric: Some(291) },
        /// Coptic (ISO 15924 `Copt`, numeric `204`)
        Coptic => "Copt", "Coptic", { numeric: Some(204) },
        /// Cypro-Minoan (ISO 15924 `Cpmn`, numeric `402`)
        CyproMinoan => "Cpmn", "Cypro-Minoan", { numeric: Some(402) },
        /// Cypriot syllabary (ISO 15924 `Cprt`, numeric `403`)
        CypriotSyllabary => "Cprt", "Cypriot syllabary", { numeric: Some(403) },
        /// Cyrillic (ISO 15924 `Cyrl`, numeric `220`)
        Cyrillic => "Cyrl", "Cyrillic", { numeric: Some(220) },
        /// Cyrillic (Old Church Slavonic variant) (ISO 15924 `Cyrs`, numeric `221`)
        CyrillicOldChurchSlavonic => "Cyrs", "Cyrillic (Old Church Slavonic variant)", { numeric: Some(221) },
        /// Devanagari (Nagari) (ISO 15924 `Deva`, numeric `315`)
        Devanagari => "Deva", "Devanagari (Nagari)", { numeric: Some(315) },
        /// Dives Akuru (ISO 15924 `Diak`, numeric `342`)
        DivesAkuru => "Diak", "Dives Akuru", { numeric: Some(342) },
        /// Dogra (ISO 15924 `Dogr`, numeric `328`)
        Dogra => "Dogr", "Dogra", { numeric: Some(328) },
        /// Deseret (Mormon) (ISO 15924 `Dsrt`, numeric `250`)
        Deseret => "Dsrt", "Deseret (Mormon)", { numeric: Some(250) },
        /// Duployan shorthand, Duployan stenography (ISO 15924 `Dupl`, numeric `755`)
        DuployanShorthand => "Dupl", "Duployan shorthand", { numeric: Some(755) },
        /// Egyptian demotic (ISO 15924 `Egyd`, numeric `070`)
        EgyptianDemotic => "Egyd", "Egyptian demotic", { numeric: Some(70) },
        /// Egyptian hieratic (ISO 15924 `Egyh`, numeric `060`)
        EgyptianHieratic => "Egyh", "Egyptian hieratic", { numeric: Some(60) },
        /// Egyptian hieroglyphs (ISO 15924 `Egyp`, numeric `050`)
        EgyptianHieroglyphs => "Egyp", "Egyptian hieroglyphs", { numeric: Some(50) },
        /// Elbasan (ISO 15924 `Elba`, numeric `226`)
        Elbasan => "Elba", "Elbasan", { numeric: Some(226) },
        /// Elymaic (ISO 15924 `Elym`, numeric `128`)
        Elymaic => "Elym", "Elymaic", { numeric: Some(128) },
        /// Ethiopic (Geʻez) (ISO 15924 `Ethi`, numeric `430`)
        Ethiopic => "Ethi", "Ethiopic (Geʻez)", { numeric: Some(430) },
        /// Garay (ISO 15924 `Gara`, numeric `164`)
        Garay => "Gara", "Garay", { numeric: Some(164) },
        /// Khutsuri (Asomtavruli and Nuskhuri) (ISO 15924 `Geok`, numeric `241`)
        Khutsuri => "Geok", "Khutsuri (Asomtavruli and Nuskhuri)", { numeric: Some(241) },
        /// Georgian (Mkhedruli and Mtavruli) (ISO 15924 `Geor`, numeric `240`)
        Georgian => "Geor", "Georgian (Mkhedruli and Mtavruli)", { numeric: Some(240) },
        /// Glagolitic (ISO 15924 `Glag`, numeric `225`)
        Glagolitic => "Glag", "Glagolitic", { numeric: Some(225) },
        /// Gunjala Gondi (ISO 15924 `Gong`, numeric `312`)
        GunjalaGondi => "Gong", "Gunjala Gondi", { numeric: Some(312) },
        /// Masaram Gondi (ISO 15924 `Gonm`, numeric `313`)
        MasaramGondi => "Gonm", "Masaram Gondi", { numeric: Some(313) },
        /// Gothic (ISO 15924 `Goth`, numeric `206`)
        Gothic => "Goth", "Gothic", { numeric: Some(206) },
        /// Grantha (ISO 15924 `Gran`, numeric `343`)
        Grantha => "Gran", "Grantha", { numeric: Some(343) },
        /// Greek (ISO 15924 `Grek`, numeric `200`)
        Greek => "Grek", "Greek", { numeric: Some(200) },
        /// Gujarati (ISO 15924 `Gujr`, numeric `320`)
        Gujarati => "Gujr", "Gujarati", { numeric: Some(320) },
        /// Gurung Khema (ISO 15924 `Gukh`, numeric `397`)
        GurungKhema => "Gukh", "Gurung Khema", { numeric: Some(397) },
        /// Gurmukhi (ISO 15924 `Guru`, numeric `310`)
        Gurmukhi => "Guru", "Gurmukhi", { numeric: Some(310) },
        /// Han with Bopomofo (alias for Han + Bopomofo) (ISO 15924 `Hanb`, numeric `503`)
        HanWithBopomofo => "Hanb", "Han with Bopomofo", { numeric: Some(503) },
        /// Hangul (Hangŭl, Hangeul) (ISO 15924 `Hang`, numeric `286`)
        Hangul => "Hang", "Hangul (Hangul, Hangeul)", { numeric: Some(286) },
        /// Han (Hanzi, Kanji, Hanja) (ISO 15924 `Hani`, numeric `500`)
        Han => "Hani", "Han (Hanzi, Kanji, Hanja)", { numeric: Some(500) },
        /// Hanunoo (Hanunóo) (ISO 15924 `Hano`, numeric `371`)
        Hanunoo => "Hano", "Hanunoo (Hanunoo)", { numeric: Some(371) },
        /// Han (Simplified variant) (ISO 15924 `Hans`, numeric `501`)
        HanSimplified => "Hans", "Han (Simplified variant)", { numeric: Some(501) },
        /// Han (Traditional variant) (ISO 15924 `Hant`, numeric `502`)
        HanTraditional => "Hant", "Han (Traditional variant)", { numeric: Some(502) },
        /// Hatran (ISO 15924 `Hatr`, numeric `127`)
        Hatran => "Hatr", "Hatran", { numeric: Some(127) },
        /// Hebrew (ISO 15924 `Hebr`, numeric `125`)
        Hebrew => "Hebr", "Hebrew", { numeric: Some(125) },
        /// Hiragana (ISO 15924 `Hira`, numeric `410`)
        Hiragana => "Hira", "Hiragana", { numeric: Some(410) },
        /// Anatolian Hieroglyphs (Luwian Hieroglyphs, Hittite Hieroglyphs) (ISO 15924 `Hluw`, numeric `080`)
        AnatolianHieroglyphs => "Hluw", "Anatolian Hieroglyphs (Luwian Hieroglyphs, Hittite Hieroglyphs)", { numeric: Some(80) },
        /// Pahawh Hmong (ISO 15924 `Hmng`, numeric `450`)
        PahawhHmong => "Hmng", "Pahawh Hmong", { numeric: Some(450) },
        /// Nyiakeng Puachue Hmong (ISO 15924 `Hmnp`, numeric `451`)
        NyiakengPuachueHmong => "Hmnp", "Nyiakeng Puachue Hmong", { numeric: Some(451) },
        /// Han (Traditional variant) with Latin (alias for Hant + Latn) (ISO 15924 `Hntl`, numeric `504`)
        HanWithLatin => "Hntl", "Han (Traditional variant) with Latin", { numeric: Some(504) },
        /// Japanese syllabaries (alias for Hiragana + Katakana) (ISO 15924 `Hrkt`, numeric `412`)
        JapaneseSyllabaries => "Hrkt", "Japanese syllabaries", { numeric: Some(412) },
        /// Old Hungarian (Hungarian Runic) (ISO 15924 `Hung`, numeric `176`)
        OldHungarian => "Hung", "Old Hungarian (Hungarian Runic)", { numeric: Some(176) },
        /// Indus (Harappan) (ISO 15924 `Inds`, numeric `610`)
        Indus => "Inds", "Indus (Harappan)", { numeric: Some(610) },
        /// Old Italic (Etruscan, Oscan, etc.) (ISO 15924 `Ital`, numeric `210`)
        OldItalic => "Ital", "Old Italic (Etruscan, Oscan, etc.)", { numeric: Some(210) },
        /// Jamo (alias for Jamo subset of Hangul) (ISO 15924 `Jamo`, numeric `284`)
        Jamo => "Jamo", "Jamo", { numeric: Some(284) },
        /// Javanese (ISO 15924 `Java`, numeric `361`)
        Javanese => "Java", "Javanese", { numeric: Some(361) },
        /// Japanese (alias for Han + Hiragana + Katakana) (ISO 15924 `Jpan`, numeric `413`)
        Japanese => "Jpan", "Japanese", { numeric: Some(413) },
        /// Jurchen (ISO 15924 `Jurc`, numeric `510`)
        Jurchen => "Jurc", "Jurchen", { numeric: Some(510) },
        /// Kayah Li (ISO 15924 `Kali`, numeric `357`)
        KayahLi => "Kali", "Kayah Li", { numeric: Some(357) },
        /// Katakana (ISO 15924 `Kana`, numeric `411`)
        Katakana => "Kana", "Katakana", { numeric: Some(411) },
        /// Kawi (ISO 15924 `Kawi`, numeric `368`)
        Kawi => "Kawi", "Kawi", { numeric: Some(368) },
        /// Kharoshthi (ISO 15924 `Khar`, numeric `305`)
        Kharoshthi => "Khar", "Kharoshthi", { numeric: Some(305) },
        /// Khmer (ISO 15924 `Khmr`, numeric `355`)
        Khmer => "Khmr", "Khmer", { numeric: Some(355) },
        /// Khojki (ISO 15924 `Khoj`, numeric `322`)
        Khojki => "Khoj", "Khojki", { numeric: Some(322) },
        /// Khitan large script (ISO 15924 `Kitl`, numeric `505`)
        KhitanLargeScript => "Kitl", "Khitan large script", { numeric: Some(505) },
        /// Khitan small script (ISO 15924 `Kits`, numeric `288`)
        KhitanSmallScript => "Kits", "Khitan small script", { numeric: Some(288) },
        /// Kannada (ISO 15924 `Knda`, numeric `345`)
        Kannada => "Knda", "Kannada", { numeric: Some(345) },
        /// Korean (alias for Hangul + Han) (ISO 15924 `Kore`, numeric `287`)
        Korean => "Kore", "Korean", { numeric: Some(287) },
        /// Kpelle (ISO 15924 `Kpel`, numeric `436`)
        Kpelle => "Kpel", "Kpelle", { numeric: Some(436) },
        /// Kirat Rai (ISO 15924 `Krai`, numeric `396`)
        KiratRai => "Krai", "Kirat Rai", { numeric: Some(396) },
        /// Kaithi (ISO 15924 `Kthi`, numeric `317`)
        Kaithi => "Kthi", "Kaithi", { numeric: Some(317) },
        /// Tai Tham (Lanna) (ISO 15924 `Lana`, numeric `351`)
        TaiTham => "Lana", "Tai Tham (Lanna)", { numeric: Some(351) },
        /// Lao (ISO 15924 `Laoo`, numeric `356`)
        Lao => "Laoo", "Lao", { numeric: Some(356) },
        /// Latin (Fraktur variant) (ISO 15924 `Latf`, numeric `217`)
        LatinFraktur => "Latf", "Latin (Fraktur variant)", { numeric: Some(217) },
        /// Latin (Gaelic variant) (ISO 15924 `Latg`, numeric `216`)
        LatinGaelic => "Latg", "Latin (Gaelic variant)", { numeric: Some(216) },
        /// Latin (ISO 15924 `Latn`, numeric `215`)
        Latin => "Latn", "Latin", { numeric: Some(215) },
        /// Leke (ISO 15924 `Leke`, numeric `364`)
        Leke => "Leke", "Leke", { numeric: Some(364) },
        /// Lepcha (Róng) (ISO 15924 `Lepc`, numeric `335`)
        Lepcha => "Lepc", "Lepcha (Rong)", { numeric: Some(335) },
        /// Limbu (ISO 15924 `Limb`, numeric `336`)
        Limbu => "Limb", "Limbu", { numeric: Some(336) },
        /// Linear A (ISO 15924 `Lina`, numeric `400`)
        LinearA => "Lina", "Linear A", { numeric: Some(400) },
        /// Linear B (ISO 15924 `Linb`, numeric `401`)
        LinearB => "Linb", "Linear B", { numeric: Some(401) },
        /// Lisu (Fraser) (ISO 15924 `Lisu`, numeric `399`)
        Lisu => "Lisu", "Lisu (Fraser)", { numeric: Some(399) },
        /// Loma (ISO 15924 `Loma`, numeric `437`)
        Loma => "Loma", "Loma", { numeric: Some(437) },
        /// Lycian (ISO 15924 `Lyci`, numeric `202`)
        Lycian => "Lyci", "Lycian", { numeric: Some(202) },
        /// Lydian (ISO 15924 `Lydi`, numeric `116`)
        Lydian => "Lydi", "Lydian", { numeric: Some(116) },
        /// Mahajani (ISO 15924 `Mahj`, numeric `314`)
        Mahajani => "Mahj", "Mahajani", { numeric: Some(314) },
        /// Makasar (ISO 15924 `Maka`, numeric `366`)
        Makasar => "Maka", "Makasar", { numeric: Some(366) },
        /// Mandaic, Mandaean (ISO 15924 `Mand`, numeric `140`)
        Mandaic => "Mand", "Mandaic", { numeric: Some(140) },
        /// Manichaean (ISO 15924 `Mani`, numeric `139`)
        Manichaean => "Mani", "Manichaean", { numeric: Some(139) },
        /// Marchen (ISO 15924 `Marc`, numeric `332`)
        Marchen => "Marc", "Marchen", { numeric: Some(332) },
        /// Mayan hieroglyphs (ISO 15924 `Maya`, numeric `090`)
        MayanHieroglyphs => "Maya", "Mayan hieroglyphs", { numeric: Some(90) },
        /// Medefaidrin (Oberi Okaime, Oberi Ɔkaimɛ) (ISO 15924 `Medf`, numeric `265`)
        Medefaidrin => "Medf", "Medefaidrin (Oberi Okaime, Oberi Ɔkaimɛ)", { numeric: Some(265) },
        /// Mende Kikakui (ISO 15924 `Mend`, numeric `438`)
        MendeKikakui => "Mend", "Mende Kikakui", { numeric: Some(438) },
        /// Meroitic Cursive (ISO 15924 `Merc`, numeric `101`)
        MeroiticCursive => "Merc", "Meroitic Cursive", { numeric: Some(101) },
        /// Meroitic Hieroglyphs (ISO 15924 `Mero`, numeric `100`)
        MeroiticHieroglyphs => "Mero", "Meroitic Hieroglyphs", { numeric: Some(100) },
        /// Malayalam (ISO 15924 `Mlym`, numeric `347`)
        Malayalam => "Mlym", "Malayalam", { numeric: Some(347) },
        /// Modi, Moḍī (ISO 15924 `Modi`, numeric `324`)
        Modi => "Modi", "Modi", { numeric: Some(324) },
        /// Mongolian (ISO 15924 `Mong`, numeric `145`)
        Mongolian => "Mong", "Mongolian", { numeric: Some(145) },
        /// Moon (Moon code, Moon script, Moon type) (ISO 15924 `Moon`, numeric `218`)
        Moon => "Moon", "Moon (Moon code, Moon script, Moon type)", { numeric: Some(218) },
        /// Mro, Mru (ISO 15924 `Mroo`, numeric `264`)
        Mro => "Mroo", "Mro", { numeric: Some(264) },
        /// Meitei Mayek (Meithei, Meetei) (ISO 15924 `Mtei`, numeric `337`)
        MeiteiMayek => "Mtei", "Meitei Mayek (Meithei, Meetei)", { numeric: Some(337) },
        /// Multani (ISO 15924 `Mult`, numeric `323`)
        Multani => "Mult", "Multani", { numeric: Some(323) },
        /// Myanmar (Burmese) (ISO 15924 `Mymr`, numeric `350`)
        Myanmar => "Mymr", "Myanmar (Burmese)", { numeric: Some(350) },
        /// Nag Mundari (ISO 15924 `Nagm`, numeric `295`)
        NagMundari => "Nagm", "Nag Mundari", { numeric: Some(295) },
        /// Nandinagari (ISO 15924 `Nand`, numeric `311`)
        Nandinagari => "Nand", "Nandinagari", { numeric: Some(311) },
        /// Old North Arabian (Ancient North Arabian) (ISO 15924 `Narb`, numeric `106`)
        OldNorthArabian => "Narb", "Old North Arabian (Ancient North Arabian)", { numeric: Some(106) },
        /// Nabataean (ISO 15924 `Nbat`, numeric `159`)
        Nabataean => "Nbat", "Nabataean", { numeric: Some(159) },
        /// Newa, Newar, Newari, Nepāla lipi (ISO 15924 `Newa`, numeric `333`)
        Newa => "Newa", "Newa", { numeric: Some(333) },
        /// Naxi Dongba (na²¹ɕi³³ to³³ba²¹, Nakhi Tomba) (ISO 15924 `Nkdb`, numeric `085`)
        NaxiDongba => "Nkdb", "Naxi Dongba (na21ɕi33 to33ba21, Nakhi Tomba)", { numeric: Some(85) },
        /// Naxi Geba (na²¹ɕi³³ gʌ²¹ba²¹, 'Na-'Khi ²Ggŏ-¹baw, Nakhi Geba) (ISO 15924 `Nkgb`, numeric `420`)
        NaxiGeba => "Nkgb", "Naxi Geba (na21ɕi33 gʌ21ba21, 'Na-'Khi 2Ggo-1baw, Nakhi Geba)", { numeric: Some(420) },
        /// N’Ko (ISO 15924 `Nkoo`, numeric `165`)
        NKo => "Nkoo", "N’Ko", { numeric: Some(165) },
        /// Nüshu (ISO 15924 `Nshu`, numeric `499`)
        Nushu => "Nshu", "Nushu", { numeric: Some(499) },
        /// Ogham (ISO 15924 `Ogam`, numeric `212`)
        Ogham => "Ogam", "Ogham", { numeric: Some(212) },
        /// Ol Chiki (Ol Cemet’, Ol, Santali) (ISO 15924 `Olck`, numeric `261`)
        OlChiki => "Olck", "Ol Chiki (Ol Cemet’, Ol, Santali)", { numeric: Some(261) },
        /// Ol Onal (ISO 15924 `Onao`, numeric `296`)
        OlOnal => "Onao", "Ol Onal", { numeric: Some(296) },
        /// Old Turkic, Orkhon Runic (ISO 15924 `Orkh`, numeric `175`)
        OldTurkic => "Orkh", "Old Turkic", { numeric: Some(175) },
        /// Oriya (Odia) (ISO 15924 `Orya`, numeric `327`)
        Oriya => "Orya", "Oriya (Odia)", { numeric: Some(327) },
        /// Osage (ISO 15924 `Osge`, numeric `219`)
        Osage => "Osge", "Osage", { numeric: Some(219) },
        /// Osmanya (ISO 15924 `Osma`, numeric `260`)
        Osmanya => "Osma", "Osmanya", { numeric: Some(260) },
        /// Old Uyghur (ISO 15924 `Ougr`, numeric `143`)
        OldUyghur => "Ougr", "Old Uyghur", { numeric: Some(143) },
        /// Palmyrene (ISO 15924 `Palm`, numeric `126`)
        Palmyrene => "Palm", "Palmyrene", { numeric: Some(126) },
        /// Pau Cin Hau (ISO 15924 `Pauc`, numeric `263`)
        PauCinHau => "Pauc", "Pau Cin Hau", { numeric: Some(263) },
        /// Proto-Cuneiform (ISO 15924 `Pcun`, numeric `015`)
        ProtoCuneiform => "Pcun", "Proto-Cuneiform", { numeric: Some(15) },
        /// Proto-Elamite (ISO 15924 `Pelm`, numeric `016`)
        ProtoElamite => "Pelm", "Proto-Elamite", { numeric: Some(16) },
        /// Old Permic (ISO 15924 `Perm`, numeric `227`)
        OldPermic => "Perm", "Old Permic", { numeric: Some(227) },
        /// Phags-pa (ISO 15924 `Phag`, numeric `331`)
        PhagsPa => "Phag", "Phags-pa", { numeric: Some(331) },
        /// Inscriptional Pahlavi (ISO 15924 `Phli`, numeric `131`)
        InscriptionalPahlavi => "Phli", "Inscriptional Pahlavi", { numeric: Some(131) },
        /// Psalter Pahlavi (ISO 15924 `Phlp`, numeric `132`)
        PsalterPahlavi => "Phlp", "Psalter Pahlavi", { numeric: Some(132) },
        /// Book Pahlavi (ISO 15924 `Phlv`, numeric `133`)
        BookPahlavi => "Phlv", "Book Pahlavi", { numeric: Some(133) },
        /// Phoenician (ISO 15924 `Phnx`, numeric `115`)
        Phoenician => "Phnx", "Phoenician", { numeric: Some(115) },
        /// Klingon (KLI pIqaD) (ISO 15924 `Piqd`, numeric `293`)
        Klingon => "Piqd", "Klingon (KLI pIqaD)", { numeric: Some(293) },
        /// Miao (Pollard) (ISO 15924 `Plrd`, numeric `282`)
        Miao => "Plrd", "Miao (Pollard)", { numeric: Some(282) },
        /// Inscriptional Parthian (ISO 15924 `Prti`, numeric `130`)
        InscriptionalParthian => "Prti", "Inscriptional Parthian", { numeric: Some(130) },
        /// Proto-Sinaitic (ISO 15924 `Psin`, numeric `103`)
        ProtoSinaitic => "Psin", "Proto-Sinaitic", { numeric: Some(103) },
        /// Reserved for private use (start) (ISO 15924 `Qaaa`, numeric `900`)
        PrivateUseStart => "Qaaa", "Reserved for private use (start)", { numeric: Some(900) },
        /// Reserved for private use (end) (ISO 15924 `Qabx`, numeric `949`)
        PrivateUseEnd => "Qabx", "Reserved for private use (end)", { numeric: Some(949) },
        /// Ranjana (ISO 15924 `Ranj`, numeric `303`)
        Ranjana => "Ranj", "Ranjana", { numeric: Some(303) },
        /// Rejang (Redjang, Kaganga) (ISO 15924 `Rjng`, numeric `363`)
        Rejang => "Rjng", "Rejang (Redjang, Kaganga)", { numeric: Some(363) },
        /// Hanifi Rohingya (ISO 15924 `Rohg`, numeric `167`)
        HanifiRohingya => "Rohg", "Hanifi Rohingya", { numeric: Some(167) },
        /// Rongorongo (ISO 15924 `Roro`, numeric `620`)
        Rongorongo => "Roro", "Rongorongo", { numeric: Some(620) },
        /// Runic (ISO 15924 `Runr`, numeric `211`)
        Runic => "Runr", "Runic", { numeric: Some(211) },
        /// Samaritan (ISO 15924 `Samr`, numeric `123`)
        Samaritan => "Samr", "Samaritan", { numeric: Some(123) },
        /// Sarati (ISO 15924 `Sara`, numeric `292`)
        Sarati => "Sara", "Sarati", { numeric: Some(292) },
        /// Old South Arabian (ISO 15924 `Sarb`, numeric `105`)
        OldSouthArabian => "Sarb", "Old South Arabian", { numeric: Some(105) },
        /// Saurashtra (ISO 15924 `Saur`, numeric `344`)
        Saurashtra => "Saur", "Saurashtra", { numeric: Some(344) },
        /// (Small) Seal (ISO 15924 `Seal`, numeric `590`)
        Seal => "Seal", "(Small) Seal", { numeric: Some(590) },
        /// SignWriting (ISO 15924 `Sgnw`, numeric `095`)
        SignWriting => "Sgnw", "SignWriting", { numeric: Some(95) },
        /// Shavian (Shaw) (ISO 15924 `Shaw`, numeric `281`)
        Shavian => "Shaw", "Shavian (Shaw)", { numeric: Some(281) },
        /// Sharada, Śāradā (ISO 15924 `Shrd`, numeric `319`)
        Sharada => "Shrd", "Sharada", { numeric: Some(319) },
        /// Shuishu (ISO 15924 `Shui`, numeric `530`)
        Shuishu => "Shui", "Shuishu", { numeric: Some(530) },
        /// Siddham, Siddhaṃ, Siddhamātṛkā (ISO 15924 `Sidd`, numeric `302`)
        Siddham => "Sidd", "Siddham", { numeric: Some(302) },
        /// Sidetic (ISO 15924 `Sidt`, numeric `180`)
        Sidetic => "Sidt", "Sidetic", { numeric: Some(180) },
        /// Khudawadi, Sindhi (ISO 15924 `Sind`, numeric `318`)
        Khudawadi => "Sind", "Khudawadi", { numeric: Some(318) },
        /// Sinhala (ISO 15924 `Sinh`, numeric `348`)
        Sinhala => "Sinh", "Sinhala", { numeric: Some(348) },
        /// Sogdian (ISO 15924 `Sogd`, numeric `141`)
        Sogdian => "Sogd", "Sogdian", { numeric: Some(141) },
        /// Old Sogdian (ISO 15924 `Sogo`, numeric `142`)
        OldSogdian => "Sogo", "Old Sogdian", { numeric: Some(142) },
        /// Sora Sompeng (ISO 15924 `Sora`, numeric `398`)
        SoraSompeng => "Sora", "Sora Sompeng", { numeric: Some(398) },
        /// Soyombo (ISO 15924 `Soyo`, numeric `329`)
        Soyombo => "Soyo", "Soyombo", { numeric: Some(329) },
        /// Sundanese (ISO 15924 `Sund`, numeric `362`)
        Sundanese => "Sund", "Sundanese", { numeric: Some(362) },
        /// Sunuwar (ISO 15924 `Sunu`, numeric `274`)
        Sunuwar => "Sunu", "Sunuwar", { numeric: Some(274) },
        /// Syloti Nagri (ISO 15924 `Sylo`, numeric `316`)
        SylotiNagri => "Sylo", "Syloti Nagri", { numeric: Some(316) },
        /// Syriac (ISO 15924 `Syrc`, numeric `135`)
        Syriac => "Syrc", "Syriac", { numeric: Some(135) },
        /// Syriac (Estrangelo variant) (ISO 15924 `Syre`, numeric `138`)
        SyriacEstrangelo => "Syre", "Syriac (Estrangelo variant)", { numeric: Some(138) },
        /// Syriac (Western variant) (ISO 15924 `Syrj`, numeric `137`)
        SyriacWestern => "Syrj", "Syriac (Western variant)", { numeric: Some(137) },
        /// Syriac (Eastern variant) (ISO 15924 `Syrn`, numeric `136`)
        SyriacEastern => "Syrn", "Syriac (Eastern variant)", { numeric: Some(136) },
        /// Tagbanwa (ISO 15924 `Tagb`, numeric `373`)
        Tagbanwa => "Tagb", "Tagbanwa", { numeric: Some(373) },
        /// Takri, Ṭākrī, Ṭāṅkrī (ISO 15924 `Takr`, numeric `321`)
        Takri => "Takr", "Takri", { numeric: Some(321) },
        /// Tai Le (ISO 15924 `Tale`, numeric `353`)
        TaiLe => "Tale", "Tai Le", { numeric: Some(353) },
        /// New Tai Lue (ISO 15924 `Talu`, numeric `354`)
        NewTaiLue => "Talu", "New Tai Lue", { numeric: Some(354) },
        /// Tamil (ISO 15924 `Taml`, numeric `346`)
        Tamil => "Taml", "Tamil", { numeric: Some(346) },
        /// Tangut (ISO 15924 `Tang`, numeric `520`)
        Tangut => "Tang", "Tangut", { numeric: Some(520) },
        /// Tai Viet (ISO 15924 `Tavt`, numeric `359`)
        TaiViet => "Tavt", "Tai Viet", { numeric: Some(359) },
        /// Tai Yo (ISO 15924 `Tayo`, numeric `380`)
        TaiYo => "Tayo", "Tai Yo", { numeric: Some(380) },
        /// Telugu (ISO 15924 `Telu`, numeric `340`)
        Telugu => "Telu", "Telugu", { numeric: Some(340) },
        /// Tengwar (ISO 15924 `Teng`, numeric `290`)
        Tengwar => "Teng", "Tengwar", { numeric: Some(290) },
        /// Tifinagh (Berber) (ISO 15924 `Tfng`, numeric `120`)
        Tifinagh => "Tfng", "Tifinagh (Berber)", { numeric: Some(120) },
        /// Tagalog (Baybayin, Alibata) (ISO 15924 `Tglg`, numeric `370`)
        Tagalog => "Tglg", "Tagalog (Baybayin, Alibata)", { numeric: Some(370) },
        /// Thaana (ISO 15924 `Thaa`, numeric `170`)
        Thaana => "Thaa", "Thaana", { numeric: Some(170) },
        /// Thai (ISO 15924 `Thai`, numeric `352`)
        Thai => "Thai", "Thai", { numeric: Some(352) },
        /// Tibetan (ISO 15924 `Tibt`, numeric `330`)
        Tibetan => "Tibt", "Tibetan", { numeric: Some(330) },
        /// Tirhuta (ISO 15924 `Tirh`, numeric `326`)
        Tirhuta => "Tirh", "Tirhuta", { numeric: Some(326) },
        /// Tangsa (ISO 15924 `Tnsa`, numeric `275`)
        Tangsa => "Tnsa", "Tangsa", { numeric: Some(275) },
        /// Todhri (ISO 15924 `Todr`, numeric `229`)
        Todhri => "Todr", "Todhri", { numeric: Some(229) },
        /// Tolong Siki (ISO 15924 `Tols`, numeric `299`)
        TolongSiki => "Tols", "Tolong Siki", { numeric: Some(299) },
        /// Toto (ISO 15924 `Toto`, numeric `294`)
        Toto => "Toto", "Toto", { numeric: Some(294) },
        /// Tulu-Tigalari (ISO 15924 `Tutg`, numeric `341`)
        TuluTigalari => "Tutg", "Tulu-Tigalari", { numeric: Some(341) },
        /// Ugaritic (ISO 15924 `Ugar`, numeric `040`)
        Ugaritic => "Ugar", "Ugaritic", { numeric: Some(40) },
        /// Vai (ISO 15924 `Vaii`, numeric `470`)
        Vai => "Vaii", "Vai", { numeric: Some(470) },
        /// Visible Speech (ISO 15924 `Visp`, numeric `280`)
        VisibleSpeech => "Visp", "Visible Speech", { numeric: Some(280) },
        /// Vithkuqi (ISO 15924 `Vith`, numeric `228`)
        Vithkuqi => "Vith", "Vithkuqi", { numeric: Some(228) },
        /// Warang Citi (Varang Kshiti) (ISO 15924 `Wara`, numeric `262`)
        WarangCiti => "Wara", "Warang Citi (Varang Kshiti)", { numeric: Some(262) },
        /// Wancho (ISO 15924 `Wcho`, numeric `283`)
        Wancho => "Wcho", "Wancho", { numeric: Some(283) },
        /// Woleai (ISO 15924 `Wole`, numeric `480`)
        Woleai => "Wole", "Woleai", { numeric: Some(480) },
        /// Old Persian (ISO 15924 `Xpeo`, numeric `030`)
        OldPersian => "Xpeo", "Old Persian", { numeric: Some(30) },
        /// Cuneiform, Sumero-Akkadian (ISO 15924 `Xsux`, numeric `020`)
        Cuneiform => "Xsux", "Cuneiform", { numeric: Some(20) },
        /// Yezidi (ISO 15924 `Yezi`, numeric `192`)
        Yezidi => "Yezi", "Yezidi", { numeric: Some(192) },
        /// Yi (ISO 15924 `Yiii`, numeric `460`)
        Yi => "Yiii", "Yi", { numeric: Some(460) },
        /// Zanabazar Square (Zanabazarin Dörböljin Useg, Xewtee Dörböljin Bicig, Horizontal Square Script) (ISO 15924 `Zanb`, numeric `339`)
        ZanabazarSquare => "Zanb", "Zanabazar Square (Zanabazarin Dorboljin Useg, Xewtee Dorboljin Bicig, Horizontal Square Script)", { numeric: Some(339) },
        /// Code for inherited script (ISO 15924 `Zinh`, numeric `994`)
        Inherited => "Zinh", "Code for inherited script", { numeric: Some(994) },
        /// Mathematical notation (ISO 15924 `Zmth`, numeric `995`)
        MathematicalNotation => "Zmth", "Mathematical notation", { numeric: Some(995) },
        /// Symbols (Emoji variant) (ISO 15924 `Zsye`, numeric `993`)
        SymbolsEmoji => "Zsye", "Symbols (Emoji variant)", { numeric: Some(993) },
        /// Symbols (ISO 15924 `Zsym`, numeric `996`)
        Symbols => "Zsym", "Symbols", { numeric: Some(996) },
        /// Code for unwritten documents (ISO 15924 `Zxxx`, numeric `997`)
        Unwritten => "Zxxx", "Code for unwritten documents", { numeric: Some(997) },
        /// Code for undetermined script (ISO 15924 `Zyyy`, numeric `998`)
        Undetermined => "Zyyy", "Code for undetermined script", { numeric: Some(998) },
        /// Code for uncoded script (ISO 15924 `Zzzz`, numeric `999`)
        Uncoded => "Zzzz", "Code for uncoded script", { numeric: Some(999) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_codes() {
        assert_eq!(Script::from_code("Hant"), Script::HanTraditional);
        assert_eq!(Script::Latin.code(), "Latn");
        assert_eq!(Script::from_code("Zzzz"), Script::Uncoded);
    }

    #[test]
    fn numeric_codes() {
        assert_eq!(Script::Latin.numeric(), Some(215));
        assert_eq!(Script::Arabic.numeric(), Some(160));
        assert_eq!(Script::from_code("Qqqq").numeric(), None);
        assert_eq!(ScriptRef::Latin.numeric(), Some(215));
    }

    #[test]
    fn reverse_lookup() {
        assert_eq!(Script::from_numeric(215), Some(Script::Latin));
        assert_eq!(Script::from_numeric(160), Some(Script::Arabic));
        assert_eq!(Script::from_numeric(0), None);
    }

    #[test]
    fn all_codes_roundtrip() {
        // complete ISO 15924 set
        assert_eq!(Script::ALL.len(), 226);
        for s in Script::ALL {
            assert!(s.is_known());
            assert_eq!(Script::from_code(s.code()), s.clone());
            assert!(s.name().is_some());
            assert!(s.numeric().is_some(), "{s:?} missing numeric");
        }
    }
}
