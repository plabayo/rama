//! Language identity, keyed by ISO 639-1 two-letter codes (BCP 47 primary
//! language subtags; see [`super::Locale`]).
//!
//! The set is the complete list of ISO 639-1 alpha-2 codes. Each carries its
//! ISO 639-2 alpha-3 (terminologic) code via [`Language::alpha3`], and — for
//! the handful where it differs — the bibliographic code via
//! [`Language::bibliographic`]. Any other code round-trips through `Unknown`.
//!
//! Source (cross-verified): ISO 639-1 / ISO 639-2 (Library of Congress
//! registration authority), via the `iso-codes` dataset.

use super::builder::geo_enum;

impl Language {
    /// Look up a language by its ISO 639-2 / ISO 639-3 alpha-3 code, matching
    /// either the terminologic or the bibliographic form (case-sensitive),
    /// e.g. `"deu"` or `"ger"` for German. Returns `None` if unrecognised.
    #[must_use]
    pub fn from_alpha3(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|l| l.alpha3() == Some(code) || l.bibliographic() == Some(code))
            .cloned()
    }
}

geo_enum! {
    meta LanguageMeta {
        alpha3: Option<&'static str>,
        bibliographic: Option<&'static str>,
    }

    /// A language, keyed by its ISO 639-1 two-letter code.
    pub enum Language / LanguageRef {
        /// Afar (ISO 639-1 `aa`, ISO 639-2 `aar`)
        Afar => "aa", "Afar", { alpha3: Some("aar"), bibliographic: None },
        /// Abkhazian (ISO 639-1 `ab`, ISO 639-2 `abk`)
        Abkhazian => "ab", "Abkhazian", { alpha3: Some("abk"), bibliographic: None },
        /// Avestan (ISO 639-1 `ae`, ISO 639-2 `ave`)
        Avestan => "ae", "Avestan", { alpha3: Some("ave"), bibliographic: None },
        /// Afrikaans (ISO 639-1 `af`, ISO 639-2 `afr`)
        Afrikaans => "af", "Afrikaans", { alpha3: Some("afr"), bibliographic: None },
        /// Akan (ISO 639-1 `ak`, ISO 639-2 `aka`)
        Akan => "ak", "Akan", { alpha3: Some("aka"), bibliographic: None },
        /// Amharic (ISO 639-1 `am`, ISO 639-2 `amh`)
        Amharic => "am", "Amharic", { alpha3: Some("amh"), bibliographic: None },
        /// Aragonese (ISO 639-1 `an`, ISO 639-2 `arg`)
        Aragonese => "an", "Aragonese", { alpha3: Some("arg"), bibliographic: None },
        /// Arabic (ISO 639-1 `ar`, ISO 639-2 `ara`)
        Arabic => "ar", "Arabic", { alpha3: Some("ara"), bibliographic: None },
        /// Assamese (ISO 639-1 `as`, ISO 639-2 `asm`)
        Assamese => "as", "Assamese", { alpha3: Some("asm"), bibliographic: None },
        /// Avaric (ISO 639-1 `av`, ISO 639-2 `ava`)
        Avaric => "av", "Avaric", { alpha3: Some("ava"), bibliographic: None },
        /// Aymara (ISO 639-1 `ay`, ISO 639-2 `aym`)
        Aymara => "ay", "Aymara", { alpha3: Some("aym"), bibliographic: None },
        /// Azerbaijani (ISO 639-1 `az`, ISO 639-2 `aze`)
        Azerbaijani => "az", "Azerbaijani", { alpha3: Some("aze"), bibliographic: None },
        /// Bashkir (ISO 639-1 `ba`, ISO 639-2 `bak`)
        Bashkir => "ba", "Bashkir", { alpha3: Some("bak"), bibliographic: None },
        /// Belarusian (ISO 639-1 `be`, ISO 639-2 `bel`)
        Belarusian => "be", "Belarusian", { alpha3: Some("bel"), bibliographic: None },
        /// Bulgarian (ISO 639-1 `bg`, ISO 639-2 `bul`)
        Bulgarian => "bg", "Bulgarian", { alpha3: Some("bul"), bibliographic: None },
        /// Bislama (ISO 639-1 `bi`, ISO 639-2 `bis`)
        Bislama => "bi", "Bislama", { alpha3: Some("bis"), bibliographic: None },
        /// Bambara (ISO 639-1 `bm`, ISO 639-2 `bam`)
        Bambara => "bm", "Bambara", { alpha3: Some("bam"), bibliographic: None },
        /// Bengali (ISO 639-1 `bn`, ISO 639-2 `ben`)
        Bengali => "bn", "Bengali", { alpha3: Some("ben"), bibliographic: None },
        /// Tibetan (ISO 639-1 `bo`, ISO 639-2 `bod`, /B `tib`)
        Tibetan => "bo", "Tibetan", { alpha3: Some("bod"), bibliographic: Some("tib") },
        /// Breton (ISO 639-1 `br`, ISO 639-2 `bre`)
        Breton => "br", "Breton", { alpha3: Some("bre"), bibliographic: None },
        /// Bosnian (ISO 639-1 `bs`, ISO 639-2 `bos`)
        Bosnian => "bs", "Bosnian", { alpha3: Some("bos"), bibliographic: None },
        /// Catalan; Valencian (ISO 639-1 `ca`, ISO 639-2 `cat`)
        Catalan => "ca", "Catalan", { alpha3: Some("cat"), bibliographic: None },
        /// Chechen (ISO 639-1 `ce`, ISO 639-2 `che`)
        Chechen => "ce", "Chechen", { alpha3: Some("che"), bibliographic: None },
        /// Chamorro (ISO 639-1 `ch`, ISO 639-2 `cha`)
        Chamorro => "ch", "Chamorro", { alpha3: Some("cha"), bibliographic: None },
        /// Corsican (ISO 639-1 `co`, ISO 639-2 `cos`)
        Corsican => "co", "Corsican", { alpha3: Some("cos"), bibliographic: None },
        /// Cree (ISO 639-1 `cr`, ISO 639-2 `cre`)
        Cree => "cr", "Cree", { alpha3: Some("cre"), bibliographic: None },
        /// Czech (ISO 639-1 `cs`, ISO 639-2 `ces`, /B `cze`)
        Czech => "cs", "Czech", { alpha3: Some("ces"), bibliographic: Some("cze") },
        /// Church Slavic; Old Slavonic; Church Slavonic; Old Bulgarian; Old Church Slavonic (ISO 639-1 `cu`, ISO 639-2 `chu`)
        ChurchSlavic => "cu", "Church Slavic", { alpha3: Some("chu"), bibliographic: None },
        /// Chuvash (ISO 639-1 `cv`, ISO 639-2 `chv`)
        Chuvash => "cv", "Chuvash", { alpha3: Some("chv"), bibliographic: None },
        /// Welsh (ISO 639-1 `cy`, ISO 639-2 `cym`, /B `wel`)
        Welsh => "cy", "Welsh", { alpha3: Some("cym"), bibliographic: Some("wel") },
        /// Danish (ISO 639-1 `da`, ISO 639-2 `dan`)
        Danish => "da", "Danish", { alpha3: Some("dan"), bibliographic: None },
        /// German (ISO 639-1 `de`, ISO 639-2 `deu`, /B `ger`)
        German => "de", "German", { alpha3: Some("deu"), bibliographic: Some("ger") },
        /// Divehi; Dhivehi; Maldivian (ISO 639-1 `dv`, ISO 639-2 `div`)
        Divehi => "dv", "Divehi", { alpha3: Some("div"), bibliographic: None },
        /// Dzongkha (ISO 639-1 `dz`, ISO 639-2 `dzo`)
        Dzongkha => "dz", "Dzongkha", { alpha3: Some("dzo"), bibliographic: None },
        /// Ewe (ISO 639-1 `ee`, ISO 639-2 `ewe`)
        Ewe => "ee", "Ewe", { alpha3: Some("ewe"), bibliographic: None },
        /// Greek, Modern (1453-) (ISO 639-1 `el`, ISO 639-2 `ell`, /B `gre`)
        Greek => "el", "Greek", { alpha3: Some("ell"), bibliographic: Some("gre") },
        /// English (ISO 639-1 `en`, ISO 639-2 `eng`)
        English => "en", "English", { alpha3: Some("eng"), bibliographic: None },
        /// Esperanto (ISO 639-1 `eo`, ISO 639-2 `epo`)
        Esperanto => "eo", "Esperanto", { alpha3: Some("epo"), bibliographic: None },
        /// Spanish; Castilian (ISO 639-1 `es`, ISO 639-2 `spa`)
        Spanish => "es", "Spanish", { alpha3: Some("spa"), bibliographic: None },
        /// Estonian (ISO 639-1 `et`, ISO 639-2 `est`)
        Estonian => "et", "Estonian", { alpha3: Some("est"), bibliographic: None },
        /// Basque (ISO 639-1 `eu`, ISO 639-2 `eus`, /B `baq`)
        Basque => "eu", "Basque", { alpha3: Some("eus"), bibliographic: Some("baq") },
        /// Persian (ISO 639-1 `fa`, ISO 639-2 `fas`, /B `per`)
        Persian => "fa", "Persian", { alpha3: Some("fas"), bibliographic: Some("per") },
        /// Fulah (ISO 639-1 `ff`, ISO 639-2 `ful`)
        Fulah => "ff", "Fulah", { alpha3: Some("ful"), bibliographic: None },
        /// Finnish (ISO 639-1 `fi`, ISO 639-2 `fin`)
        Finnish => "fi", "Finnish", { alpha3: Some("fin"), bibliographic: None },
        /// Fijian (ISO 639-1 `fj`, ISO 639-2 `fij`)
        Fijian => "fj", "Fijian", { alpha3: Some("fij"), bibliographic: None },
        /// Faroese (ISO 639-1 `fo`, ISO 639-2 `fao`)
        Faroese => "fo", "Faroese", { alpha3: Some("fao"), bibliographic: None },
        /// French (ISO 639-1 `fr`, ISO 639-2 `fra`, /B `fre`)
        French => "fr", "French", { alpha3: Some("fra"), bibliographic: Some("fre") },
        /// Western Frisian (ISO 639-1 `fy`, ISO 639-2 `fry`)
        WesternFrisian => "fy", "Western Frisian", { alpha3: Some("fry"), bibliographic: None },
        /// Irish (ISO 639-1 `ga`, ISO 639-2 `gle`)
        Irish => "ga", "Irish", { alpha3: Some("gle"), bibliographic: None },
        /// Gaelic; Scottish Gaelic (ISO 639-1 `gd`, ISO 639-2 `gla`)
        Gaelic => "gd", "Gaelic", { alpha3: Some("gla"), bibliographic: None },
        /// Galician (ISO 639-1 `gl`, ISO 639-2 `glg`)
        Galician => "gl", "Galician", { alpha3: Some("glg"), bibliographic: None },
        /// Guarani (ISO 639-1 `gn`, ISO 639-2 `grn`)
        Guarani => "gn", "Guarani", { alpha3: Some("grn"), bibliographic: None },
        /// Gujarati (ISO 639-1 `gu`, ISO 639-2 `guj`)
        Gujarati => "gu", "Gujarati", { alpha3: Some("guj"), bibliographic: None },
        /// Manx (ISO 639-1 `gv`, ISO 639-2 `glv`)
        Manx => "gv", "Manx", { alpha3: Some("glv"), bibliographic: None },
        /// Hausa (ISO 639-1 `ha`, ISO 639-2 `hau`)
        Hausa => "ha", "Hausa", { alpha3: Some("hau"), bibliographic: None },
        /// Hebrew (ISO 639-1 `he`, ISO 639-2 `heb`)
        Hebrew => "he", "Hebrew", { alpha3: Some("heb"), bibliographic: None },
        /// Hindi (ISO 639-1 `hi`, ISO 639-2 `hin`)
        Hindi => "hi", "Hindi", { alpha3: Some("hin"), bibliographic: None },
        /// Hiri Motu (ISO 639-1 `ho`, ISO 639-2 `hmo`)
        HiriMotu => "ho", "Hiri Motu", { alpha3: Some("hmo"), bibliographic: None },
        /// Croatian (ISO 639-1 `hr`, ISO 639-2 `hrv`)
        Croatian => "hr", "Croatian", { alpha3: Some("hrv"), bibliographic: None },
        /// Haitian; Haitian Creole (ISO 639-1 `ht`, ISO 639-2 `hat`)
        Haitian => "ht", "Haitian", { alpha3: Some("hat"), bibliographic: None },
        /// Hungarian (ISO 639-1 `hu`, ISO 639-2 `hun`)
        Hungarian => "hu", "Hungarian", { alpha3: Some("hun"), bibliographic: None },
        /// Armenian (ISO 639-1 `hy`, ISO 639-2 `hye`, /B `arm`)
        Armenian => "hy", "Armenian", { alpha3: Some("hye"), bibliographic: Some("arm") },
        /// Herero (ISO 639-1 `hz`, ISO 639-2 `her`)
        Herero => "hz", "Herero", { alpha3: Some("her"), bibliographic: None },
        /// Interlingua (International Auxiliary Language Association) (ISO 639-1 `ia`, ISO 639-2 `ina`)
        Interlingua => "ia", "Interlingua", { alpha3: Some("ina"), bibliographic: None },
        /// Indonesian (ISO 639-1 `id`, ISO 639-2 `ind`)
        Indonesian => "id", "Indonesian", { alpha3: Some("ind"), bibliographic: None },
        /// Interlingue; Occidental (ISO 639-1 `ie`, ISO 639-2 `ile`)
        Interlingue => "ie", "Interlingue", { alpha3: Some("ile"), bibliographic: None },
        /// Igbo (ISO 639-1 `ig`, ISO 639-2 `ibo`)
        Igbo => "ig", "Igbo", { alpha3: Some("ibo"), bibliographic: None },
        /// Sichuan Yi; Nuosu (ISO 639-1 `ii`, ISO 639-2 `iii`)
        SichuanYi => "ii", "Sichuan Yi", { alpha3: Some("iii"), bibliographic: None },
        /// Inupiaq (ISO 639-1 `ik`, ISO 639-2 `ipk`)
        Inupiaq => "ik", "Inupiaq", { alpha3: Some("ipk"), bibliographic: None },
        /// Ido (ISO 639-1 `io`, ISO 639-2 `ido`)
        Ido => "io", "Ido", { alpha3: Some("ido"), bibliographic: None },
        /// Icelandic (ISO 639-1 `is`, ISO 639-2 `isl`, /B `ice`)
        Icelandic => "is", "Icelandic", { alpha3: Some("isl"), bibliographic: Some("ice") },
        /// Italian (ISO 639-1 `it`, ISO 639-2 `ita`)
        Italian => "it", "Italian", { alpha3: Some("ita"), bibliographic: None },
        /// Inuktitut (ISO 639-1 `iu`, ISO 639-2 `iku`)
        Inuktitut => "iu", "Inuktitut", { alpha3: Some("iku"), bibliographic: None },
        /// Japanese (ISO 639-1 `ja`, ISO 639-2 `jpn`)
        Japanese => "ja", "Japanese", { alpha3: Some("jpn"), bibliographic: None },
        /// Javanese (ISO 639-1 `jv`, ISO 639-2 `jav`)
        Javanese => "jv", "Javanese", { alpha3: Some("jav"), bibliographic: None },
        /// Georgian (ISO 639-1 `ka`, ISO 639-2 `kat`, /B `geo`)
        Georgian => "ka", "Georgian", { alpha3: Some("kat"), bibliographic: Some("geo") },
        /// Kongo (ISO 639-1 `kg`, ISO 639-2 `kon`)
        Kongo => "kg", "Kongo", { alpha3: Some("kon"), bibliographic: None },
        /// Kikuyu; Gikuyu (ISO 639-1 `ki`, ISO 639-2 `kik`)
        Kikuyu => "ki", "Kikuyu", { alpha3: Some("kik"), bibliographic: None },
        /// Kuanyama; Kwanyama (ISO 639-1 `kj`, ISO 639-2 `kua`)
        Kuanyama => "kj", "Kuanyama", { alpha3: Some("kua"), bibliographic: None },
        /// Kazakh (ISO 639-1 `kk`, ISO 639-2 `kaz`)
        Kazakh => "kk", "Kazakh", { alpha3: Some("kaz"), bibliographic: None },
        /// Kalaallisut; Greenlandic (ISO 639-1 `kl`, ISO 639-2 `kal`)
        Kalaallisut => "kl", "Kalaallisut", { alpha3: Some("kal"), bibliographic: None },
        /// Central Khmer (ISO 639-1 `km`, ISO 639-2 `khm`)
        CentralKhmer => "km", "Central Khmer", { alpha3: Some("khm"), bibliographic: None },
        /// Kannada (ISO 639-1 `kn`, ISO 639-2 `kan`)
        Kannada => "kn", "Kannada", { alpha3: Some("kan"), bibliographic: None },
        /// Korean (ISO 639-1 `ko`, ISO 639-2 `kor`)
        Korean => "ko", "Korean", { alpha3: Some("kor"), bibliographic: None },
        /// Kanuri (ISO 639-1 `kr`, ISO 639-2 `kau`)
        Kanuri => "kr", "Kanuri", { alpha3: Some("kau"), bibliographic: None },
        /// Kashmiri (ISO 639-1 `ks`, ISO 639-2 `kas`)
        Kashmiri => "ks", "Kashmiri", { alpha3: Some("kas"), bibliographic: None },
        /// Kurdish (ISO 639-1 `ku`, ISO 639-2 `kur`)
        Kurdish => "ku", "Kurdish", { alpha3: Some("kur"), bibliographic: None },
        /// Komi (ISO 639-1 `kv`, ISO 639-2 `kom`)
        Komi => "kv", "Komi", { alpha3: Some("kom"), bibliographic: None },
        /// Cornish (ISO 639-1 `kw`, ISO 639-2 `cor`)
        Cornish => "kw", "Cornish", { alpha3: Some("cor"), bibliographic: None },
        /// Kirghiz; Kyrgyz (ISO 639-1 `ky`, ISO 639-2 `kir`)
        Kirghiz => "ky", "Kirghiz", { alpha3: Some("kir"), bibliographic: None },
        /// Latin (ISO 639-1 `la`, ISO 639-2 `lat`)
        Latin => "la", "Latin", { alpha3: Some("lat"), bibliographic: None },
        /// Luxembourgish; Letzeburgesch (ISO 639-1 `lb`, ISO 639-2 `ltz`)
        Luxembourgish => "lb", "Luxembourgish", { alpha3: Some("ltz"), bibliographic: None },
        /// Ganda (ISO 639-1 `lg`, ISO 639-2 `lug`)
        Ganda => "lg", "Ganda", { alpha3: Some("lug"), bibliographic: None },
        /// Limburgan; Limburger; Limburgish (ISO 639-1 `li`, ISO 639-2 `lim`)
        Limburgan => "li", "Limburgan", { alpha3: Some("lim"), bibliographic: None },
        /// Lingala (ISO 639-1 `ln`, ISO 639-2 `lin`)
        Lingala => "ln", "Lingala", { alpha3: Some("lin"), bibliographic: None },
        /// Lao (ISO 639-1 `lo`, ISO 639-2 `lao`)
        Lao => "lo", "Lao", { alpha3: Some("lao"), bibliographic: None },
        /// Lithuanian (ISO 639-1 `lt`, ISO 639-2 `lit`)
        Lithuanian => "lt", "Lithuanian", { alpha3: Some("lit"), bibliographic: None },
        /// Luba-Katanga (ISO 639-1 `lu`, ISO 639-2 `lub`)
        LubaKatanga => "lu", "Luba-Katanga", { alpha3: Some("lub"), bibliographic: None },
        /// Latvian (ISO 639-1 `lv`, ISO 639-2 `lav`)
        Latvian => "lv", "Latvian", { alpha3: Some("lav"), bibliographic: None },
        /// Malagasy (ISO 639-1 `mg`, ISO 639-2 `mlg`)
        Malagasy => "mg", "Malagasy", { alpha3: Some("mlg"), bibliographic: None },
        /// Marshallese (ISO 639-1 `mh`, ISO 639-2 `mah`)
        Marshallese => "mh", "Marshallese", { alpha3: Some("mah"), bibliographic: None },
        /// Maori (ISO 639-1 `mi`, ISO 639-2 `mri`, /B `mao`)
        Maori => "mi", "Maori", { alpha3: Some("mri"), bibliographic: Some("mao") },
        /// Macedonian (ISO 639-1 `mk`, ISO 639-2 `mkd`, /B `mac`)
        Macedonian => "mk", "Macedonian", { alpha3: Some("mkd"), bibliographic: Some("mac") },
        /// Malayalam (ISO 639-1 `ml`, ISO 639-2 `mal`)
        Malayalam => "ml", "Malayalam", { alpha3: Some("mal"), bibliographic: None },
        /// Mongolian (ISO 639-1 `mn`, ISO 639-2 `mon`)
        Mongolian => "mn", "Mongolian", { alpha3: Some("mon"), bibliographic: None },
        /// Marathi (ISO 639-1 `mr`, ISO 639-2 `mar`)
        Marathi => "mr", "Marathi", { alpha3: Some("mar"), bibliographic: None },
        /// Malay (ISO 639-1 `ms`, ISO 639-2 `msa`, /B `may`)
        Malay => "ms", "Malay", { alpha3: Some("msa"), bibliographic: Some("may") },
        /// Maltese (ISO 639-1 `mt`, ISO 639-2 `mlt`)
        Maltese => "mt", "Maltese", { alpha3: Some("mlt"), bibliographic: None },
        /// Burmese (ISO 639-1 `my`, ISO 639-2 `mya`, /B `bur`)
        Burmese => "my", "Burmese", { alpha3: Some("mya"), bibliographic: Some("bur") },
        /// Nauru (ISO 639-1 `na`, ISO 639-2 `nau`)
        Nauru => "na", "Nauru", { alpha3: Some("nau"), bibliographic: None },
        /// Norwegian Bokmål (ISO 639-1 `nb`, ISO 639-2 `nob`)
        NorwegianBokmal => "nb", "Norwegian Bokmal", { alpha3: Some("nob"), bibliographic: None },
        /// North Ndebele (ISO 639-1 `nd`, ISO 639-2 `nde`)
        NorthNdebele => "nd", "North Ndebele", { alpha3: Some("nde"), bibliographic: None },
        /// Nepali (ISO 639-1 `ne`, ISO 639-2 `nep`)
        Nepali => "ne", "Nepali", { alpha3: Some("nep"), bibliographic: None },
        /// Ndonga (ISO 639-1 `ng`, ISO 639-2 `ndo`)
        Ndonga => "ng", "Ndonga", { alpha3: Some("ndo"), bibliographic: None },
        /// Dutch; Flemish (ISO 639-1 `nl`, ISO 639-2 `nld`, /B `dut`)
        Dutch => "nl", "Dutch", { alpha3: Some("nld"), bibliographic: Some("dut") },
        /// Norwegian Nynorsk (ISO 639-1 `nn`, ISO 639-2 `nno`)
        NorwegianNynorsk => "nn", "Norwegian Nynorsk", { alpha3: Some("nno"), bibliographic: None },
        /// Norwegian (ISO 639-1 `no`, ISO 639-2 `nor`)
        Norwegian => "no", "Norwegian", { alpha3: Some("nor"), bibliographic: None },
        /// South Ndebele (ISO 639-1 `nr`, ISO 639-2 `nbl`)
        SouthNdebele => "nr", "South Ndebele", { alpha3: Some("nbl"), bibliographic: None },
        /// Navajo; Navaho (ISO 639-1 `nv`, ISO 639-2 `nav`)
        Navajo => "nv", "Navajo", { alpha3: Some("nav"), bibliographic: None },
        /// Chichewa; Chewa; Nyanja (ISO 639-1 `ny`, ISO 639-2 `nya`)
        Chichewa => "ny", "Chichewa", { alpha3: Some("nya"), bibliographic: None },
        /// Occitan (post 1500) (ISO 639-1 `oc`, ISO 639-2 `oci`)
        Occitan => "oc", "Occitan", { alpha3: Some("oci"), bibliographic: None },
        /// Ojibwa (ISO 639-1 `oj`, ISO 639-2 `oji`)
        Ojibwa => "oj", "Ojibwa", { alpha3: Some("oji"), bibliographic: None },
        /// Oromo (ISO 639-1 `om`, ISO 639-2 `orm`)
        Oromo => "om", "Oromo", { alpha3: Some("orm"), bibliographic: None },
        /// Oriya (ISO 639-1 `or`, ISO 639-2 `ori`)
        Oriya => "or", "Oriya", { alpha3: Some("ori"), bibliographic: None },
        /// Ossetian; Ossetic (ISO 639-1 `os`, ISO 639-2 `oss`)
        Ossetian => "os", "Ossetian", { alpha3: Some("oss"), bibliographic: None },
        /// Panjabi; Punjabi (ISO 639-1 `pa`, ISO 639-2 `pan`)
        Panjabi => "pa", "Panjabi", { alpha3: Some("pan"), bibliographic: None },
        /// Pali (ISO 639-1 `pi`, ISO 639-2 `pli`)
        Pali => "pi", "Pali", { alpha3: Some("pli"), bibliographic: None },
        /// Polish (ISO 639-1 `pl`, ISO 639-2 `pol`)
        Polish => "pl", "Polish", { alpha3: Some("pol"), bibliographic: None },
        /// Pushto; Pashto (ISO 639-1 `ps`, ISO 639-2 `pus`)
        Pushto => "ps", "Pushto", { alpha3: Some("pus"), bibliographic: None },
        /// Portuguese (ISO 639-1 `pt`, ISO 639-2 `por`)
        Portuguese => "pt", "Portuguese", { alpha3: Some("por"), bibliographic: None },
        /// Quechua (ISO 639-1 `qu`, ISO 639-2 `que`)
        Quechua => "qu", "Quechua", { alpha3: Some("que"), bibliographic: None },
        /// Romansh (ISO 639-1 `rm`, ISO 639-2 `roh`)
        Romansh => "rm", "Romansh", { alpha3: Some("roh"), bibliographic: None },
        /// Rundi (ISO 639-1 `rn`, ISO 639-2 `run`)
        Rundi => "rn", "Rundi", { alpha3: Some("run"), bibliographic: None },
        /// Romanian; Moldavian; Moldovan (ISO 639-1 `ro`, ISO 639-2 `ron`, /B `rum`)
        Romanian => "ro", "Romanian", { alpha3: Some("ron"), bibliographic: Some("rum") },
        /// Russian (ISO 639-1 `ru`, ISO 639-2 `rus`)
        Russian => "ru", "Russian", { alpha3: Some("rus"), bibliographic: None },
        /// Kinyarwanda (ISO 639-1 `rw`, ISO 639-2 `kin`)
        Kinyarwanda => "rw", "Kinyarwanda", { alpha3: Some("kin"), bibliographic: None },
        /// Sanskrit (ISO 639-1 `sa`, ISO 639-2 `san`)
        Sanskrit => "sa", "Sanskrit", { alpha3: Some("san"), bibliographic: None },
        /// Sardinian (ISO 639-1 `sc`, ISO 639-2 `srd`)
        Sardinian => "sc", "Sardinian", { alpha3: Some("srd"), bibliographic: None },
        /// Sindhi (ISO 639-1 `sd`, ISO 639-2 `snd`)
        Sindhi => "sd", "Sindhi", { alpha3: Some("snd"), bibliographic: None },
        /// Northern Sami (ISO 639-1 `se`, ISO 639-2 `sme`)
        NorthernSami => "se", "Northern Sami", { alpha3: Some("sme"), bibliographic: None },
        /// Sango (ISO 639-1 `sg`, ISO 639-2 `sag`)
        Sango => "sg", "Sango", { alpha3: Some("sag"), bibliographic: None },
        /// Sinhala; Sinhalese (ISO 639-1 `si`, ISO 639-2 `sin`)
        Sinhala => "si", "Sinhala", { alpha3: Some("sin"), bibliographic: None },
        /// Slovak (ISO 639-1 `sk`, ISO 639-2 `slk`, /B `slo`)
        Slovak => "sk", "Slovak", { alpha3: Some("slk"), bibliographic: Some("slo") },
        /// Slovenian (ISO 639-1 `sl`, ISO 639-2 `slv`)
        Slovenian => "sl", "Slovenian", { alpha3: Some("slv"), bibliographic: None },
        /// Samoan (ISO 639-1 `sm`, ISO 639-2 `smo`)
        Samoan => "sm", "Samoan", { alpha3: Some("smo"), bibliographic: None },
        /// Shona (ISO 639-1 `sn`, ISO 639-2 `sna`)
        Shona => "sn", "Shona", { alpha3: Some("sna"), bibliographic: None },
        /// Somali (ISO 639-1 `so`, ISO 639-2 `som`)
        Somali => "so", "Somali", { alpha3: Some("som"), bibliographic: None },
        /// Albanian (ISO 639-1 `sq`, ISO 639-2 `sqi`, /B `alb`)
        Albanian => "sq", "Albanian", { alpha3: Some("sqi"), bibliographic: Some("alb") },
        /// Serbian (ISO 639-1 `sr`, ISO 639-2 `srp`)
        Serbian => "sr", "Serbian", { alpha3: Some("srp"), bibliographic: None },
        /// Swati (ISO 639-1 `ss`, ISO 639-2 `ssw`)
        Swati => "ss", "Swati", { alpha3: Some("ssw"), bibliographic: None },
        /// Sotho, Southern (ISO 639-1 `st`, ISO 639-2 `sot`)
        Sotho => "st", "Sotho", { alpha3: Some("sot"), bibliographic: None },
        /// Sundanese (ISO 639-1 `su`, ISO 639-2 `sun`)
        Sundanese => "su", "Sundanese", { alpha3: Some("sun"), bibliographic: None },
        /// Swedish (ISO 639-1 `sv`, ISO 639-2 `swe`)
        Swedish => "sv", "Swedish", { alpha3: Some("swe"), bibliographic: None },
        /// Swahili (ISO 639-1 `sw`, ISO 639-2 `swa`)
        Swahili => "sw", "Swahili", { alpha3: Some("swa"), bibliographic: None },
        /// Tamil (ISO 639-1 `ta`, ISO 639-2 `tam`)
        Tamil => "ta", "Tamil", { alpha3: Some("tam"), bibliographic: None },
        /// Telugu (ISO 639-1 `te`, ISO 639-2 `tel`)
        Telugu => "te", "Telugu", { alpha3: Some("tel"), bibliographic: None },
        /// Tajik (ISO 639-1 `tg`, ISO 639-2 `tgk`)
        Tajik => "tg", "Tajik", { alpha3: Some("tgk"), bibliographic: None },
        /// Thai (ISO 639-1 `th`, ISO 639-2 `tha`)
        Thai => "th", "Thai", { alpha3: Some("tha"), bibliographic: None },
        /// Tigrinya (ISO 639-1 `ti`, ISO 639-2 `tir`)
        Tigrinya => "ti", "Tigrinya", { alpha3: Some("tir"), bibliographic: None },
        /// Turkmen (ISO 639-1 `tk`, ISO 639-2 `tuk`)
        Turkmen => "tk", "Turkmen", { alpha3: Some("tuk"), bibliographic: None },
        /// Tagalog (ISO 639-1 `tl`, ISO 639-2 `tgl`)
        Tagalog => "tl", "Tagalog", { alpha3: Some("tgl"), bibliographic: None },
        /// Tswana (ISO 639-1 `tn`, ISO 639-2 `tsn`)
        Tswana => "tn", "Tswana", { alpha3: Some("tsn"), bibliographic: None },
        /// Tonga (Tonga Islands) (ISO 639-1 `to`, ISO 639-2 `ton`)
        Tonga => "to", "Tonga", { alpha3: Some("ton"), bibliographic: None },
        /// Turkish (ISO 639-1 `tr`, ISO 639-2 `tur`)
        Turkish => "tr", "Turkish", { alpha3: Some("tur"), bibliographic: None },
        /// Tsonga (ISO 639-1 `ts`, ISO 639-2 `tso`)
        Tsonga => "ts", "Tsonga", { alpha3: Some("tso"), bibliographic: None },
        /// Tatar (ISO 639-1 `tt`, ISO 639-2 `tat`)
        Tatar => "tt", "Tatar", { alpha3: Some("tat"), bibliographic: None },
        /// Twi (ISO 639-1 `tw`, ISO 639-2 `twi`)
        Twi => "tw", "Twi", { alpha3: Some("twi"), bibliographic: None },
        /// Tahitian (ISO 639-1 `ty`, ISO 639-2 `tah`)
        Tahitian => "ty", "Tahitian", { alpha3: Some("tah"), bibliographic: None },
        /// Uighur; Uyghur (ISO 639-1 `ug`, ISO 639-2 `uig`)
        Uighur => "ug", "Uighur", { alpha3: Some("uig"), bibliographic: None },
        /// Ukrainian (ISO 639-1 `uk`, ISO 639-2 `ukr`)
        Ukrainian => "uk", "Ukrainian", { alpha3: Some("ukr"), bibliographic: None },
        /// Urdu (ISO 639-1 `ur`, ISO 639-2 `urd`)
        Urdu => "ur", "Urdu", { alpha3: Some("urd"), bibliographic: None },
        /// Uzbek (ISO 639-1 `uz`, ISO 639-2 `uzb`)
        Uzbek => "uz", "Uzbek", { alpha3: Some("uzb"), bibliographic: None },
        /// Venda (ISO 639-1 `ve`, ISO 639-2 `ven`)
        Venda => "ve", "Venda", { alpha3: Some("ven"), bibliographic: None },
        /// Vietnamese (ISO 639-1 `vi`, ISO 639-2 `vie`)
        Vietnamese => "vi", "Vietnamese", { alpha3: Some("vie"), bibliographic: None },
        /// Volapük (ISO 639-1 `vo`, ISO 639-2 `vol`)
        Volapuk => "vo", "Volapuk", { alpha3: Some("vol"), bibliographic: None },
        /// Walloon (ISO 639-1 `wa`, ISO 639-2 `wln`)
        Walloon => "wa", "Walloon", { alpha3: Some("wln"), bibliographic: None },
        /// Wolof (ISO 639-1 `wo`, ISO 639-2 `wol`)
        Wolof => "wo", "Wolof", { alpha3: Some("wol"), bibliographic: None },
        /// Xhosa (ISO 639-1 `xh`, ISO 639-2 `xho`)
        Xhosa => "xh", "Xhosa", { alpha3: Some("xho"), bibliographic: None },
        /// Yiddish (ISO 639-1 `yi`, ISO 639-2 `yid`)
        Yiddish => "yi", "Yiddish", { alpha3: Some("yid"), bibliographic: None },
        /// Yoruba (ISO 639-1 `yo`, ISO 639-2 `yor`)
        Yoruba => "yo", "Yoruba", { alpha3: Some("yor"), bibliographic: None },
        /// Zhuang; Chuang (ISO 639-1 `za`, ISO 639-2 `zha`)
        Zhuang => "za", "Zhuang", { alpha3: Some("zha"), bibliographic: None },
        /// Chinese (ISO 639-1 `zh`, ISO 639-2 `zho`, /B `chi`)
        Chinese => "zh", "Chinese", { alpha3: Some("zho"), bibliographic: Some("chi") },
        /// Zulu (ISO 639-1 `zu`, ISO 639-2 `zul`)
        Zulu => "zu", "Zulu", { alpha3: Some("zul"), bibliographic: None },
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
    fn alpha3_and_bibliographic() {
        assert_eq!(Language::German.alpha3(), Some("deu"));
        assert_eq!(Language::German.bibliographic(), Some("ger"));
        // most languages have no distinct bibliographic code
        assert_eq!(Language::English.alpha3(), Some("eng"));
        assert_eq!(Language::English.bibliographic(), None);
        assert_eq!(Language::from_code("xx").alpha3(), None);
        assert_eq!(LanguageRef::German.bibliographic(), Some("ger"));
    }

    #[test]
    fn reverse_lookup() {
        assert_eq!(Language::from_alpha3("deu"), Some(Language::German));
        assert_eq!(Language::from_alpha3("ger"), Some(Language::German));
        assert_eq!(Language::from_alpha3("eng"), Some(Language::English));
        assert_eq!(Language::from_alpha3("zzz"), None);
    }

    #[test]
    fn all_codes_roundtrip() {
        // complete ISO 639-1 set
        assert_eq!(Language::ALL.len(), 183);
        for l in Language::ALL {
            assert!(l.is_known());
            assert_eq!(Language::from_code(l.code()), l.clone());
            assert!(l.name().is_some());
            assert!(l.alpha3().is_some(), "{l:?} missing alpha-3");
        }
    }
}
