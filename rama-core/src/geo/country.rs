//! Country / territory identity, keyed by ISO 3166-1 alpha-2 code.
//!
//! The set below covers every officially-assigned ISO 3166-1 alpha-2 code,
//! plus the commonly-seen user-assigned `XK` (Kosovo) and exceptionally-reserved
//! `EU` (European Union). Any other code round-trips through `Unknown`.
//!
//! rama takes no political stance: contested territories are included purely
//! for completeness of the standard.
//!
//! Source: ISO 3166-1 (ISO 3166 Maintenance Agency); see the ISO Online
//! Browsing Platform <https://www.iso.org/obp/ui/#search>.
//!
//! The owned form encodes identity only (the localised name is not retained);
//! use [`Country::name`] for the English name and [`Country::code`] for the
//! alpha-2 code.

use super::builder::geo_enum;

impl Country {
    /// Whether this country is a current member state of the European Union
    /// (the 27 members as of 2020, post-Brexit).
    ///
    /// This is derived from the country identity rather than read from any
    /// database, so it reflects rama's maintained view of EU membership.
    #[must_use]
    pub fn is_in_eu(&self) -> bool {
        matches!(
            self,
            Self::Austria
                | Self::Belgium
                | Self::Bulgaria
                | Self::Croatia
                | Self::Cyprus
                | Self::CzechRepublic
                | Self::Denmark
                | Self::Estonia
                | Self::Finland
                | Self::France
                | Self::Germany
                | Self::Greece
                | Self::Hungary
                | Self::Ireland
                | Self::Italy
                | Self::Latvia
                | Self::Lithuania
                | Self::Luxembourg
                | Self::Malta
                | Self::Netherlands
                | Self::Poland
                | Self::Portugal
                | Self::Romania
                | Self::Slovakia
                | Self::Slovenia
                | Self::Spain
                | Self::Sweden
        )
    }
    /// Look up a country by its ISO 3166-1 alpha-3 code (case-sensitive),
    /// e.g. `"BEL"`. Returns `None` for an unrecognised code.
    #[must_use]
    pub fn from_alpha3(code: &str) -> Option<Self> {
        Self::ALL.iter().find(|c| c.alpha3() == Some(code)).cloned()
    }

    /// Look up a country by its ISO 3166-1 numeric code, e.g. `56` (Belgium).
    /// Returns `None` for an unrecognised code.
    #[must_use]
    pub fn from_numeric(numeric: u16) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|c| c.numeric() == Some(numeric))
            .cloned()
    }
}

geo_enum! {
    meta CountryMeta {
        alpha3: Option<&'static str>,
        numeric: Option<u16>,
    }

    /// A country or territory, identified by its ISO 3166-1 alpha-2 code.
    pub enum Country / CountryRef {
        /// Andorra (alpha-3 `AND`, numeric `020`)
        Andorra => "AD", "Andorra", { alpha3: Some("AND"), numeric: Some(20) },
        /// United Arab Emirates (the) (alpha-3 `ARE`, numeric `784`)
        UnitedArabEmirates => "AE", "United Arab Emirates", { alpha3: Some("ARE"), numeric: Some(784) },
        /// Afghanistan (alpha-3 `AFG`, numeric `004`)
        Afghanistan => "AF", "Afghanistan", { alpha3: Some("AFG"), numeric: Some(4) },
        /// Antigua and Barbuda (alpha-3 `ATG`, numeric `028`)
        AntiguaAndBarbuda => "AG", "Antigua and Barbuda", { alpha3: Some("ATG"), numeric: Some(28) },
        /// Anguilla (alpha-3 `AIA`, numeric `660`)
        Anguilla => "AI", "Anguilla", { alpha3: Some("AIA"), numeric: Some(660) },
        /// Albania (alpha-3 `ALB`, numeric `008`)
        Albania => "AL", "Albania", { alpha3: Some("ALB"), numeric: Some(8) },
        /// Armenia (alpha-3 `ARM`, numeric `051`)
        Armenia => "AM", "Armenia", { alpha3: Some("ARM"), numeric: Some(51) },
        /// Angola (alpha-3 `AGO`, numeric `024`)
        Angola => "AO", "Angola", { alpha3: Some("AGO"), numeric: Some(24) },
        /// Antarctica (alpha-3 `ATA`, numeric `010`)
        Antarctica => "AQ", "Antarctica", { alpha3: Some("ATA"), numeric: Some(10) },
        /// Argentina (alpha-3 `ARG`, numeric `032`)
        Argentina => "AR", "Argentina", { alpha3: Some("ARG"), numeric: Some(32) },
        /// American Samoa (alpha-3 `ASM`, numeric `016`)
        AmericanSamoa => "AS", "American Samoa", { alpha3: Some("ASM"), numeric: Some(16) },
        /// Austria (alpha-3 `AUT`, numeric `040`)
        Austria => "AT", "Austria", { alpha3: Some("AUT"), numeric: Some(40) },
        /// Australia (alpha-3 `AUS`, numeric `036`)
        Australia => "AU", "Australia", { alpha3: Some("AUS"), numeric: Some(36) },
        /// Aruba (alpha-3 `ABW`, numeric `533`)
        Aruba => "AW", "Aruba", { alpha3: Some("ABW"), numeric: Some(533) },
        /// Åland Islands (alpha-3 `ALA`, numeric `248`)
        AlandIslands => "AX", "Aland Islands", { alpha3: Some("ALA"), numeric: Some(248) },
        /// Azerbaijan (alpha-3 `AZE`, numeric `031`)
        Azerbaijan => "AZ", "Azerbaijan", { alpha3: Some("AZE"), numeric: Some(31) },
        /// Bosnia and Herzegovina (alpha-3 `BIH`, numeric `070`)
        BosniaAndHerzegovina => "BA", "Bosnia and Herzegovina", { alpha3: Some("BIH"), numeric: Some(70) },
        /// Barbados (alpha-3 `BRB`, numeric `052`)
        Barbados => "BB", "Barbados", { alpha3: Some("BRB"), numeric: Some(52) },
        /// Bangladesh (alpha-3 `BGD`, numeric `050`)
        Bangladesh => "BD", "Bangladesh", { alpha3: Some("BGD"), numeric: Some(50) },
        /// Belgium (alpha-3 `BEL`, numeric `056`)
        Belgium => "BE", "Belgium", { alpha3: Some("BEL"), numeric: Some(56) },
        /// Burkina Faso (alpha-3 `BFA`, numeric `854`)
        BurkinaFaso => "BF", "Burkina Faso", { alpha3: Some("BFA"), numeric: Some(854) },
        /// Bulgaria (alpha-3 `BGR`, numeric `100`)
        Bulgaria => "BG", "Bulgaria", { alpha3: Some("BGR"), numeric: Some(100) },
        /// Bahrain (alpha-3 `BHR`, numeric `048`)
        Bahrain => "BH", "Bahrain", { alpha3: Some("BHR"), numeric: Some(48) },
        /// Burundi (alpha-3 `BDI`, numeric `108`)
        Burundi => "BI", "Burundi", { alpha3: Some("BDI"), numeric: Some(108) },
        /// Benin (alpha-3 `BEN`, numeric `204`)
        Benin => "BJ", "Benin", { alpha3: Some("BEN"), numeric: Some(204) },
        /// Saint Barthélemy (alpha-3 `BLM`, numeric `652`)
        SaintBarthelemy => "BL", "Saint Barthelemy", { alpha3: Some("BLM"), numeric: Some(652) },
        /// Bermuda (alpha-3 `BMU`, numeric `060`)
        Bermuda => "BM", "Bermuda", { alpha3: Some("BMU"), numeric: Some(60) },
        /// Brunei Darussalam (alpha-3 `BRN`, numeric `096`)
        Brunei => "BN", "Brunei", { alpha3: Some("BRN"), numeric: Some(96) },
        /// Bolivia (Plurinational State of) (alpha-3 `BOL`, numeric `068`)
        Bolivia => "BO", "Bolivia", { alpha3: Some("BOL"), numeric: Some(68) },
        /// Bonaire, Sint Eustatius and Saba (alpha-3 `BES`, numeric `535`)
        BonaireSintEustatiusAndSaba => "BQ", "Bonaire, Sint Eustatius and Saba", { alpha3: Some("BES"), numeric: Some(535) },
        /// Brazil (alpha-3 `BRA`, numeric `076`)
        Brazil => "BR", "Brazil", { alpha3: Some("BRA"), numeric: Some(76) },
        /// Bahamas (the) (alpha-3 `BHS`, numeric `044`)
        Bahamas => "BS", "Bahamas", { alpha3: Some("BHS"), numeric: Some(44) },
        /// Bhutan (alpha-3 `BTN`, numeric `064`)
        Bhutan => "BT", "Bhutan", { alpha3: Some("BTN"), numeric: Some(64) },
        /// Bouvet Island (alpha-3 `BVT`, numeric `074`)
        BouvetIsland => "BV", "Bouvet Island", { alpha3: Some("BVT"), numeric: Some(74) },
        /// Botswana (alpha-3 `BWA`, numeric `072`)
        Botswana => "BW", "Botswana", { alpha3: Some("BWA"), numeric: Some(72) },
        /// Belarus (alpha-3 `BLR`, numeric `112`)
        Belarus => "BY", "Belarus", { alpha3: Some("BLR"), numeric: Some(112) },
        /// Belize (alpha-3 `BLZ`, numeric `084`)
        Belize => "BZ", "Belize", { alpha3: Some("BLZ"), numeric: Some(84) },
        /// Canada (alpha-3 `CAN`, numeric `124`)
        Canada => "CA", "Canada", { alpha3: Some("CAN"), numeric: Some(124) },
        /// Cocos (Keeling) Islands (the) (alpha-3 `CCK`, numeric `166`)
        CocosKeelingIslands => "CC", "Cocos (Keeling) Islands", { alpha3: Some("CCK"), numeric: Some(166) },
        /// Congo (the Democratic Republic of the) (alpha-3 `COD`, numeric `180`)
        DemocraticRepublicOfTheCongo => "CD", "Democratic Republic of the Congo", { alpha3: Some("COD"), numeric: Some(180) },
        /// Central African Republic (the) (alpha-3 `CAF`, numeric `140`)
        CentralAfricanRepublic => "CF", "Central African Republic", { alpha3: Some("CAF"), numeric: Some(140) },
        /// Congo (the) (alpha-3 `COG`, numeric `178`)
        Congo => "CG", "Republic of the Congo", { alpha3: Some("COG"), numeric: Some(178) },
        /// Switzerland (alpha-3 `CHE`, numeric `756`)
        Switzerland => "CH", "Switzerland", { alpha3: Some("CHE"), numeric: Some(756) },
        /// Côte d'Ivoire (alpha-3 `CIV`, numeric `384`)
        CoteDIvoire => "CI", "Cote d'Ivoire", { alpha3: Some("CIV"), numeric: Some(384) },
        /// Cook Islands (the) (alpha-3 `COK`, numeric `184`)
        CookIslands => "CK", "Cook Islands", { alpha3: Some("COK"), numeric: Some(184) },
        /// Chile (alpha-3 `CHL`, numeric `152`)
        Chile => "CL", "Chile", { alpha3: Some("CHL"), numeric: Some(152) },
        /// Cameroon (alpha-3 `CMR`, numeric `120`)
        Cameroon => "CM", "Cameroon", { alpha3: Some("CMR"), numeric: Some(120) },
        /// China (alpha-3 `CHN`, numeric `156`)
        China => "CN", "China", { alpha3: Some("CHN"), numeric: Some(156) },
        /// Colombia (alpha-3 `COL`, numeric `170`)
        Colombia => "CO", "Colombia", { alpha3: Some("COL"), numeric: Some(170) },
        /// Costa Rica (alpha-3 `CRI`, numeric `188`)
        CostaRica => "CR", "Costa Rica", { alpha3: Some("CRI"), numeric: Some(188) },
        /// Cuba (alpha-3 `CUB`, numeric `192`)
        Cuba => "CU", "Cuba", { alpha3: Some("CUB"), numeric: Some(192) },
        /// Cabo Verde (alpha-3 `CPV`, numeric `132`)
        CapeVerde => "CV", "Cape Verde", { alpha3: Some("CPV"), numeric: Some(132) },
        /// Curaçao (alpha-3 `CUW`, numeric `531`)
        Curacao => "CW", "Curacao", { alpha3: Some("CUW"), numeric: Some(531) },
        /// Christmas Island (alpha-3 `CXR`, numeric `162`)
        ChristmasIsland => "CX", "Christmas Island", { alpha3: Some("CXR"), numeric: Some(162) },
        /// Cyprus (alpha-3 `CYP`, numeric `196`)
        Cyprus => "CY", "Cyprus", { alpha3: Some("CYP"), numeric: Some(196) },
        /// Czechia (alpha-3 `CZE`, numeric `203`)
        CzechRepublic => "CZ", "Czechia", { alpha3: Some("CZE"), numeric: Some(203) },
        /// Germany (alpha-3 `DEU`, numeric `276`)
        Germany => "DE", "Germany", { alpha3: Some("DEU"), numeric: Some(276) },
        /// Djibouti (alpha-3 `DJI`, numeric `262`)
        Djibouti => "DJ", "Djibouti", { alpha3: Some("DJI"), numeric: Some(262) },
        /// Denmark (alpha-3 `DNK`, numeric `208`)
        Denmark => "DK", "Denmark", { alpha3: Some("DNK"), numeric: Some(208) },
        /// Dominica (alpha-3 `DMA`, numeric `212`)
        Dominica => "DM", "Dominica", { alpha3: Some("DMA"), numeric: Some(212) },
        /// Dominican Republic (the) (alpha-3 `DOM`, numeric `214`)
        DominicanRepublic => "DO", "Dominican Republic", { alpha3: Some("DOM"), numeric: Some(214) },
        /// Algeria (alpha-3 `DZA`, numeric `012`)
        Algeria => "DZ", "Algeria", { alpha3: Some("DZA"), numeric: Some(12) },
        /// Ecuador (alpha-3 `ECU`, numeric `218`)
        Ecuador => "EC", "Ecuador", { alpha3: Some("ECU"), numeric: Some(218) },
        /// Estonia (alpha-3 `EST`, numeric `233`)
        Estonia => "EE", "Estonia", { alpha3: Some("EST"), numeric: Some(233) },
        /// Egypt (alpha-3 `EGY`, numeric `818`)
        Egypt => "EG", "Egypt", { alpha3: Some("EGY"), numeric: Some(818) },
        /// Western Sahara* (alpha-3 `ESH`, numeric `732`) — contested
        WesternSahara => "EH", "Western Sahara", { alpha3: Some("ESH"), numeric: Some(732) },
        /// Eritrea (alpha-3 `ERI`, numeric `232`)
        Eritrea => "ER", "Eritrea", { alpha3: Some("ERI"), numeric: Some(232) },
        /// Spain (alpha-3 `ESP`, numeric `724`)
        Spain => "ES", "Spain", { alpha3: Some("ESP"), numeric: Some(724) },
        /// Ethiopia (alpha-3 `ETH`, numeric `231`)
        Ethiopia => "ET", "Ethiopia", { alpha3: Some("ETH"), numeric: Some(231) },
        /// European Union (alpha-3 `—`, numeric `—`) — exceptionally reserved (not a country); commonly seen in geolocation data; no official ISO 3166-1 alpha-3 or numeric code
        EuropeanUnion => "EU", "European Union", { alpha3: None, numeric: None },
        /// Finland (alpha-3 `FIN`, numeric `246`)
        Finland => "FI", "Finland", { alpha3: Some("FIN"), numeric: Some(246) },
        /// Fiji (alpha-3 `FJI`, numeric `242`)
        Fiji => "FJ", "Fiji", { alpha3: Some("FJI"), numeric: Some(242) },
        /// Falkland Islands (the) \[Malvinas\] (alpha-3 `FLK`, numeric `238`) — contested
        FalklandIslands => "FK", "Falkland Islands", { alpha3: Some("FLK"), numeric: Some(238) },
        /// Micronesia (Federated States of) (alpha-3 `FSM`, numeric `583`)
        Micronesia => "FM", "Micronesia", { alpha3: Some("FSM"), numeric: Some(583) },
        /// Faroe Islands (the) (alpha-3 `FRO`, numeric `234`)
        FaroeIslands => "FO", "Faroe Islands", { alpha3: Some("FRO"), numeric: Some(234) },
        /// France (alpha-3 `FRA`, numeric `250`)
        France => "FR", "France", { alpha3: Some("FRA"), numeric: Some(250) },
        /// Gabon (alpha-3 `GAB`, numeric `266`)
        Gabon => "GA", "Gabon", { alpha3: Some("GAB"), numeric: Some(266) },
        /// United Kingdom of Great Britain and Northern Ireland (the) (alpha-3 `GBR`, numeric `826`)
        UnitedKingdom => "GB", "United Kingdom", { alpha3: Some("GBR"), numeric: Some(826) },
        /// Grenada (alpha-3 `GRD`, numeric `308`)
        Grenada => "GD", "Grenada", { alpha3: Some("GRD"), numeric: Some(308) },
        /// Georgia (alpha-3 `GEO`, numeric `268`)
        Georgia => "GE", "Georgia", { alpha3: Some("GEO"), numeric: Some(268) },
        /// French Guiana (alpha-3 `GUF`, numeric `254`)
        FrenchGuiana => "GF", "French Guiana", { alpha3: Some("GUF"), numeric: Some(254) },
        /// Guernsey (alpha-3 `GGY`, numeric `831`)
        Guernsey => "GG", "Guernsey", { alpha3: Some("GGY"), numeric: Some(831) },
        /// Ghana (alpha-3 `GHA`, numeric `288`)
        Ghana => "GH", "Ghana", { alpha3: Some("GHA"), numeric: Some(288) },
        /// Gibraltar (alpha-3 `GIB`, numeric `292`)
        Gibraltar => "GI", "Gibraltar", { alpha3: Some("GIB"), numeric: Some(292) },
        /// Greenland (alpha-3 `GRL`, numeric `304`)
        Greenland => "GL", "Greenland", { alpha3: Some("GRL"), numeric: Some(304) },
        /// Gambia (the) (alpha-3 `GMB`, numeric `270`)
        Gambia => "GM", "Gambia", { alpha3: Some("GMB"), numeric: Some(270) },
        /// Guinea (alpha-3 `GIN`, numeric `324`)
        Guinea => "GN", "Guinea", { alpha3: Some("GIN"), numeric: Some(324) },
        /// Guadeloupe (alpha-3 `GLP`, numeric `312`)
        Guadeloupe => "GP", "Guadeloupe", { alpha3: Some("GLP"), numeric: Some(312) },
        /// Equatorial Guinea (alpha-3 `GNQ`, numeric `226`)
        EquatorialGuinea => "GQ", "Equatorial Guinea", { alpha3: Some("GNQ"), numeric: Some(226) },
        /// Greece (alpha-3 `GRC`, numeric `300`)
        Greece => "GR", "Greece", { alpha3: Some("GRC"), numeric: Some(300) },
        /// South Georgia and the South Sandwich Islands (alpha-3 `SGS`, numeric `239`)
        SouthGeorgiaAndTheSouthSandwichIslands => "GS", "South Georgia and the South Sandwich Islands", { alpha3: Some("SGS"), numeric: Some(239) },
        /// Guatemala (alpha-3 `GTM`, numeric `320`)
        Guatemala => "GT", "Guatemala", { alpha3: Some("GTM"), numeric: Some(320) },
        /// Guam (alpha-3 `GUM`, numeric `316`)
        Guam => "GU", "Guam", { alpha3: Some("GUM"), numeric: Some(316) },
        /// Guinea-Bissau (alpha-3 `GNB`, numeric `624`)
        GuineaBissau => "GW", "Guinea-Bissau", { alpha3: Some("GNB"), numeric: Some(624) },
        /// Guyana (alpha-3 `GUY`, numeric `328`)
        Guyana => "GY", "Guyana", { alpha3: Some("GUY"), numeric: Some(328) },
        /// Hong Kong (alpha-3 `HKG`, numeric `344`)
        HongKong => "HK", "Hong Kong", { alpha3: Some("HKG"), numeric: Some(344) },
        /// Heard Island and McDonald Islands (alpha-3 `HMD`, numeric `334`)
        HeardIslandAndMcDonaldIslands => "HM", "Heard Island and McDonald Islands", { alpha3: Some("HMD"), numeric: Some(334) },
        /// Honduras (alpha-3 `HND`, numeric `340`)
        Honduras => "HN", "Honduras", { alpha3: Some("HND"), numeric: Some(340) },
        /// Croatia (alpha-3 `HRV`, numeric `191`)
        Croatia => "HR", "Croatia", { alpha3: Some("HRV"), numeric: Some(191) },
        /// Haiti (alpha-3 `HTI`, numeric `332`)
        Haiti => "HT", "Haiti", { alpha3: Some("HTI"), numeric: Some(332) },
        /// Hungary (alpha-3 `HUN`, numeric `348`)
        Hungary => "HU", "Hungary", { alpha3: Some("HUN"), numeric: Some(348) },
        /// Indonesia (alpha-3 `IDN`, numeric `360`)
        Indonesia => "ID", "Indonesia", { alpha3: Some("IDN"), numeric: Some(360) },
        /// Ireland (alpha-3 `IRL`, numeric `372`)
        Ireland => "IE", "Ireland", { alpha3: Some("IRL"), numeric: Some(372) },
        /// Israel (alpha-3 `ISR`, numeric `376`)
        Israel => "IL", "Israel", { alpha3: Some("ISR"), numeric: Some(376) },
        /// Isle of Man (alpha-3 `IMN`, numeric `833`)
        IsleOfMan => "IM", "Isle of Man", { alpha3: Some("IMN"), numeric: Some(833) },
        /// India (alpha-3 `IND`, numeric `356`)
        India => "IN", "India", { alpha3: Some("IND"), numeric: Some(356) },
        /// British Indian Ocean Territory (the) (alpha-3 `IOT`, numeric `086`)
        BritishIndianOceanTerritory => "IO", "British Indian Ocean Territory", { alpha3: Some("IOT"), numeric: Some(86) },
        /// Iraq (alpha-3 `IRQ`, numeric `368`)
        Iraq => "IQ", "Iraq", { alpha3: Some("IRQ"), numeric: Some(368) },
        /// Iran (Islamic Republic of) (alpha-3 `IRN`, numeric `364`)
        Iran => "IR", "Iran", { alpha3: Some("IRN"), numeric: Some(364) },
        /// Iceland (alpha-3 `ISL`, numeric `352`)
        Iceland => "IS", "Iceland", { alpha3: Some("ISL"), numeric: Some(352) },
        /// Italy (alpha-3 `ITA`, numeric `380`)
        Italy => "IT", "Italy", { alpha3: Some("ITA"), numeric: Some(380) },
        /// Jersey (alpha-3 `JEY`, numeric `832`)
        Jersey => "JE", "Jersey", { alpha3: Some("JEY"), numeric: Some(832) },
        /// Jamaica (alpha-3 `JAM`, numeric `388`)
        Jamaica => "JM", "Jamaica", { alpha3: Some("JAM"), numeric: Some(388) },
        /// Jordan (alpha-3 `JOR`, numeric `400`)
        Jordan => "JO", "Jordan", { alpha3: Some("JOR"), numeric: Some(400) },
        /// Japan (alpha-3 `JPN`, numeric `392`)
        Japan => "JP", "Japan", { alpha3: Some("JPN"), numeric: Some(392) },
        /// Kenya (alpha-3 `KEN`, numeric `404`)
        Kenya => "KE", "Kenya", { alpha3: Some("KEN"), numeric: Some(404) },
        /// Kyrgyzstan (alpha-3 `KGZ`, numeric `417`)
        Kyrgyzstan => "KG", "Kyrgyzstan", { alpha3: Some("KGZ"), numeric: Some(417) },
        /// Cambodia (alpha-3 `KHM`, numeric `116`)
        Cambodia => "KH", "Cambodia", { alpha3: Some("KHM"), numeric: Some(116) },
        /// Kiribati (alpha-3 `KIR`, numeric `296`)
        Kiribati => "KI", "Kiribati", { alpha3: Some("KIR"), numeric: Some(296) },
        /// Comoros (the) (alpha-3 `COM`, numeric `174`)
        Comoros => "KM", "Comoros", { alpha3: Some("COM"), numeric: Some(174) },
        /// Saint Kitts and Nevis (alpha-3 `KNA`, numeric `659`)
        SaintKittsAndNevis => "KN", "Saint Kitts and Nevis", { alpha3: Some("KNA"), numeric: Some(659) },
        /// Korea (the Democratic People's Republic of) (alpha-3 `PRK`, numeric `408`)
        NorthKorea => "KP", "North Korea", { alpha3: Some("PRK"), numeric: Some(408) },
        /// Korea (the Republic of) (alpha-3 `KOR`, numeric `410`)
        SouthKorea => "KR", "South Korea", { alpha3: Some("KOR"), numeric: Some(410) },
        /// Kuwait (alpha-3 `KWT`, numeric `414`)
        Kuwait => "KW", "Kuwait", { alpha3: Some("KWT"), numeric: Some(414) },
        /// Cayman Islands (the) (alpha-3 `CYM`, numeric `136`)
        CaymanIslands => "KY", "Cayman Islands", { alpha3: Some("CYM"), numeric: Some(136) },
        /// Kazakhstan (alpha-3 `KAZ`, numeric `398`)
        Kazakhstan => "KZ", "Kazakhstan", { alpha3: Some("KAZ"), numeric: Some(398) },
        /// Lao People's Democratic Republic (the) (alpha-3 `LAO`, numeric `418`)
        Laos => "LA", "Laos", { alpha3: Some("LAO"), numeric: Some(418) },
        /// Lebanon (alpha-3 `LBN`, numeric `422`)
        Lebanon => "LB", "Lebanon", { alpha3: Some("LBN"), numeric: Some(422) },
        /// Saint Lucia (alpha-3 `LCA`, numeric `662`)
        SaintLucia => "LC", "Saint Lucia", { alpha3: Some("LCA"), numeric: Some(662) },
        /// Liechtenstein (alpha-3 `LIE`, numeric `438`)
        Liechtenstein => "LI", "Liechtenstein", { alpha3: Some("LIE"), numeric: Some(438) },
        /// Sri Lanka (alpha-3 `LKA`, numeric `144`)
        SriLanka => "LK", "Sri Lanka", { alpha3: Some("LKA"), numeric: Some(144) },
        /// Liberia (alpha-3 `LBR`, numeric `430`)
        Liberia => "LR", "Liberia", { alpha3: Some("LBR"), numeric: Some(430) },
        /// Lesotho (alpha-3 `LSO`, numeric `426`)
        Lesotho => "LS", "Lesotho", { alpha3: Some("LSO"), numeric: Some(426) },
        /// Lithuania (alpha-3 `LTU`, numeric `440`)
        Lithuania => "LT", "Lithuania", { alpha3: Some("LTU"), numeric: Some(440) },
        /// Luxembourg (alpha-3 `LUX`, numeric `442`)
        Luxembourg => "LU", "Luxembourg", { alpha3: Some("LUX"), numeric: Some(442) },
        /// Latvia (alpha-3 `LVA`, numeric `428`)
        Latvia => "LV", "Latvia", { alpha3: Some("LVA"), numeric: Some(428) },
        /// Libya (alpha-3 `LBY`, numeric `434`)
        Libya => "LY", "Libya", { alpha3: Some("LBY"), numeric: Some(434) },
        /// Morocco (alpha-3 `MAR`, numeric `504`)
        Morocco => "MA", "Morocco", { alpha3: Some("MAR"), numeric: Some(504) },
        /// Monaco (alpha-3 `MCO`, numeric `492`)
        Monaco => "MC", "Monaco", { alpha3: Some("MCO"), numeric: Some(492) },
        /// Moldova (the Republic of) (alpha-3 `MDA`, numeric `498`)
        Moldova => "MD", "Moldova", { alpha3: Some("MDA"), numeric: Some(498) },
        /// Montenegro (alpha-3 `MNE`, numeric `499`)
        Montenegro => "ME", "Montenegro", { alpha3: Some("MNE"), numeric: Some(499) },
        /// Saint Martin (French part) (alpha-3 `MAF`, numeric `663`)
        SaintMartin => "MF", "Saint Martin (French part)", { alpha3: Some("MAF"), numeric: Some(663) },
        /// Madagascar (alpha-3 `MDG`, numeric `450`)
        Madagascar => "MG", "Madagascar", { alpha3: Some("MDG"), numeric: Some(450) },
        /// Marshall Islands (the) (alpha-3 `MHL`, numeric `584`)
        MarshallIslands => "MH", "Marshall Islands", { alpha3: Some("MHL"), numeric: Some(584) },
        /// North Macedonia (alpha-3 `MKD`, numeric `807`)
        NorthMacedonia => "MK", "North Macedonia", { alpha3: Some("MKD"), numeric: Some(807) },
        /// Mali (alpha-3 `MLI`, numeric `466`)
        Mali => "ML", "Mali", { alpha3: Some("MLI"), numeric: Some(466) },
        /// Myanmar (alpha-3 `MMR`, numeric `104`)
        Myanmar => "MM", "Myanmar", { alpha3: Some("MMR"), numeric: Some(104) },
        /// Mongolia (alpha-3 `MNG`, numeric `496`)
        Mongolia => "MN", "Mongolia", { alpha3: Some("MNG"), numeric: Some(496) },
        /// Macao (alpha-3 `MAC`, numeric `446`)
        Macau => "MO", "Macau", { alpha3: Some("MAC"), numeric: Some(446) },
        /// Northern Mariana Islands (the) (alpha-3 `MNP`, numeric `580`)
        NorthernMarianaIslands => "MP", "Northern Mariana Islands", { alpha3: Some("MNP"), numeric: Some(580) },
        /// Martinique (alpha-3 `MTQ`, numeric `474`)
        Martinique => "MQ", "Martinique", { alpha3: Some("MTQ"), numeric: Some(474) },
        /// Mauritania (alpha-3 `MRT`, numeric `478`)
        Mauritania => "MR", "Mauritania", { alpha3: Some("MRT"), numeric: Some(478) },
        /// Montserrat (alpha-3 `MSR`, numeric `500`)
        Montserrat => "MS", "Montserrat", { alpha3: Some("MSR"), numeric: Some(500) },
        /// Malta (alpha-3 `MLT`, numeric `470`)
        Malta => "MT", "Malta", { alpha3: Some("MLT"), numeric: Some(470) },
        /// Mauritius (alpha-3 `MUS`, numeric `480`)
        Mauritius => "MU", "Mauritius", { alpha3: Some("MUS"), numeric: Some(480) },
        /// Maldives (alpha-3 `MDV`, numeric `462`)
        Maldives => "MV", "Maldives", { alpha3: Some("MDV"), numeric: Some(462) },
        /// Malawi (alpha-3 `MWI`, numeric `454`)
        Malawi => "MW", "Malawi", { alpha3: Some("MWI"), numeric: Some(454) },
        /// Mexico (alpha-3 `MEX`, numeric `484`)
        Mexico => "MX", "Mexico", { alpha3: Some("MEX"), numeric: Some(484) },
        /// Malaysia (alpha-3 `MYS`, numeric `458`)
        Malaysia => "MY", "Malaysia", { alpha3: Some("MYS"), numeric: Some(458) },
        /// Mozambique (alpha-3 `MOZ`, numeric `508`)
        Mozambique => "MZ", "Mozambique", { alpha3: Some("MOZ"), numeric: Some(508) },
        /// Namibia (alpha-3 `NAM`, numeric `516`)
        Namibia => "NA", "Namibia", { alpha3: Some("NAM"), numeric: Some(516) },
        /// New Caledonia (alpha-3 `NCL`, numeric `540`)
        NewCaledonia => "NC", "New Caledonia", { alpha3: Some("NCL"), numeric: Some(540) },
        /// Niger (the) (alpha-3 `NER`, numeric `562`)
        Niger => "NE", "Niger", { alpha3: Some("NER"), numeric: Some(562) },
        /// Norfolk Island (alpha-3 `NFK`, numeric `574`)
        NorfolkIsland => "NF", "Norfolk Island", { alpha3: Some("NFK"), numeric: Some(574) },
        /// Nigeria (alpha-3 `NGA`, numeric `566`)
        Nigeria => "NG", "Nigeria", { alpha3: Some("NGA"), numeric: Some(566) },
        /// Nicaragua (alpha-3 `NIC`, numeric `558`)
        Nicaragua => "NI", "Nicaragua", { alpha3: Some("NIC"), numeric: Some(558) },
        /// Netherlands (the) (alpha-3 `NLD`, numeric `528`)
        Netherlands => "NL", "Netherlands", { alpha3: Some("NLD"), numeric: Some(528) },
        /// Norway (alpha-3 `NOR`, numeric `578`)
        Norway => "NO", "Norway", { alpha3: Some("NOR"), numeric: Some(578) },
        /// Nepal (alpha-3 `NPL`, numeric `524`)
        Nepal => "NP", "Nepal", { alpha3: Some("NPL"), numeric: Some(524) },
        /// Nauru (alpha-3 `NRU`, numeric `520`)
        Nauru => "NR", "Nauru", { alpha3: Some("NRU"), numeric: Some(520) },
        /// Niue (alpha-3 `NIU`, numeric `570`)
        Niue => "NU", "Niue", { alpha3: Some("NIU"), numeric: Some(570) },
        /// New Zealand (alpha-3 `NZL`, numeric `554`)
        NewZealand => "NZ", "New Zealand", { alpha3: Some("NZL"), numeric: Some(554) },
        /// Oman (alpha-3 `OMN`, numeric `512`)
        Oman => "OM", "Oman", { alpha3: Some("OMN"), numeric: Some(512) },
        /// Panama (alpha-3 `PAN`, numeric `591`)
        Panama => "PA", "Panama", { alpha3: Some("PAN"), numeric: Some(591) },
        /// Peru (alpha-3 `PER`, numeric `604`)
        Peru => "PE", "Peru", { alpha3: Some("PER"), numeric: Some(604) },
        /// French Polynesia (alpha-3 `PYF`, numeric `258`)
        FrenchPolynesia => "PF", "French Polynesia", { alpha3: Some("PYF"), numeric: Some(258) },
        /// Papua New Guinea (alpha-3 `PNG`, numeric `598`)
        PapuaNewGuinea => "PG", "Papua New Guinea", { alpha3: Some("PNG"), numeric: Some(598) },
        /// Philippines (the) (alpha-3 `PHL`, numeric `608`)
        Philippines => "PH", "Philippines", { alpha3: Some("PHL"), numeric: Some(608) },
        /// Pakistan (alpha-3 `PAK`, numeric `586`)
        Pakistan => "PK", "Pakistan", { alpha3: Some("PAK"), numeric: Some(586) },
        /// Poland (alpha-3 `POL`, numeric `616`)
        Poland => "PL", "Poland", { alpha3: Some("POL"), numeric: Some(616) },
        /// Saint Pierre and Miquelon (alpha-3 `SPM`, numeric `666`)
        SaintPierreAndMiquelon => "PM", "Saint Pierre and Miquelon", { alpha3: Some("SPM"), numeric: Some(666) },
        /// Pitcairn (alpha-3 `PCN`, numeric `612`)
        Pitcairn => "PN", "Pitcairn Islands", { alpha3: Some("PCN"), numeric: Some(612) },
        /// Puerto Rico (alpha-3 `PRI`, numeric `630`)
        PuertoRico => "PR", "Puerto Rico", { alpha3: Some("PRI"), numeric: Some(630) },
        /// Palestine, State of (alpha-3 `PSE`, numeric `275`) — contested
        Palestine => "PS", "Palestine", { alpha3: Some("PSE"), numeric: Some(275) },
        /// Portugal (alpha-3 `PRT`, numeric `620`)
        Portugal => "PT", "Portugal", { alpha3: Some("PRT"), numeric: Some(620) },
        /// Palau (alpha-3 `PLW`, numeric `585`)
        Palau => "PW", "Palau", { alpha3: Some("PLW"), numeric: Some(585) },
        /// Paraguay (alpha-3 `PRY`, numeric `600`)
        Paraguay => "PY", "Paraguay", { alpha3: Some("PRY"), numeric: Some(600) },
        /// Qatar (alpha-3 `QAT`, numeric `634`)
        Qatar => "QA", "Qatar", { alpha3: Some("QAT"), numeric: Some(634) },
        /// Reunion (alpha-3 `REU`, numeric `638`)
        Reunion => "RE", "Reunion", { alpha3: Some("REU"), numeric: Some(638) },
        /// Romania (alpha-3 `ROU`, numeric `642`)
        Romania => "RO", "Romania", { alpha3: Some("ROU"), numeric: Some(642) },
        /// Serbia (alpha-3 `SRB`, numeric `688`)
        Serbia => "RS", "Serbia", { alpha3: Some("SRB"), numeric: Some(688) },
        /// Russian Federation (the) (alpha-3 `RUS`, numeric `643`)
        Russia => "RU", "Russia", { alpha3: Some("RUS"), numeric: Some(643) },
        /// Rwanda (alpha-3 `RWA`, numeric `646`)
        Rwanda => "RW", "Rwanda", { alpha3: Some("RWA"), numeric: Some(646) },
        /// Saudi Arabia (alpha-3 `SAU`, numeric `682`)
        SaudiArabia => "SA", "Saudi Arabia", { alpha3: Some("SAU"), numeric: Some(682) },
        /// Solomon Islands (alpha-3 `SLB`, numeric `090`)
        SolomonIslands => "SB", "Solomon Islands", { alpha3: Some("SLB"), numeric: Some(90) },
        /// Seychelles (alpha-3 `SYC`, numeric `690`)
        Seychelles => "SC", "Seychelles", { alpha3: Some("SYC"), numeric: Some(690) },
        /// Sudan (the) (alpha-3 `SDN`, numeric `729`)
        Sudan => "SD", "Sudan", { alpha3: Some("SDN"), numeric: Some(729) },
        /// Sweden (alpha-3 `SWE`, numeric `752`)
        Sweden => "SE", "Sweden", { alpha3: Some("SWE"), numeric: Some(752) },
        /// Singapore (alpha-3 `SGP`, numeric `702`)
        Singapore => "SG", "Singapore", { alpha3: Some("SGP"), numeric: Some(702) },
        /// Saint Helena, Ascension and Tristan da Cunha (alpha-3 `SHN`, numeric `654`)
        SaintHelena => "SH", "Saint Helena, Ascension and Tristan da Cunha", { alpha3: Some("SHN"), numeric: Some(654) },
        /// Slovenia (alpha-3 `SVN`, numeric `705`)
        Slovenia => "SI", "Slovenia", { alpha3: Some("SVN"), numeric: Some(705) },
        /// Svalbard and Jan Mayen (alpha-3 `SJM`, numeric `744`)
        SvalbardAndJanMayen => "SJ", "Svalbard and Jan Mayen", { alpha3: Some("SJM"), numeric: Some(744) },
        /// Slovakia (alpha-3 `SVK`, numeric `703`)
        Slovakia => "SK", "Slovakia", { alpha3: Some("SVK"), numeric: Some(703) },
        /// Sierra Leone (alpha-3 `SLE`, numeric `694`)
        SierraLeone => "SL", "Sierra Leone", { alpha3: Some("SLE"), numeric: Some(694) },
        /// San Marino (alpha-3 `SMR`, numeric `674`)
        SanMarino => "SM", "San Marino", { alpha3: Some("SMR"), numeric: Some(674) },
        /// Senegal (alpha-3 `SEN`, numeric `686`)
        Senegal => "SN", "Senegal", { alpha3: Some("SEN"), numeric: Some(686) },
        /// Somalia (alpha-3 `SOM`, numeric `706`)
        Somalia => "SO", "Somalia", { alpha3: Some("SOM"), numeric: Some(706) },
        /// Suriname (alpha-3 `SUR`, numeric `740`)
        Suriname => "SR", "Suriname", { alpha3: Some("SUR"), numeric: Some(740) },
        /// South Sudan (alpha-3 `SSD`, numeric `728`)
        SouthSudan => "SS", "South Sudan", { alpha3: Some("SSD"), numeric: Some(728) },
        /// Sao Tome and Principe (alpha-3 `STP`, numeric `678`)
        SaoTomeAndPrincipe => "ST", "Sao Tome and Principe", { alpha3: Some("STP"), numeric: Some(678) },
        /// El Salvador (alpha-3 `SLV`, numeric `222`)
        ElSalvador => "SV", "El Salvador", { alpha3: Some("SLV"), numeric: Some(222) },
        /// Sint Maarten (Dutch part) (alpha-3 `SXM`, numeric `534`)
        SintMaarten => "SX", "Sint Maarten", { alpha3: Some("SXM"), numeric: Some(534) },
        /// Syrian Arab Republic (the) (alpha-3 `SYR`, numeric `760`)
        Syria => "SY", "Syria", { alpha3: Some("SYR"), numeric: Some(760) },
        /// Eswatini (alpha-3 `SWZ`, numeric `748`)
        Eswatini => "SZ", "Eswatini", { alpha3: Some("SWZ"), numeric: Some(748) },
        /// Turks and Caicos Islands (the) (alpha-3 `TCA`, numeric `796`)
        TurksAndCaicosIslands => "TC", "Turks and Caicos Islands", { alpha3: Some("TCA"), numeric: Some(796) },
        /// Chad (alpha-3 `TCD`, numeric `148`)
        Chad => "TD", "Chad", { alpha3: Some("TCD"), numeric: Some(148) },
        /// French Southern Territories (the) (alpha-3 `ATF`, numeric `260`)
        FrenchSouthernTerritories => "TF", "French Southern Territories", { alpha3: Some("ATF"), numeric: Some(260) },
        /// Togo (alpha-3 `TGO`, numeric `768`)
        Togo => "TG", "Togo", { alpha3: Some("TGO"), numeric: Some(768) },
        /// Thailand (alpha-3 `THA`, numeric `764`)
        Thailand => "TH", "Thailand", { alpha3: Some("THA"), numeric: Some(764) },
        /// Tajikistan (alpha-3 `TJK`, numeric `762`)
        Tajikistan => "TJ", "Tajikistan", { alpha3: Some("TJK"), numeric: Some(762) },
        /// Tokelau (alpha-3 `TKL`, numeric `772`)
        Tokelau => "TK", "Tokelau", { alpha3: Some("TKL"), numeric: Some(772) },
        /// Timor-Leste (alpha-3 `TLS`, numeric `626`)
        TimorLeste => "TL", "Timor-Leste", { alpha3: Some("TLS"), numeric: Some(626) },
        /// Turkmenistan (alpha-3 `TKM`, numeric `795`)
        Turkmenistan => "TM", "Turkmenistan", { alpha3: Some("TKM"), numeric: Some(795) },
        /// Tunisia (alpha-3 `TUN`, numeric `788`)
        Tunisia => "TN", "Tunisia", { alpha3: Some("TUN"), numeric: Some(788) },
        /// Tonga (alpha-3 `TON`, numeric `776`)
        Tonga => "TO", "Tonga", { alpha3: Some("TON"), numeric: Some(776) },
        /// Türkiye (alpha-3 `TUR`, numeric `792`)
        Turkey => "TR", "Turkey", { alpha3: Some("TUR"), numeric: Some(792) },
        /// Trinidad and Tobago (alpha-3 `TTO`, numeric `780`)
        TrinidadAndTobago => "TT", "Trinidad and Tobago", { alpha3: Some("TTO"), numeric: Some(780) },
        /// Tuvalu (alpha-3 `TUV`, numeric `798`)
        Tuvalu => "TV", "Tuvalu", { alpha3: Some("TUV"), numeric: Some(798) },
        /// Taiwan (Province of China) (alpha-3 `TWN`, numeric `158`) — contested
        Taiwan => "TW", "Taiwan", { alpha3: Some("TWN"), numeric: Some(158) },
        /// Tanzania, the United Republic of (alpha-3 `TZA`, numeric `834`)
        Tanzania => "TZ", "Tanzania", { alpha3: Some("TZA"), numeric: Some(834) },
        /// Ukraine (alpha-3 `UKR`, numeric `804`)
        Ukraine => "UA", "Ukraine", { alpha3: Some("UKR"), numeric: Some(804) },
        /// Uganda (alpha-3 `UGA`, numeric `800`)
        Uganda => "UG", "Uganda", { alpha3: Some("UGA"), numeric: Some(800) },
        /// United States Minor Outlying Islands (the) (alpha-3 `UMI`, numeric `581`)
        UnitedStatesMinorOutlyingIslands => "UM", "United States Minor Outlying Islands", { alpha3: Some("UMI"), numeric: Some(581) },
        /// United States of America (the) (alpha-3 `USA`, numeric `840`)
        UnitedStates => "US", "United States", { alpha3: Some("USA"), numeric: Some(840) },
        /// Uruguay (alpha-3 `URY`, numeric `858`)
        Uruguay => "UY", "Uruguay", { alpha3: Some("URY"), numeric: Some(858) },
        /// Uzbekistan (alpha-3 `UZB`, numeric `860`)
        Uzbekistan => "UZ", "Uzbekistan", { alpha3: Some("UZB"), numeric: Some(860) },
        /// Holy See (the) (alpha-3 `VAT`, numeric `336`)
        VaticanCity => "VA", "Vatican City", { alpha3: Some("VAT"), numeric: Some(336) },
        /// Saint Vincent and the Grenadines (alpha-3 `VCT`, numeric `670`)
        SaintVincentAndTheGrenadines => "VC", "Saint Vincent and the Grenadines", { alpha3: Some("VCT"), numeric: Some(670) },
        /// Venezuela (Bolivarian Republic of) (alpha-3 `VEN`, numeric `862`)
        Venezuela => "VE", "Venezuela", { alpha3: Some("VEN"), numeric: Some(862) },
        /// Virgin Islands (British) (alpha-3 `VGB`, numeric `092`)
        BritishVirginIslands => "VG", "British Virgin Islands", { alpha3: Some("VGB"), numeric: Some(92) },
        /// Virgin Islands (U.S.) (alpha-3 `VIR`, numeric `850`)
        UnitedStatesVirginIslands => "VI", "U.S. Virgin Islands", { alpha3: Some("VIR"), numeric: Some(850) },
        /// Viet Nam (alpha-3 `VNM`, numeric `704`)
        Vietnam => "VN", "Vietnam", { alpha3: Some("VNM"), numeric: Some(704) },
        /// Vanuatu (alpha-3 `VUT`, numeric `548`)
        Vanuatu => "VU", "Vanuatu", { alpha3: Some("VUT"), numeric: Some(548) },
        /// Wallis and Futuna (alpha-3 `WLF`, numeric `876`)
        WallisAndFutuna => "WF", "Wallis and Futuna", { alpha3: Some("WLF"), numeric: Some(876) },
        /// Samoa (alpha-3 `WSM`, numeric `882`)
        Samoa => "WS", "Samoa", { alpha3: Some("WSM"), numeric: Some(882) },
        /// Kosovo (alpha-3 `XKX`, numeric `983`) — user-assigned (not officially in ISO 3166-1); XKX/983 are common de-facto conventions used by EU/IMF/geolocation data; contested
        Kosovo => "XK", "Kosovo", { alpha3: Some("XKX"), numeric: Some(983) },
        /// Yemen (alpha-3 `YEM`, numeric `887`)
        Yemen => "YE", "Yemen", { alpha3: Some("YEM"), numeric: Some(887) },
        /// Mayotte (alpha-3 `MYT`, numeric `175`)
        Mayotte => "YT", "Mayotte", { alpha3: Some("MYT"), numeric: Some(175) },
        /// South Africa (alpha-3 `ZAF`, numeric `710`)
        SouthAfrica => "ZA", "South Africa", { alpha3: Some("ZAF"), numeric: Some(710) },
        /// Zambia (alpha-3 `ZMB`, numeric `894`)
        Zambia => "ZM", "Zambia", { alpha3: Some("ZMB"), numeric: Some(894) },
        /// Zimbabwe (alpha-3 `ZWE`, numeric `716`)
        Zimbabwe => "ZW", "Zimbabwe", { alpha3: Some("ZWE"), numeric: Some(716) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_lookups() {
        assert_eq!(Country::from_code("BE"), Country::Belgium);
        assert_eq!(Country::Belgium.name(), Some("Belgium"));
        assert_eq!(Country::UnitedStates.code(), "US");
        assert_eq!(Country::from_code("TW"), Country::Taiwan);
        assert_eq!(Country::from_code("XK"), Country::Kosovo);
        assert_eq!(Country::from_code("ZZ"), Country::Unknown("ZZ".into()));
    }

    #[test]
    fn alpha3_and_numeric() {
        assert_eq!(Country::Belgium.alpha3(), Some("BEL"));
        assert_eq!(Country::Belgium.numeric(), Some(56));
        assert_eq!(Country::UnitedStates.alpha3(), Some("USA"));
        assert_eq!(Country::UnitedStates.numeric(), Some(840));
        assert_eq!(Country::Kosovo.alpha3(), Some("XKX"));
        // the EU pseudo-entry has no official alpha-3 / numeric
        assert_eq!(Country::EuropeanUnion.alpha3(), None);
        assert_eq!(Country::EuropeanUnion.numeric(), None);
        // unknown codes carry no metadata
        assert_eq!(Country::from_code("ZZ").alpha3(), None);
        assert_eq!(Country::from_code("ZZ").numeric(), None);
        // the borrowing form exposes the same metadata
        assert_eq!(CountryRef::Belgium.alpha3(), Some("BEL"));
    }

    #[test]
    fn reverse_lookups() {
        assert_eq!(Country::from_alpha3("USA"), Some(Country::UnitedStates));
        assert_eq!(Country::from_alpha3("BEL"), Some(Country::Belgium));
        assert_eq!(Country::from_alpha3("ZZZ"), None);
        assert_eq!(Country::from_numeric(840), Some(Country::UnitedStates));
        assert_eq!(Country::from_numeric(56), Some(Country::Belgium));
        assert_eq!(Country::from_numeric(1), None);
    }

    #[test]
    fn all_codes_roundtrip() {
        // 249 official ISO 3166-1 codes + EU + XK
        assert_eq!(Country::ALL.len(), 251);
        for c in Country::ALL {
            assert!(c.is_known(), "{c:?} should be known");
            assert_eq!(Country::from_code(c.code()), c.clone());
            assert!(c.name().is_some());
            // every official entry has both an alpha-3 and a numeric code
            if !matches!(c, Country::EuropeanUnion) {
                assert!(c.alpha3().is_some(), "{c:?} missing alpha-3");
                assert!(c.numeric().is_some(), "{c:?} missing numeric");
            }
        }
    }
}
