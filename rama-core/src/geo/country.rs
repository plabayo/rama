//! Country / territory identity, keyed by ISO 3166-1 alpha-2 code.
//!
//! The set below covers every officially-assigned ISO 3166-1 alpha-2 code,
//! plus the commonly-seen user-assigned `XK` (Kosovo) and exceptionally-reserved
//! `EU` (European Union). Any other code round-trips through `Unknown`.
//!
//! rama takes no political stance: contested territories are included purely
//! for completeness of the standard.
//!
//! Sources (cross-verified):
//! - ISO 3166-1 official standard (ISO 3166 Maintenance Agency)
//! - ISO Online Browsing Platform: <https://www.iso.org/obp/ui/#search>
//! - <https://en.wikipedia.org/wiki/ISO_3166-1> (and the alpha-2 / alpha-3 /
//!   numeric sub-pages)
//!
//! This file is generated; the owned form encodes identity only (the
//! database's localised name is not retained). Use [`Country::name`] for the
//! canonical English name and [`Country::code`] for the alpha-2 code.

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
}

geo_enum! {
    /// A country or territory, identified by its ISO 3166-1 alpha-2 code.
    pub enum Country / CountryRef {
        /// Andorra (alpha-3 `AND`, numeric `020`)
        Andorra => "AD", "Andorra",
        /// United Arab Emirates (the) (alpha-3 `ARE`, numeric `784`)
        UnitedArabEmirates => "AE", "United Arab Emirates",
        /// Afghanistan (alpha-3 `AFG`, numeric `004`)
        Afghanistan => "AF", "Afghanistan",
        /// Antigua and Barbuda (alpha-3 `ATG`, numeric `028`)
        AntiguaAndBarbuda => "AG", "Antigua and Barbuda",
        /// Anguilla (alpha-3 `AIA`, numeric `660`)
        Anguilla => "AI", "Anguilla",
        /// Albania (alpha-3 `ALB`, numeric `008`)
        Albania => "AL", "Albania",
        /// Armenia (alpha-3 `ARM`, numeric `051`)
        Armenia => "AM", "Armenia",
        /// Angola (alpha-3 `AGO`, numeric `024`)
        Angola => "AO", "Angola",
        /// Antarctica (alpha-3 `ATA`, numeric `010`)
        Antarctica => "AQ", "Antarctica",
        /// Argentina (alpha-3 `ARG`, numeric `032`)
        Argentina => "AR", "Argentina",
        /// American Samoa (alpha-3 `ASM`, numeric `016`)
        AmericanSamoa => "AS", "American Samoa",
        /// Austria (alpha-3 `AUT`, numeric `040`)
        Austria => "AT", "Austria",
        /// Australia (alpha-3 `AUS`, numeric `036`)
        Australia => "AU", "Australia",
        /// Aruba (alpha-3 `ABW`, numeric `533`)
        Aruba => "AW", "Aruba",
        /// Åland Islands (alpha-3 `ALA`, numeric `248`)
        AlandIslands => "AX", "Aland Islands",
        /// Azerbaijan (alpha-3 `AZE`, numeric `031`)
        Azerbaijan => "AZ", "Azerbaijan",
        /// Bosnia and Herzegovina (alpha-3 `BIH`, numeric `070`)
        BosniaAndHerzegovina => "BA", "Bosnia and Herzegovina",
        /// Barbados (alpha-3 `BRB`, numeric `052`)
        Barbados => "BB", "Barbados",
        /// Bangladesh (alpha-3 `BGD`, numeric `050`)
        Bangladesh => "BD", "Bangladesh",
        /// Belgium (alpha-3 `BEL`, numeric `056`)
        Belgium => "BE", "Belgium",
        /// Burkina Faso (alpha-3 `BFA`, numeric `854`)
        BurkinaFaso => "BF", "Burkina Faso",
        /// Bulgaria (alpha-3 `BGR`, numeric `100`)
        Bulgaria => "BG", "Bulgaria",
        /// Bahrain (alpha-3 `BHR`, numeric `048`)
        Bahrain => "BH", "Bahrain",
        /// Burundi (alpha-3 `BDI`, numeric `108`)
        Burundi => "BI", "Burundi",
        /// Benin (alpha-3 `BEN`, numeric `204`)
        Benin => "BJ", "Benin",
        /// Saint Barthélemy (alpha-3 `BLM`, numeric `652`)
        SaintBarthelemy => "BL", "Saint Barthelemy",
        /// Bermuda (alpha-3 `BMU`, numeric `060`)
        Bermuda => "BM", "Bermuda",
        /// Brunei Darussalam (alpha-3 `BRN`, numeric `096`)
        Brunei => "BN", "Brunei",
        /// Bolivia (Plurinational State of) (alpha-3 `BOL`, numeric `068`)
        Bolivia => "BO", "Bolivia",
        /// Bonaire, Sint Eustatius and Saba (alpha-3 `BES`, numeric `535`)
        BonaireSintEustatiusAndSaba => "BQ", "Bonaire, Sint Eustatius and Saba",
        /// Brazil (alpha-3 `BRA`, numeric `076`)
        Brazil => "BR", "Brazil",
        /// Bahamas (the) (alpha-3 `BHS`, numeric `044`)
        Bahamas => "BS", "Bahamas",
        /// Bhutan (alpha-3 `BTN`, numeric `064`)
        Bhutan => "BT", "Bhutan",
        /// Bouvet Island (alpha-3 `BVT`, numeric `074`)
        BouvetIsland => "BV", "Bouvet Island",
        /// Botswana (alpha-3 `BWA`, numeric `072`)
        Botswana => "BW", "Botswana",
        /// Belarus (alpha-3 `BLR`, numeric `112`)
        Belarus => "BY", "Belarus",
        /// Belize (alpha-3 `BLZ`, numeric `084`)
        Belize => "BZ", "Belize",
        /// Canada (alpha-3 `CAN`, numeric `124`)
        Canada => "CA", "Canada",
        /// Cocos (Keeling) Islands (the) (alpha-3 `CCK`, numeric `166`)
        CocosKeelingIslands => "CC", "Cocos (Keeling) Islands",
        /// Congo (the Democratic Republic of the) (alpha-3 `COD`, numeric `180`)
        DemocraticRepublicOfTheCongo => "CD", "Democratic Republic of the Congo",
        /// Central African Republic (the) (alpha-3 `CAF`, numeric `140`)
        CentralAfricanRepublic => "CF", "Central African Republic",
        /// Congo (the) (alpha-3 `COG`, numeric `178`)
        Congo => "CG", "Republic of the Congo",
        /// Switzerland (alpha-3 `CHE`, numeric `756`)
        Switzerland => "CH", "Switzerland",
        /// Côte d'Ivoire (alpha-3 `CIV`, numeric `384`)
        CoteDIvoire => "CI", "Cote d'Ivoire",
        /// Cook Islands (the) (alpha-3 `COK`, numeric `184`)
        CookIslands => "CK", "Cook Islands",
        /// Chile (alpha-3 `CHL`, numeric `152`)
        Chile => "CL", "Chile",
        /// Cameroon (alpha-3 `CMR`, numeric `120`)
        Cameroon => "CM", "Cameroon",
        /// China (alpha-3 `CHN`, numeric `156`)
        China => "CN", "China",
        /// Colombia (alpha-3 `COL`, numeric `170`)
        Colombia => "CO", "Colombia",
        /// Costa Rica (alpha-3 `CRI`, numeric `188`)
        CostaRica => "CR", "Costa Rica",
        /// Cuba (alpha-3 `CUB`, numeric `192`)
        Cuba => "CU", "Cuba",
        /// Cabo Verde (alpha-3 `CPV`, numeric `132`)
        CapeVerde => "CV", "Cape Verde",
        /// Curaçao (alpha-3 `CUW`, numeric `531`)
        Curacao => "CW", "Curacao",
        /// Christmas Island (alpha-3 `CXR`, numeric `162`)
        ChristmasIsland => "CX", "Christmas Island",
        /// Cyprus (alpha-3 `CYP`, numeric `196`)
        Cyprus => "CY", "Cyprus",
        /// Czechia (alpha-3 `CZE`, numeric `203`)
        CzechRepublic => "CZ", "Czechia",
        /// Germany (alpha-3 `DEU`, numeric `276`)
        Germany => "DE", "Germany",
        /// Djibouti (alpha-3 `DJI`, numeric `262`)
        Djibouti => "DJ", "Djibouti",
        /// Denmark (alpha-3 `DNK`, numeric `208`)
        Denmark => "DK", "Denmark",
        /// Dominica (alpha-3 `DMA`, numeric `212`)
        Dominica => "DM", "Dominica",
        /// Dominican Republic (the) (alpha-3 `DOM`, numeric `214`)
        DominicanRepublic => "DO", "Dominican Republic",
        /// Algeria (alpha-3 `DZA`, numeric `012`)
        Algeria => "DZ", "Algeria",
        /// Ecuador (alpha-3 `ECU`, numeric `218`)
        Ecuador => "EC", "Ecuador",
        /// Estonia (alpha-3 `EST`, numeric `233`)
        Estonia => "EE", "Estonia",
        /// Egypt (alpha-3 `EGY`, numeric `818`)
        Egypt => "EG", "Egypt",
        /// Western Sahara* (alpha-3 `ESH`, numeric `732`) — contested
        WesternSahara => "EH", "Western Sahara",
        /// Eritrea (alpha-3 `ERI`, numeric `232`)
        Eritrea => "ER", "Eritrea",
        /// Spain (alpha-3 `ESP`, numeric `724`)
        Spain => "ES", "Spain",
        /// Ethiopia (alpha-3 `ETH`, numeric `231`)
        Ethiopia => "ET", "Ethiopia",
        /// European Union (alpha-3 `—`, numeric `—`) — exceptionally reserved (not a country); commonly seen in geolocation data; no official ISO 3166-1 alpha-3 or numeric code
        EuropeanUnion => "EU", "European Union",
        /// Finland (alpha-3 `FIN`, numeric `246`)
        Finland => "FI", "Finland",
        /// Fiji (alpha-3 `FJI`, numeric `242`)
        Fiji => "FJ", "Fiji",
        /// Falkland Islands (the) \[Malvinas\] (alpha-3 `FLK`, numeric `238`) — contested
        FalklandIslands => "FK", "Falkland Islands",
        /// Micronesia (Federated States of) (alpha-3 `FSM`, numeric `583`)
        Micronesia => "FM", "Micronesia",
        /// Faroe Islands (the) (alpha-3 `FRO`, numeric `234`)
        FaroeIslands => "FO", "Faroe Islands",
        /// France (alpha-3 `FRA`, numeric `250`)
        France => "FR", "France",
        /// Gabon (alpha-3 `GAB`, numeric `266`)
        Gabon => "GA", "Gabon",
        /// United Kingdom of Great Britain and Northern Ireland (the) (alpha-3 `GBR`, numeric `826`)
        UnitedKingdom => "GB", "United Kingdom",
        /// Grenada (alpha-3 `GRD`, numeric `308`)
        Grenada => "GD", "Grenada",
        /// Georgia (alpha-3 `GEO`, numeric `268`)
        Georgia => "GE", "Georgia",
        /// French Guiana (alpha-3 `GUF`, numeric `254`)
        FrenchGuiana => "GF", "French Guiana",
        /// Guernsey (alpha-3 `GGY`, numeric `831`)
        Guernsey => "GG", "Guernsey",
        /// Ghana (alpha-3 `GHA`, numeric `288`)
        Ghana => "GH", "Ghana",
        /// Gibraltar (alpha-3 `GIB`, numeric `292`)
        Gibraltar => "GI", "Gibraltar",
        /// Greenland (alpha-3 `GRL`, numeric `304`)
        Greenland => "GL", "Greenland",
        /// Gambia (the) (alpha-3 `GMB`, numeric `270`)
        Gambia => "GM", "Gambia",
        /// Guinea (alpha-3 `GIN`, numeric `324`)
        Guinea => "GN", "Guinea",
        /// Guadeloupe (alpha-3 `GLP`, numeric `312`)
        Guadeloupe => "GP", "Guadeloupe",
        /// Equatorial Guinea (alpha-3 `GNQ`, numeric `226`)
        EquatorialGuinea => "GQ", "Equatorial Guinea",
        /// Greece (alpha-3 `GRC`, numeric `300`)
        Greece => "GR", "Greece",
        /// South Georgia and the South Sandwich Islands (alpha-3 `SGS`, numeric `239`)
        SouthGeorgiaAndTheSouthSandwichIslands => "GS", "South Georgia and the South Sandwich Islands",
        /// Guatemala (alpha-3 `GTM`, numeric `320`)
        Guatemala => "GT", "Guatemala",
        /// Guam (alpha-3 `GUM`, numeric `316`)
        Guam => "GU", "Guam",
        /// Guinea-Bissau (alpha-3 `GNB`, numeric `624`)
        GuineaBissau => "GW", "Guinea-Bissau",
        /// Guyana (alpha-3 `GUY`, numeric `328`)
        Guyana => "GY", "Guyana",
        /// Hong Kong (alpha-3 `HKG`, numeric `344`)
        HongKong => "HK", "Hong Kong",
        /// Heard Island and McDonald Islands (alpha-3 `HMD`, numeric `334`)
        HeardIslandAndMcDonaldIslands => "HM", "Heard Island and McDonald Islands",
        /// Honduras (alpha-3 `HND`, numeric `340`)
        Honduras => "HN", "Honduras",
        /// Croatia (alpha-3 `HRV`, numeric `191`)
        Croatia => "HR", "Croatia",
        /// Haiti (alpha-3 `HTI`, numeric `332`)
        Haiti => "HT", "Haiti",
        /// Hungary (alpha-3 `HUN`, numeric `348`)
        Hungary => "HU", "Hungary",
        /// Indonesia (alpha-3 `IDN`, numeric `360`)
        Indonesia => "ID", "Indonesia",
        /// Ireland (alpha-3 `IRL`, numeric `372`)
        Ireland => "IE", "Ireland",
        /// Israel (alpha-3 `ISR`, numeric `376`)
        Israel => "IL", "Israel",
        /// Isle of Man (alpha-3 `IMN`, numeric `833`)
        IsleOfMan => "IM", "Isle of Man",
        /// India (alpha-3 `IND`, numeric `356`)
        India => "IN", "India",
        /// British Indian Ocean Territory (the) (alpha-3 `IOT`, numeric `086`)
        BritishIndianOceanTerritory => "IO", "British Indian Ocean Territory",
        /// Iraq (alpha-3 `IRQ`, numeric `368`)
        Iraq => "IQ", "Iraq",
        /// Iran (Islamic Republic of) (alpha-3 `IRN`, numeric `364`)
        Iran => "IR", "Iran",
        /// Iceland (alpha-3 `ISL`, numeric `352`)
        Iceland => "IS", "Iceland",
        /// Italy (alpha-3 `ITA`, numeric `380`)
        Italy => "IT", "Italy",
        /// Jersey (alpha-3 `JEY`, numeric `832`)
        Jersey => "JE", "Jersey",
        /// Jamaica (alpha-3 `JAM`, numeric `388`)
        Jamaica => "JM", "Jamaica",
        /// Jordan (alpha-3 `JOR`, numeric `400`)
        Jordan => "JO", "Jordan",
        /// Japan (alpha-3 `JPN`, numeric `392`)
        Japan => "JP", "Japan",
        /// Kenya (alpha-3 `KEN`, numeric `404`)
        Kenya => "KE", "Kenya",
        /// Kyrgyzstan (alpha-3 `KGZ`, numeric `417`)
        Kyrgyzstan => "KG", "Kyrgyzstan",
        /// Cambodia (alpha-3 `KHM`, numeric `116`)
        Cambodia => "KH", "Cambodia",
        /// Kiribati (alpha-3 `KIR`, numeric `296`)
        Kiribati => "KI", "Kiribati",
        /// Comoros (the) (alpha-3 `COM`, numeric `174`)
        Comoros => "KM", "Comoros",
        /// Saint Kitts and Nevis (alpha-3 `KNA`, numeric `659`)
        SaintKittsAndNevis => "KN", "Saint Kitts and Nevis",
        /// Korea (the Democratic People's Republic of) (alpha-3 `PRK`, numeric `408`)
        NorthKorea => "KP", "North Korea",
        /// Korea (the Republic of) (alpha-3 `KOR`, numeric `410`)
        SouthKorea => "KR", "South Korea",
        /// Kuwait (alpha-3 `KWT`, numeric `414`)
        Kuwait => "KW", "Kuwait",
        /// Cayman Islands (the) (alpha-3 `CYM`, numeric `136`)
        CaymanIslands => "KY", "Cayman Islands",
        /// Kazakhstan (alpha-3 `KAZ`, numeric `398`)
        Kazakhstan => "KZ", "Kazakhstan",
        /// Lao People's Democratic Republic (the) (alpha-3 `LAO`, numeric `418`)
        Laos => "LA", "Laos",
        /// Lebanon (alpha-3 `LBN`, numeric `422`)
        Lebanon => "LB", "Lebanon",
        /// Saint Lucia (alpha-3 `LCA`, numeric `662`)
        SaintLucia => "LC", "Saint Lucia",
        /// Liechtenstein (alpha-3 `LIE`, numeric `438`)
        Liechtenstein => "LI", "Liechtenstein",
        /// Sri Lanka (alpha-3 `LKA`, numeric `144`)
        SriLanka => "LK", "Sri Lanka",
        /// Liberia (alpha-3 `LBR`, numeric `430`)
        Liberia => "LR", "Liberia",
        /// Lesotho (alpha-3 `LSO`, numeric `426`)
        Lesotho => "LS", "Lesotho",
        /// Lithuania (alpha-3 `LTU`, numeric `440`)
        Lithuania => "LT", "Lithuania",
        /// Luxembourg (alpha-3 `LUX`, numeric `442`)
        Luxembourg => "LU", "Luxembourg",
        /// Latvia (alpha-3 `LVA`, numeric `428`)
        Latvia => "LV", "Latvia",
        /// Libya (alpha-3 `LBY`, numeric `434`)
        Libya => "LY", "Libya",
        /// Morocco (alpha-3 `MAR`, numeric `504`)
        Morocco => "MA", "Morocco",
        /// Monaco (alpha-3 `MCO`, numeric `492`)
        Monaco => "MC", "Monaco",
        /// Moldova (the Republic of) (alpha-3 `MDA`, numeric `498`)
        Moldova => "MD", "Moldova",
        /// Montenegro (alpha-3 `MNE`, numeric `499`)
        Montenegro => "ME", "Montenegro",
        /// Saint Martin (French part) (alpha-3 `MAF`, numeric `663`)
        SaintMartin => "MF", "Saint Martin (French part)",
        /// Madagascar (alpha-3 `MDG`, numeric `450`)
        Madagascar => "MG", "Madagascar",
        /// Marshall Islands (the) (alpha-3 `MHL`, numeric `584`)
        MarshallIslands => "MH", "Marshall Islands",
        /// North Macedonia (alpha-3 `MKD`, numeric `807`)
        NorthMacedonia => "MK", "North Macedonia",
        /// Mali (alpha-3 `MLI`, numeric `466`)
        Mali => "ML", "Mali",
        /// Myanmar (alpha-3 `MMR`, numeric `104`)
        Myanmar => "MM", "Myanmar",
        /// Mongolia (alpha-3 `MNG`, numeric `496`)
        Mongolia => "MN", "Mongolia",
        /// Macao (alpha-3 `MAC`, numeric `446`)
        Macau => "MO", "Macau",
        /// Northern Mariana Islands (the) (alpha-3 `MNP`, numeric `580`)
        NorthernMarianaIslands => "MP", "Northern Mariana Islands",
        /// Martinique (alpha-3 `MTQ`, numeric `474`)
        Martinique => "MQ", "Martinique",
        /// Mauritania (alpha-3 `MRT`, numeric `478`)
        Mauritania => "MR", "Mauritania",
        /// Montserrat (alpha-3 `MSR`, numeric `500`)
        Montserrat => "MS", "Montserrat",
        /// Malta (alpha-3 `MLT`, numeric `470`)
        Malta => "MT", "Malta",
        /// Mauritius (alpha-3 `MUS`, numeric `480`)
        Mauritius => "MU", "Mauritius",
        /// Maldives (alpha-3 `MDV`, numeric `462`)
        Maldives => "MV", "Maldives",
        /// Malawi (alpha-3 `MWI`, numeric `454`)
        Malawi => "MW", "Malawi",
        /// Mexico (alpha-3 `MEX`, numeric `484`)
        Mexico => "MX", "Mexico",
        /// Malaysia (alpha-3 `MYS`, numeric `458`)
        Malaysia => "MY", "Malaysia",
        /// Mozambique (alpha-3 `MOZ`, numeric `508`)
        Mozambique => "MZ", "Mozambique",
        /// Namibia (alpha-3 `NAM`, numeric `516`)
        Namibia => "NA", "Namibia",
        /// New Caledonia (alpha-3 `NCL`, numeric `540`)
        NewCaledonia => "NC", "New Caledonia",
        /// Niger (the) (alpha-3 `NER`, numeric `562`)
        Niger => "NE", "Niger",
        /// Norfolk Island (alpha-3 `NFK`, numeric `574`)
        NorfolkIsland => "NF", "Norfolk Island",
        /// Nigeria (alpha-3 `NGA`, numeric `566`)
        Nigeria => "NG", "Nigeria",
        /// Nicaragua (alpha-3 `NIC`, numeric `558`)
        Nicaragua => "NI", "Nicaragua",
        /// Netherlands (the) (alpha-3 `NLD`, numeric `528`)
        Netherlands => "NL", "Netherlands",
        /// Norway (alpha-3 `NOR`, numeric `578`)
        Norway => "NO", "Norway",
        /// Nepal (alpha-3 `NPL`, numeric `524`)
        Nepal => "NP", "Nepal",
        /// Nauru (alpha-3 `NRU`, numeric `520`)
        Nauru => "NR", "Nauru",
        /// Niue (alpha-3 `NIU`, numeric `570`)
        Niue => "NU", "Niue",
        /// New Zealand (alpha-3 `NZL`, numeric `554`)
        NewZealand => "NZ", "New Zealand",
        /// Oman (alpha-3 `OMN`, numeric `512`)
        Oman => "OM", "Oman",
        /// Panama (alpha-3 `PAN`, numeric `591`)
        Panama => "PA", "Panama",
        /// Peru (alpha-3 `PER`, numeric `604`)
        Peru => "PE", "Peru",
        /// French Polynesia (alpha-3 `PYF`, numeric `258`)
        FrenchPolynesia => "PF", "French Polynesia",
        /// Papua New Guinea (alpha-3 `PNG`, numeric `598`)
        PapuaNewGuinea => "PG", "Papua New Guinea",
        /// Philippines (the) (alpha-3 `PHL`, numeric `608`)
        Philippines => "PH", "Philippines",
        /// Pakistan (alpha-3 `PAK`, numeric `586`)
        Pakistan => "PK", "Pakistan",
        /// Poland (alpha-3 `POL`, numeric `616`)
        Poland => "PL", "Poland",
        /// Saint Pierre and Miquelon (alpha-3 `SPM`, numeric `666`)
        SaintPierreAndMiquelon => "PM", "Saint Pierre and Miquelon",
        /// Pitcairn (alpha-3 `PCN`, numeric `612`)
        Pitcairn => "PN", "Pitcairn Islands",
        /// Puerto Rico (alpha-3 `PRI`, numeric `630`)
        PuertoRico => "PR", "Puerto Rico",
        /// Palestine, State of (alpha-3 `PSE`, numeric `275`) — contested
        Palestine => "PS", "Palestine",
        /// Portugal (alpha-3 `PRT`, numeric `620`)
        Portugal => "PT", "Portugal",
        /// Palau (alpha-3 `PLW`, numeric `585`)
        Palau => "PW", "Palau",
        /// Paraguay (alpha-3 `PRY`, numeric `600`)
        Paraguay => "PY", "Paraguay",
        /// Qatar (alpha-3 `QAT`, numeric `634`)
        Qatar => "QA", "Qatar",
        /// Reunion (alpha-3 `REU`, numeric `638`)
        Reunion => "RE", "Reunion",
        /// Romania (alpha-3 `ROU`, numeric `642`)
        Romania => "RO", "Romania",
        /// Serbia (alpha-3 `SRB`, numeric `688`)
        Serbia => "RS", "Serbia",
        /// Russian Federation (the) (alpha-3 `RUS`, numeric `643`)
        Russia => "RU", "Russia",
        /// Rwanda (alpha-3 `RWA`, numeric `646`)
        Rwanda => "RW", "Rwanda",
        /// Saudi Arabia (alpha-3 `SAU`, numeric `682`)
        SaudiArabia => "SA", "Saudi Arabia",
        /// Solomon Islands (alpha-3 `SLB`, numeric `090`)
        SolomonIslands => "SB", "Solomon Islands",
        /// Seychelles (alpha-3 `SYC`, numeric `690`)
        Seychelles => "SC", "Seychelles",
        /// Sudan (the) (alpha-3 `SDN`, numeric `729`)
        Sudan => "SD", "Sudan",
        /// Sweden (alpha-3 `SWE`, numeric `752`)
        Sweden => "SE", "Sweden",
        /// Singapore (alpha-3 `SGP`, numeric `702`)
        Singapore => "SG", "Singapore",
        /// Saint Helena, Ascension and Tristan da Cunha (alpha-3 `SHN`, numeric `654`)
        SaintHelena => "SH", "Saint Helena, Ascension and Tristan da Cunha",
        /// Slovenia (alpha-3 `SVN`, numeric `705`)
        Slovenia => "SI", "Slovenia",
        /// Svalbard and Jan Mayen (alpha-3 `SJM`, numeric `744`)
        SvalbardAndJanMayen => "SJ", "Svalbard and Jan Mayen",
        /// Slovakia (alpha-3 `SVK`, numeric `703`)
        Slovakia => "SK", "Slovakia",
        /// Sierra Leone (alpha-3 `SLE`, numeric `694`)
        SierraLeone => "SL", "Sierra Leone",
        /// San Marino (alpha-3 `SMR`, numeric `674`)
        SanMarino => "SM", "San Marino",
        /// Senegal (alpha-3 `SEN`, numeric `686`)
        Senegal => "SN", "Senegal",
        /// Somalia (alpha-3 `SOM`, numeric `706`)
        Somalia => "SO", "Somalia",
        /// Suriname (alpha-3 `SUR`, numeric `740`)
        Suriname => "SR", "Suriname",
        /// South Sudan (alpha-3 `SSD`, numeric `728`)
        SouthSudan => "SS", "South Sudan",
        /// Sao Tome and Principe (alpha-3 `STP`, numeric `678`)
        SaoTomeAndPrincipe => "ST", "Sao Tome and Principe",
        /// El Salvador (alpha-3 `SLV`, numeric `222`)
        ElSalvador => "SV", "El Salvador",
        /// Sint Maarten (Dutch part) (alpha-3 `SXM`, numeric `534`)
        SintMaarten => "SX", "Sint Maarten",
        /// Syrian Arab Republic (the) (alpha-3 `SYR`, numeric `760`)
        Syria => "SY", "Syria",
        /// Eswatini (alpha-3 `SWZ`, numeric `748`)
        Eswatini => "SZ", "Eswatini",
        /// Turks and Caicos Islands (the) (alpha-3 `TCA`, numeric `796`)
        TurksAndCaicosIslands => "TC", "Turks and Caicos Islands",
        /// Chad (alpha-3 `TCD`, numeric `148`)
        Chad => "TD", "Chad",
        /// French Southern Territories (the) (alpha-3 `ATF`, numeric `260`)
        FrenchSouthernTerritories => "TF", "French Southern Territories",
        /// Togo (alpha-3 `TGO`, numeric `768`)
        Togo => "TG", "Togo",
        /// Thailand (alpha-3 `THA`, numeric `764`)
        Thailand => "TH", "Thailand",
        /// Tajikistan (alpha-3 `TJK`, numeric `762`)
        Tajikistan => "TJ", "Tajikistan",
        /// Tokelau (alpha-3 `TKL`, numeric `772`)
        Tokelau => "TK", "Tokelau",
        /// Timor-Leste (alpha-3 `TLS`, numeric `626`)
        TimorLeste => "TL", "Timor-Leste",
        /// Turkmenistan (alpha-3 `TKM`, numeric `795`)
        Turkmenistan => "TM", "Turkmenistan",
        /// Tunisia (alpha-3 `TUN`, numeric `788`)
        Tunisia => "TN", "Tunisia",
        /// Tonga (alpha-3 `TON`, numeric `776`)
        Tonga => "TO", "Tonga",
        /// Türkiye (alpha-3 `TUR`, numeric `792`)
        Turkey => "TR", "Turkey",
        /// Trinidad and Tobago (alpha-3 `TTO`, numeric `780`)
        TrinidadAndTobago => "TT", "Trinidad and Tobago",
        /// Tuvalu (alpha-3 `TUV`, numeric `798`)
        Tuvalu => "TV", "Tuvalu",
        /// Taiwan (Province of China) (alpha-3 `TWN`, numeric `158`) — contested
        Taiwan => "TW", "Taiwan",
        /// Tanzania, the United Republic of (alpha-3 `TZA`, numeric `834`)
        Tanzania => "TZ", "Tanzania",
        /// Ukraine (alpha-3 `UKR`, numeric `804`)
        Ukraine => "UA", "Ukraine",
        /// Uganda (alpha-3 `UGA`, numeric `800`)
        Uganda => "UG", "Uganda",
        /// United States Minor Outlying Islands (the) (alpha-3 `UMI`, numeric `581`)
        UnitedStatesMinorOutlyingIslands => "UM", "United States Minor Outlying Islands",
        /// United States of America (the) (alpha-3 `USA`, numeric `840`)
        UnitedStates => "US", "United States",
        /// Uruguay (alpha-3 `URY`, numeric `858`)
        Uruguay => "UY", "Uruguay",
        /// Uzbekistan (alpha-3 `UZB`, numeric `860`)
        Uzbekistan => "UZ", "Uzbekistan",
        /// Holy See (the) (alpha-3 `VAT`, numeric `336`)
        VaticanCity => "VA", "Vatican City",
        /// Saint Vincent and the Grenadines (alpha-3 `VCT`, numeric `670`)
        SaintVincentAndTheGrenadines => "VC", "Saint Vincent and the Grenadines",
        /// Venezuela (Bolivarian Republic of) (alpha-3 `VEN`, numeric `862`)
        Venezuela => "VE", "Venezuela",
        /// Virgin Islands (British) (alpha-3 `VGB`, numeric `092`)
        BritishVirginIslands => "VG", "British Virgin Islands",
        /// Virgin Islands (U.S.) (alpha-3 `VIR`, numeric `850`)
        UnitedStatesVirginIslands => "VI", "U.S. Virgin Islands",
        /// Viet Nam (alpha-3 `VNM`, numeric `704`)
        Vietnam => "VN", "Vietnam",
        /// Vanuatu (alpha-3 `VUT`, numeric `548`)
        Vanuatu => "VU", "Vanuatu",
        /// Wallis and Futuna (alpha-3 `WLF`, numeric `876`)
        WallisAndFutuna => "WF", "Wallis and Futuna",
        /// Samoa (alpha-3 `WSM`, numeric `882`)
        Samoa => "WS", "Samoa",
        /// Kosovo (alpha-3 `XKX`, numeric `983`) — user-assigned (not officially in ISO 3166-1); XKX/983 are common de-facto conventions used by EU/IMF/geolocation data; contested
        Kosovo => "XK", "Kosovo",
        /// Yemen (alpha-3 `YEM`, numeric `887`)
        Yemen => "YE", "Yemen",
        /// Mayotte (alpha-3 `MYT`, numeric `175`)
        Mayotte => "YT", "Mayotte",
        /// South Africa (alpha-3 `ZAF`, numeric `710`)
        SouthAfrica => "ZA", "South Africa",
        /// Zambia (alpha-3 `ZMB`, numeric `894`)
        Zambia => "ZM", "Zambia",
        /// Zimbabwe (alpha-3 `ZWE`, numeric `716`)
        Zimbabwe => "ZW", "Zimbabwe",
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
    fn every_known_code_roundtrips() {
        // exhaustive: parsing each canonical code yields a known variant whose
        // code() returns the same string.
        for code in CODES {
            let c = Country::from_code(code);
            assert!(c.is_known(), "{code} should be known");
            assert_eq!(c.code(), *code);
        }
    }

    const CODES: &[&str] = &[
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX",
        "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
        "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK",
        "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
        "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "EU", "FI", "FJ", "FK", "FM", "FO",
        "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR",
        "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM",
        "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM",
        "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU",
        "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP",
        "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG",
        "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL",
        "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB",
        "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST",
        "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
        "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG",
        "VI", "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
    ];
}
