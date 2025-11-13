use clap::ValueEnum;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum TlsVersion {
    #[value(name = TlsVersion::NAME_V10)]
    V10,
    #[value(name = TlsVersion::NAME_V11)]
    V11,
    #[value(name = TlsVersion::NAME_V12)]
    V12,
    #[value(name = TlsVersion::NAME_V13)]
    V13,
}

impl TlsVersion {
    const NAME_V10: &'static str = "1.0";
    const NAME_V11: &'static str = "1.1";
    const NAME_V12: &'static str = "1.2";
    const NAME_V13: &'static str = "1.3";
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V10 => Self::NAME_V10,
            Self::V11 => Self::NAME_V11,
            Self::V12 => Self::NAME_V12,
            Self::V13 => Self::NAME_V13,
        }
        .fmt(f)
    }
}
