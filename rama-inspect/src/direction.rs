//! Traffic direction relative to the inspecting proxy.

use std::{fmt, str::FromStr};

use rama_core::error::{BoxError, BoxErrorExt as _};
use serde::{Deserialize, Serialize};

/// The two directions of a proxied flow, independent of message protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// From the downstream client towards the upstream server.
    Ingress,
    /// From the upstream server towards the downstream client.
    Egress,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Direction {
    type Err = BoxError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("ingress") {
            Ok(Self::Ingress)
        } else if value.eq_ignore_ascii_case("egress") {
            Ok(Self::Egress)
        } else {
            Err(BoxError::from_static_str(
                "direction must be ingress or egress",
            ))
        }
    }
}
