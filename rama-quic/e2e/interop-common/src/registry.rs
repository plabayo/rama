//! The shared cases and the runner that executes them, so a case added here runs in every peer
//! project without any of them being edited.

use std::{fmt, future::Future};

use rama::utils::octets;

use crate::{
    identity::{Identity, server_identity},
    scenario::{Chunk, StreamScenario},
    support::Deadline,
};

/// Which end Rama is in a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Rama opens the connection and the peer answers it.
    RamaClient,
    /// The peer opens the connection and Rama answers it.
    RamaServer,
}

impl Role {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RamaClient => "rama-client",
            Self::RamaServer => "rama-server",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One shared case: a name and the parameters that are the single source for every peer.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: &'static str,
    pub scenario: StreamScenario,
}

/// Every case each eligible peer runs, in both roles. Adding one here runs it everywhere.
#[must_use]
pub fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "stream-baseline",
            scenario: StreamScenario {
                up: Chunk {
                    seed: 0x11,
                    len: octets::kib(64),
                },
                question: Chunk {
                    seed: 0x22,
                    len: octets::kib(4),
                },
                answer: Chunk {
                    seed: 0x33,
                    len: octets::kib(8),
                },
            },
        },
        // Different lengths and seeds through the same code, so a peer that quietly kept its
        // own parameters carries the wrong bytes here.
        Case {
            name: "stream-compact",
            scenario: StreamScenario {
                up: Chunk {
                    seed: 0x44,
                    len: octets::kib(3),
                },
                question: Chunk {
                    seed: 0x55,
                    len: 777,
                },
                answer: Chunk {
                    seed: 0x66,
                    len: octets::kib(2) + 5,
                },
            },
        },
    ]
}

/// One case being run: its name for failures, its parameters, the identity in play and the
/// deadline every await under it shares.
#[derive(Debug, Clone)]
pub struct CaseRun {
    pub what: String,
    pub scenario: StreamScenario,
    pub identity: Identity,
    pub deadline: Deadline,
    pub role: Role,
}

impl CaseRun {
    /// The same case with an identity of the peer's own making, for a peer that needs one in a
    /// form only it can produce — files on disk, say. The payloads are unaffected: they come
    /// from the registry and nowhere else.
    #[must_use]
    pub fn with_identity(self, identity: Identity) -> Self {
        Self { identity, ..self }
    }
}

/// Run `body` once for every shared case in `role`. [`cases`] is the only list an adapter
/// iterates, so a case added there reaches every peer project without any of them being
/// edited. What `body` does with a case is the adapter's own business.
pub async fn for_each_case<F, Fut>(peer: &'static str, role: Role, mut body: F)
where
    F: FnMut(CaseRun) -> Fut,
    Fut: Future<Output = ()>,
{
    let all = cases();
    assert!(!all.is_empty(), "the registry names at least one case");
    for case in all {
        let run = CaseRun {
            what: format!("{peer}/{}/{role}", case.name),
            scenario: case.scenario,
            identity: server_identity(),
            deadline: Deadline::new(),
            role,
        };
        body(run).await;
    }
}

/// Why a peer does not run a case. Reported alongside the passes, never in place of one.
#[derive(Debug, Clone)]
pub struct Unsupported {
    pub case: &'static str,
    pub peer: &'static str,
    pub reason: &'static str,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} does not run {}: {}",
            self.peer, self.case, self.reason
        )
    }
}
