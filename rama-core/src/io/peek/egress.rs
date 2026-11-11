use super::PeekVerdict;

/// Judges the bytes the egress (server) side sent while a peek waits for the client.
///
/// | Verdict | Meaning | Effect |
/// |---|---|---|
/// | `Match` | definitively the server side of this protocol | keep waiting for the client; stop reading egress |
/// | `NeedMore` | a valid prefix of it so far | keep waiting; read more egress |
/// | `Reject` | cannot be this protocol, whatever follows | [`PeekCutoff::EgressMismatch`] |
///
/// Implementations must be prefix-closed (once `Reject` or `Match`, always the
/// same for any extension) and only `Reject` bytes a standard client of the
/// protocol refuses as the start of the server's side; when unsure, `NeedMore`.
/// Reaching the egress size limit while `NeedMore` keeps waiting.
///
/// A `Match` keeps the peek waiting for the client, so a server-first
/// protocol whose opening matches waits until the client speaks or the
/// scope the input runs in ends: bound that scope where this matters.
/// Once settled the egress is not read again, so a server closing after a
/// matching opening is seen by the service that follows the verdict.
///
/// Closures `Fn(&[u8]) -> PeekVerdict<()>` implement it and peek the egress.
///
/// [`PeekCutoff::EgressMismatch`]: super::PeekCutoff::EgressMismatch
pub trait PeekEgressPredicate: Send + Sync {
    /// Judge the egress bytes received so far, never empty.
    fn egress(&self, bytes: &[u8]) -> PeekVerdict<()>;

    /// Whether the egress is read at all.
    fn peeks_egress(&self) -> bool;
}

impl<F> PeekEgressPredicate for F
where
    F: Fn(&[u8]) -> PeekVerdict<()> + Send + Sync,
{
    #[inline(always)]
    fn egress(&self, bytes: &[u8]) -> PeekVerdict<()> {
        self(bytes)
    }

    #[inline(always)]
    fn peeks_egress(&self) -> bool {
        true
    }
}

/// A [`PeekEgressPredicate`] that never reads the egress.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NoEgressPeek;

impl PeekEgressPredicate for NoEgressPeek {
    #[inline(always)]
    fn egress(&self, _bytes: &[u8]) -> PeekVerdict<()> {
        PeekVerdict::NeedMore
    }

    #[inline(always)]
    fn peeks_egress(&self) -> bool {
        false
    }
}

/// A [`PeekEgressPredicate`] for a server that opens with a fixed prefix,
/// mirroring [`PeekRouter::from_prefix`] for the ingress.
///
/// [`PeekRouter::from_prefix`]: super::PeekRouter::from_prefix
#[derive(Debug, Clone, Copy)]
pub struct PeekEgressPrefix(&'static [u8]);

impl PeekEgressPrefix {
    /// Expect the egress to open with `prefix`.
    ///
    /// # Panics
    ///
    /// Panics when `prefix` is empty.
    #[must_use]
    pub const fn new(prefix: &'static [u8]) -> Self {
        assert!(!prefix.is_empty(), "egress prefix must not be empty");
        Self(prefix)
    }
}

impl PeekEgressPredicate for PeekEgressPrefix {
    fn egress(&self, bytes: &[u8]) -> PeekVerdict<()> {
        super::prefix_peek_verdict(bytes, self.0)
    }

    #[inline(always)]
    fn peeks_egress(&self) -> bool {
        true
    }
}

/// A [`PeekEgressPredicate`] for a client-first protocol: any egress byte is a mismatch.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ClientFirstEgress;

impl PeekEgressPredicate for ClientFirstEgress {
    #[inline(always)]
    fn egress(&self, _bytes: &[u8]) -> PeekVerdict<()> {
        PeekVerdict::Reject
    }

    #[inline(always)]
    fn peeks_egress(&self) -> bool {
        true
    }
}
