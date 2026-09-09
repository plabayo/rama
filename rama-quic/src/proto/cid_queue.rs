use std::net::SocketAddr;
use std::ops::Range;

use rama_core::telemetry::tracing::warn;

use crate::proto::{ConnectionId, ResetToken, frame::NewConnectionId};

/// A remote connection ID with its sequence number and, unless it is the initial one before the
/// peer's transport parameters arrived, its stateless reset token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemCid {
    pub(crate) seq: u64,
    pub(crate) id: ConnectionId,
    pub(crate) reset_token: Option<ResetToken>,
    /// The addresses a datagram carrying this identifier has actually reached the network for,
    /// least recently used first.
    ///
    /// RFC 9000 §10.3.1 ties recognition to the identifier *and* the address it was sent to, so
    /// this is a set rather than a flag. It lives here so that it travels with the identifier:
    /// moving one between the active, held, reserved, bound and unused sets cannot grant a
    /// history it does not have, nor take one away, and only retirement — which drops the value —
    /// ends it. Two addresses are kept, which is what a NAT rebinding needs: the address in use
    /// and the one the previous path may still answer from. A third displaces the one that
    /// stopped being used, which is why the order is by recency and not by arrival.
    sent_to: [Option<Association>; Self::REMOTES],
}

/// One route to this connection: an identifier at an address.
///
/// The generation names this installation, so an acknowledgement or a release that was in flight
/// cannot be applied to a later installation that happens to reuse the same identifier and
/// address.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Association {
    pub(crate) remote: SocketAddr,
    pub(crate) generation: u64,
    /// Whether a datagram carrying this identifier has actually reached the network for `remote`.
    /// The route is installed before the first one does, so no reset can race it, but until it
    /// has, a reset carrying this token is not ours (RFC 9000 §10.3.1).
    sent: bool,
    /// Whether the endpoint has been told about this route. A route recorded before the peer named
    /// the identifier's token has nothing to install yet and is announced once it does, which is
    /// how the identifier the handshake sends with keeps the history it earned.
    announced: bool,
    /// Whether the endpoint has confirmed the route exists. Until it has, a datagram carrying this
    /// identifier must not go to this address, or a reset answering it could arrive before there
    /// is anything to route it by.
    installed: bool,
}

/// What the endpoint's routing has to be told after a route was touched. Both fields empty means
/// nothing changed, which is the case for every ordinary send and every retry of one.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub(crate) struct RouteDelta {
    /// A route the endpoint does not have yet.
    pub(crate) added: Option<Association>,
    /// A route displaced by `added`, whose address had gone longest without a send.
    pub(crate) released: Option<Association>,
}

impl RouteDelta {
    pub(crate) fn is_empty(&self) -> bool {
        self.added.is_none() && self.released.is_none()
    }
}

/// The addresses a path role currently owns for an identifier: the address the current path sends
/// to, and the one a retained previous or fallback path answers from.
///
/// Recency does not decide what is still live — moving off a path that was never validated keeps
/// the *original* as the fallback, so the address in the middle is the one that stopped being
/// relevant. A role's association is never displaced by transient history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OwnedRemotes {
    pub(crate) current: Option<SocketAddr>,
    pub(crate) fallback: Option<SocketAddr>,
}

impl OwnedRemotes {
    pub(crate) fn owns(&self, remote: SocketAddr) -> bool {
        self.current == Some(remote) || self.fallback == Some(remote)
    }
}

impl RemCid {
    /// How many addresses one identifier can be recognised at, derived from the roles that can
    /// own it at once: the current path, a retained previous or fallback path, and one address
    /// that is neither but that a descriptor already accepted in part was sent to. A fourth would
    /// mean a role we do not have.
    pub(crate) const REMOTES: usize = 3;

    /// The token a stateless reset from `remote` must carry to reset us with this identifier, or
    /// `None` when nothing has gone out with it towards that address.
    pub(crate) fn used_reset_token(&self, remote: SocketAddr) -> Option<ResetToken> {
        self.reset_token.filter(|_| self.is_sent_to(remote))
    }

    /// Whether a datagram carrying this identifier has gone out at all.
    pub(crate) fn is_sent(&self) -> bool {
        self.associations().any(|assoc| assoc.sent)
    }

    /// Whether a datagram carrying this identifier has gone out towards `remote`.
    pub(crate) fn is_sent_to(&self, remote: SocketAddr) -> bool {
        self.associations()
            .any(|assoc| assoc.remote == remote && assoc.sent)
    }

    /// How many of the slots hold a route. They are kept packed from the front, so this is also
    /// where the next one goes.
    fn filled(&self) -> usize {
        self.sent_to
            .iter()
            .position(Option::is_none)
            .unwrap_or(Self::REMOTES)
    }

    /// Whether this identifier may be sent to `remote`: the route has to exist first, and an
    /// identifier with no token has no route to wait for.
    pub(crate) fn is_installed_for(&self, remote: SocketAddr) -> bool {
        if self.reset_token.is_none() {
            // The peer has not named a token for this identifier, so there is no route for a
            // reset to arrive by and nothing to wait for. The handshake sends like this.
            return true;
        }
        self.associations()
            .find(|assoc| assoc.remote == remote)
            .is_some_and(|assoc| assoc.installed)
    }

    /// The addresses this identifier is recognised at, least recently used first.
    pub(crate) fn associations(&self) -> impl Iterator<Item = Association> + '_ {
        self.sent_to.iter().flatten().copied()
    }

    /// Make sure this identifier has a route to `remote`, and say what the endpoint has to be
    /// told. `sent` records that a datagram has actually reached the network for it; installing a
    /// route does not, and cannot un-send what already has.
    ///
    /// `generation` names a new installation and is only consumed by one.
    fn route_to(
        &mut self,
        remote: SocketAddr,
        generation: u64,
        sent: bool,
        token_known: bool,
        owned: OwnedRemotes,
    ) -> RouteDelta {
        if let Some(at) = self
            .sent_to
            .iter()
            .position(|slot| slot.is_some_and(|assoc| assoc.remote == remote))
        {
            // This address is in use, so it is the other one that is next to give way. Only the
            // filled slots rotate: they are kept packed, oldest first.
            let filled = self.filled();
            self.sent_to[at..filled].rotate_left(1);
            // The refreshed route is now the most recent of the filled slots.
            let Some(assoc) = self.sent_to.get_mut(filled - 1).and_then(Option::as_mut) else {
                return RouteDelta::default();
            };
            assoc.sent |= sent;
            if token_known && !assoc.announced {
                // Recorded before the peer named this identifier's token: what is new is the
                // route, not the use, so it is installed now with the history it already has.
                assoc.announced = true;
                assoc.generation = generation;
                return RouteDelta {
                    added: Some(*assoc),
                    released: None,
                };
            }
            return RouteDelta::default();
        }
        let added = Association {
            remote,
            generation,
            sent,
            announced: token_known,
            // Nothing to wait for when there is no token to route by.
            installed: !token_known,
        };
        let filled = self.filled();
        if let Some(slot) = self.sent_to.get_mut(filled) {
            *slot = Some(added);
            return RouteDelta {
                added: token_known.then_some(added),
                released: None,
            };
        }
        // Bounded: something has to give way, and it must not be an address a path role still
        // owns. The oldest unowned one goes, which is the address that stopped being relevant.
        let victim = self
            .sent_to
            .iter()
            .position(|slot| slot.is_some_and(|assoc| !owned.owns(assoc.remote)))
            .unwrap_or_else(|| {
                // Every slot owned means more live roles than roles exist. Keeping the oldest
                // route out of the record is still better than dropping a live one silently, and
                // it is said out loud rather than assumed away.
                warn!(
                    %remote,
                    "no unowned address to displace for a connection ID; keeping the oldest"
                );
                0
            });
        let released = self.sent_to[victim]
            .replace(added)
            // A route the endpoint was never told about has nothing to release.
            .filter(|released| released.announced);
        // The new one is the most recent, and the rest keep their order.
        self.sent_to[victim..].rotate_left(1);
        RouteDelta {
            added: token_known.then_some(added),
            released,
        }
    }
}

/// The identifiers a peer's retirement took out of the sets kept aside for paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetiredAside {
    /// The one kept for a previous path.
    pub(crate) held: Option<u64>,
    /// The one set aside for a candidate path.
    pub(crate) reserved: Option<u64>,
    /// The ones bound to a path of their own.
    pub(crate) bound: [Option<u64>; CidQueue::LEN],
}

impl RetiredAside {
    /// The ones kept for the previous and the candidate path, for assertions.
    #[cfg(test)]
    pub(crate) fn kept_aside(&self) -> [Option<u64>; 2] {
        assert!(
            self.bound.iter().all(Option::is_none),
            "an identifier bound to a path was retired: {:?}",
            self.bound
        );
        [self.held, self.reserved]
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        [self.held, self.reserved]
            .into_iter()
            .chain(self.bound.iter().copied())
            .flatten()
    }
}

/// Sequence numbers to retire after a switch of the active connection ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Retired {
    /// The identifier that was active (empty when it is kept aside instead).
    pub(crate) previous: Range<u64>,
    /// Numbers skipped on the way to the new active one: never received and not retired before,
    /// in runs around the identifiers the connection still holds.
    pub(crate) skipped: [Range<u64>; CidQueue::SKIPPED_RUNS],
}

impl Retired {
    pub(crate) fn iter(&self) -> impl Iterator<Item = Range<u64>> {
        std::iter::once(self.previous.clone())
            .chain(self.skipped.iter().cloned())
            .filter(|range| !range.is_empty())
    }

    /// Whether nothing is retired.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// The skipped numbers, for assertions.
    #[cfg(test)]
    pub(crate) fn skipped(&self) -> Vec<u64> {
        self.skipped.iter().cloned().flatten().collect()
    }
}

/// The remote connection IDs the peer issued and we have not retired (RFC 9000 §5.1).
///
/// Every identifier is bound to at most one path: the active one is sent on the current path,
/// a held one stays with the previous path while the current one is validated, a reserved one is
/// set aside for a candidate path, and the unused ones wait for their turn. All of them count
/// towards the limit we advertised to the peer, and only those: a sequence number we never
/// received costs nothing, so a peer that leaves gaps as paths come and go does not shrink the
/// window it may fill.
#[derive(Debug)]
pub(crate) struct CidQueue {
    active: RemCid,
    held: Option<RemCid>,
    reserved: Option<RemCid>,
    /// Identifiers bound to a path of their own, so that an answer on a path this connection does
    /// not otherwise send on carries an identifier that is not sent anywhere else (RFC 9000 §9.5).
    bound: [Option<RemCid>; Self::LEN],
    /// Bounded by the limit: the active identifier takes one of the peer's slots.
    unused: [Option<RemCid>; Self::LEN],
    /// Every sequence number below this one is either present here or retired.
    floor: u64,
}

impl CidQueue {
    pub(crate) fn new(cid: ConnectionId) -> Self {
        Self {
            active: RemCid {
                seq: 0,
                id: cid,
                reset_token: None,
                // The handshake sends with this one before the peer has named a token for it, so
                // its history begins when the first datagram is reported, like any other.
                sent_to: [None; RemCid::REMOTES],
            },
            held: None,
            reserved: None,
            bound: [None; Self::LEN],
            unused: [None; Self::LEN],
            floor: 0,
        }
    }

    fn present(&self) -> impl Iterator<Item = RemCid> + '_ {
        [Some(self.active), self.held, self.reserved]
            .into_iter()
            .chain(self.bound.iter().copied())
            .chain(self.unused.iter().copied())
            .flatten()
    }

    fn present_mut(&mut self) -> impl Iterator<Item = &mut RemCid> + '_ {
        [&mut self.active]
            .into_iter()
            .chain(self.held.iter_mut())
            .chain(self.reserved.iter_mut())
            .chain(self.bound.iter_mut().flatten())
            .chain(self.unused.iter_mut().flatten())
    }

    fn lowest_unused(&self) -> Option<(usize, RemCid)> {
        self.unused
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.map(|c| (i, c)))
            .min_by_key(|(_, c)| c.seq)
    }

    /// The never-received, not yet retired numbers between `previous` (exclusive) and `next`
    /// (exclusive): everything from the floor on, minus the identifiers kept aside.

    fn skipped_between(&self, previous: u64, next: u64) -> [Range<u64>; Self::SKIPPED_RUNS] {
        let mut runs = [const { 0..0 }; Self::SKIPPED_RUNS];
        let mut start = (previous + 1).max(self.floor);
        let mut kept = [0u64; Self::SKIPPED_RUNS];
        let mut count = 0;
        for cid in self.present() {
            if (start..next).contains(&cid.seq)
                && let Some(slot) = kept.get_mut(count)
            {
                *slot = cid.seq;
                count += 1;
            }
        }
        let Some(kept) = kept.get_mut(..count) else {
            return runs;
        };
        kept.sort_unstable();
        let mut run = 0;
        for &seq in kept.iter() {
            if let Some(slot) = runs.get_mut(run) {
                *slot = start..seq;
                run += 1;
            }
            start = seq + 1;
        }
        if let Some(slot) = runs.get_mut(run) {
            *slot = start..next.max(start);
        }
        runs
    }

    /// Everything below `seq` inclusive is now present or retired.
    fn retired_up_to(&mut self, seq: u64) {
        self.floor = self.floor.max(seq + 1);
    }

    /// Handle a `NEW_CONNECTION_ID` frame
    ///
    /// Returns a non-empty range of retired sequence numbers and the reset token of the new active
    /// CID iff the frame retired the active one. An ID kept aside whose sequence the frame retires
    /// must be let go by the caller before this call ([`retire_aside`](Self::retire_aside)).
    pub(crate) fn insert(
        &mut self,
        cid: NewConnectionId,
    ) -> Result<Option<(Range<u64>, ResetToken)>, InsertError> {
        // A retransmitted or reordered copy of an identifier we hold still carries its
        // `retire_prior_to`; one we let go of already is refused.
        let duplicate = self.present().any(|c| c.seq == cid.sequence);
        if !duplicate && cid.sequence < self.floor {
            return Err(InsertError::Retired);
        }
        // The peer may not leave us holding more identifiers than the limit we advertised. What
        // this frame retires does not count, and neither does a number we never received: a
        // connection that retires identifiers one at a time, as paths come and go, leaves gaps
        // that say nothing about how many the peer considers active. Counting what we hold is
        // what bounds us, and it is arithmetic that cannot wrap.
        let retire_prior_to = cid.retire_prior_to;
        let kept = self
            .present()
            .filter(|held| held.seq >= retire_prior_to && held.seq != cid.sequence)
            .count();
        if kept + 1 > Self::LEN {
            return Err(InsertError::ExceedsLimit);
        }

        // Discard retired unused CIDs, if any
        for slot in &mut self.unused {
            if slot.is_some_and(|c| c.seq < retire_prior_to) {
                *slot = None;
            }
        }
        // Record the new CID
        if !duplicate {
            let new = RemCid {
                seq: cid.sequence,
                id: cid.id,
                reset_token: Some(cid.reset_token),
                sent_to: [None; RemCid::REMOTES],
            };
            if let Some(slot) = self.unused.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(new);
            } else {
                // The bound above admits at most `LEN` identifiers, one of them active.
                return Err(InsertError::ExceedsLimit);
            }
        }
        self.floor = self.floor.max(retire_prior_to);

        if self.active.seq >= retire_prior_to {
            return Ok(None);
        }
        // The active CID was retired: switch to the lowest identifier at or past
        // `retire_prior_to` (at least the one just recorded is), and tell the caller which
        // sequence numbers that retires. Numbers never received beyond `LEN` past the old active
        // one are left alone: had the peer issued them we would have hit the limit; should they
        // arrive later they are refused as retired then.
        let previous = self.active.seq;
        let Some((index, next)) = self.lowest_unused() else {
            return Err(InsertError::ExceedsLimit);
        };
        self.unused[index] = None;
        self.active = next;
        self.floor = self.floor.max(next.seq);
        let token = next.reset_token.ok_or(InsertError::ExceedsLimit)?;
        Ok(Some((
            previous..next.seq.min(previous + Self::LEN as u64),
            token,
        )))
    }

    /// Make the lowest unused identifier active; `keep_previous` puts the one that was active
    /// aside as held instead of retiring it.
    fn switch(&mut self, keep_previous: bool) -> Option<(ResetToken, Retired)> {
        if keep_previous && self.held.is_some() {
            return None;
        }
        let (index, next) = self.lowest_unused()?;
        let token = next.reset_token?;
        self.unused[index] = None;
        let previous = std::mem::replace(&mut self.active, next);
        let skipped = self.skipped_between(previous.seq, next.seq);
        let retired = Retired {
            previous: if keep_previous {
                self.held = Some(previous);
                previous.seq..previous.seq
            } else {
                previous.seq..previous.seq + 1
            },
            skipped,
        };
        self.retired_up_to(next.seq - 1);
        Some((token, retired))
    }

    /// Switch to next active CID if possible, return
    /// 1) the corresponding ResetToken and 2) the sequence numbers to retire
    pub(crate) fn next(&mut self) -> Option<(ResetToken, Retired)> {
        self.switch(false)
    }

    /// Switch to the next active CID while keeping the current one aside for the path it was used
    /// on. Fails when nothing is unused or an identifier is held already.
    pub(crate) fn next_holding(&mut self) -> Option<(ResetToken, Retired)> {
        self.switch(true)
    }

    /// The previously active ID kept for its path, if any.
    pub(crate) fn held(&self) -> Option<RemCid> {
        self.held
    }

    /// Let go of the held ID; the caller retires the returned sequence number.
    pub(crate) fn retire_held(&mut self) -> Option<u64> {
        let seq = self.held.take()?.seq;
        self.retired_up_to(seq);
        Some(seq)
    }

    /// Make the held ID active again (its path is current once more) and drop the ID that was
    /// active, which the caller retires: it was used towards a path now abandoned.
    pub(crate) fn restore_held(&mut self) -> Option<u64> {
        let held = self.held.take()?;
        let abandoned = std::mem::replace(&mut self.active, held);
        self.retired_up_to(abandoned.seq);
        Some(abandoned.seq)
    }

    /// Set the lowest unused ID aside for a candidate path. Fails when none is unused or one is
    /// already reserved.
    pub(crate) fn reserve(&mut self) -> Option<RemCid> {
        if self.reserved.is_some() {
            return None;
        }
        let (index, next) = self.lowest_unused()?;
        self.unused[index] = None;
        self.reserved = Some(next);
        Some(next)
    }

    /// Set the identifier with this sequence number aside for a candidate path, if it is still
    /// unused and nothing is reserved yet.
    pub(crate) fn reserve_seq(&mut self, seq: u64) -> Option<RemCid> {
        if self.reserved.is_some() {
            return None;
        }
        let index = self
            .unused
            .iter()
            .position(|c| c.is_some_and(|c| c.seq == seq))?;
        let cid = self.unused[index].take()?;
        self.reserved = Some(cid);
        Some(cid)
    }

    /// The ID reserved for a candidate path, if any.
    #[cfg(test)]
    pub(crate) fn reserved(&self) -> Option<RemCid> {
        self.reserved
    }

    /// Give the reservation up; the caller retires the returned sequence number.
    pub(crate) fn release_reserved(&mut self) -> Option<u64> {
        let seq = self.reserved.take()?.seq;
        self.retired_up_to(seq);
        Some(seq)
    }

    /// Make the reserved ID the active one (its candidate path became the current path). Returns
    /// its reset token and the sequence numbers to retire: the ID that was active, and the
    /// never-received numbers between it and the promoted one.
    pub(crate) fn promote_reserved(&mut self) -> Option<(ResetToken, Retired)> {
        let reserved = self.reserved.take()?;
        let token = reserved.reset_token?;
        let previous = std::mem::replace(&mut self.active, reserved);
        // A reservation the ring has moved past leaves nothing in between, which the run
        // computation says by itself.
        let skipped = self.skipped_between(previous.seq, reserved.seq);
        let retired = Retired {
            previous: previous.seq..previous.seq + 1,
            skipped,
        };
        self.retired_up_to(previous.seq);
        self.retired_up_to(reserved.seq.saturating_sub(1));
        Some((token, retired))
    }

    /// Drop the aside IDs whose sequence a NEW_CONNECTION_ID frame retires (`retire_prior_to`),
    /// returning their sequence numbers for the caller to retire.
    pub(crate) fn retire_aside(&mut self, retire_prior_to: u64) -> RetiredAside {
        let held = self
            .held
            .take_if(|c| c.seq < retire_prior_to)
            .map(|c| c.seq);
        let reserved = self
            .reserved
            .take_if(|c| c.seq < retire_prior_to)
            .map(|c| c.seq);
        let mut bound = [None; Self::LEN];
        for (slot, taken) in self.bound.iter_mut().zip(bound.iter_mut()) {
            *taken = slot.take_if(|c| c.seq < retire_prior_to).map(|c| c.seq);
        }
        let aside = RetiredAside {
            held,
            reserved,
            bound,
        };
        for seq in aside.iter() {
            self.retired_up_to(seq);
        }
        aside
    }

    /// Take an unused identifier for a path of its own, leaving `keep` of them unused. It stops
    /// being unused and stays present, so it keeps counting towards the limit until it is
    /// retired; leaving some behind is what stops a path this connection does not send on from
    /// spending the identifiers a move of its own will need.
    pub(crate) fn bind_unused(&mut self, keep: usize) -> Option<RemCid> {
        let slot = self.bound.iter().position(Option::is_none)?;
        if self.unused.iter().flatten().count() <= keep {
            return None;
        }
        let (index, cid) = self.lowest_unused()?;
        self.unused[index] = None;
        self.bound[slot] = Some(cid);
        Some(cid)
    }

    /// Whether the identifier numbered `seq` is bound to a path of its own. A binding lasts until
    /// the peer retires the identifier ([`retire_aside`](Self::retire_aside)); nothing else lets
    /// it go, which is what keeps it from being sent from a second local address.
    pub(crate) fn is_bound(&self, seq: u64) -> bool {
        self.bound.iter().flatten().any(|c| c.seq == seq)
    }

    /// Replace the initial CID
    pub(crate) fn update_initial_cid(&mut self, cid: ConnectionId) {
        debug_assert_eq!(self.active.seq, 0);
        self.active.id = cid;
    }

    /// Record the reset token the peer's transport parameters gave for the initial CID.
    pub(crate) fn set_initial_reset_token(&mut self, token: ResetToken) {
        if self.active.seq == 0 {
            self.active.reset_token = Some(token);
        }
    }

    /// Whether a connection ID beyond the active one is available to switch to.
    pub(crate) fn has_unused(&self) -> bool {
        self.unused.iter().any(Option::is_some)
    }

    /// The unused identifiers, for assertions.
    #[cfg(test)]
    pub(crate) fn unused(&self) -> Vec<RemCid> {
        self.unused.iter().flatten().copied().collect()
    }

    /// Return active remote CID itself
    pub(crate) fn active(&self) -> ConnectionId {
        self.active.id
    }

    /// The reset token of the active remote CID, once known.
    pub(crate) fn active_reset_token(&self) -> Option<ResetToken> {
        self.active.reset_token
    }

    /// The reset tokens of the identifiers in use: the active one and the one held for the
    /// previous path. A reset carrying any of them is ours (RFC 9000 §10.3.1); the tokens of
    /// unused identifiers are not checked.
    /// The tokens that can reset this connection: one for every identifier a datagram has
    /// actually gone out with and that is not retired (RFC 9000 §10.3.1). An identifier that only
    /// changed role, or one moved aside before anything was sent with it, is not among them.
    pub(crate) fn used_reset_tokens(
        &self,
        remote: SocketAddr,
    ) -> [Option<ResetToken>; Self::PRESENT] {
        let mut tokens = [None; Self::PRESENT];
        for (slot, cid) in tokens.iter_mut().zip(self.present()) {
            *slot = cid.used_reset_token(remote);
        }
        tokens
    }

    /// How many associations this queue holds, which is what the endpoint's routing table has to
    /// be able to hold at once.
    #[cfg(test)]
    pub(crate) fn live_associations(&self) -> usize {
        self.present().map(|cid| cid.associations().count()).sum()
    }

    /// The endpoint has installed the route for `seq` at `remote`, when that is still the
    /// installation `generation` names. An acknowledgement for anything else is stale and does
    /// nothing: it cannot revive a retired identifier, nor open one a newer installation owns.
    pub(crate) fn route_installed(&mut self, seq: u64, remote: SocketAddr, generation: u64) {
        let Some(cid) = self.present_mut().find(|cid| cid.seq == seq) else {
            return;
        };
        for assoc in cid.sent_to.iter_mut().flatten() {
            if assoc.remote == remote && assoc.generation == generation {
                assoc.installed = true;
            }
        }
    }

    /// Whether a datagram carrying the identifier numbered `seq` may go to `remote` yet.
    pub(crate) fn is_installed(&self, seq: u64, remote: SocketAddr) -> bool {
        self.present()
            .find(|cid| cid.seq == seq)
            .is_some_and(|cid| cid.is_installed_for(remote))
    }

    /// Record that the sender has put a datagram carrying the identifier numbered `seq` on the
    /// network towards `remote`, wherever that identifier currently sits, and report what the
    /// endpoint's routing has to be told. `generation` names this installation.
    ///
    /// Nothing is reported for a send that changes nothing, so an ordinary send and a retried one
    /// publish nothing and allocate nothing.
    pub(crate) fn mark_sent(
        &mut self,
        seq: u64,
        remote: SocketAddr,
        generation: u64,
        owned: OwnedRemotes,
    ) -> Option<(RouteDelta, ResetToken)> {
        self.route(seq, remote, generation, true, owned)
    }

    /// Install a route to `remote` for the identifier numbered `seq` without claiming anything
    /// has been sent with it, so that a reset cannot arrive before the endpoint can place it.
    pub(crate) fn install_route(
        &mut self,
        seq: u64,
        remote: SocketAddr,
        generation: u64,
        owned: OwnedRemotes,
    ) -> Option<(RouteDelta, ResetToken)> {
        self.route(seq, remote, generation, false, owned)
    }

    fn route(
        &mut self,
        seq: u64,
        remote: SocketAddr,
        generation: u64,
        sent: bool,
        owned: OwnedRemotes,
    ) -> Option<(RouteDelta, ResetToken)> {
        let cid = self.present_mut().find(|cid| cid.seq == seq)?;
        let token = cid.reset_token;
        // An identifier whose token the peer has not named yet has no route to install; the
        // record is kept, so the route follows when the token arrives.
        let delta = cid.route_to(remote, generation, sent, token.is_some(), owned);
        if delta.is_empty() {
            return None;
        }
        Some((delta, token?))
    }

    /// Whether a datagram carrying the identifier numbered `seq` has gone out. An identifier we do
    /// not hold has no history to report.
    pub(crate) fn is_sent(&self, seq: u64) -> bool {
        self.present().any(|cid| cid.seq == seq && cid.is_sent())
    }

    /// Whether a datagram carrying the identifier numbered `seq` has gone out towards `remote`.
    pub(crate) fn is_sent_to(&self, seq: u64, remote: SocketAddr) -> bool {
        self.present()
            .any(|cid| cid.seq == seq && cid.is_sent_to(remote))
    }

    /// Return the sequence number of active remote CID
    pub(crate) fn active_seq(&self) -> u64 {
        self.active.seq
    }

    pub(crate) const LEN: usize = 5;

    /// Identifiers that can be present at once: the active one, one kept for a previous path, one
    /// reserved for a candidate, the ones bound to a path of their own, and the unused ones.
    pub(crate) const PRESENT: usize = 3 + Self::LEN + Self::LEN;

    /// Runs of retired numbers a switch can produce: one more than the identifiers it can hold.
    const SKIPPED_RUNS: usize = Self::LEN + 3;
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum InsertError {
    /// CID was already retired
    Retired,
    /// Sequence number violates the leading edge of the window
    ExceedsLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(sequence: u64, retire_prior_to: u64) -> NewConnectionId {
        NewConnectionId {
            sequence,
            id: ConnectionId::new(&[0xAB; 8]),
            reset_token: ResetToken::from([0xCD; crate::proto::RESET_TOKEN_SIZE]),
            retire_prior_to,
        }
    }

    fn initial_cid() -> ConnectionId {
        ConnectionId::new(&[0xFF; 8])
    }

    /// A token distinguishable per identifier, so a test can say which one would reset us.
    fn token(n: u8) -> ResetToken {
        ResetToken::from([n; crate::proto::RESET_TOKEN_SIZE])
    }

    /// A `NEW_CONNECTION_ID` whose token names its sequence number.
    fn cid_token(sequence: u64, retire_prior_to: u64) -> NewConnectionId {
        NewConnectionId {
            sequence,
            id: ConnectionId::new(&[sequence as u8; 8]),
            reset_token: token(sequence as u8),
            retire_prior_to,
        }
    }

    #[test]
    fn next_dense() {
        let mut q = CidQueue::new(initial_cid());
        assert!(q.next().is_none());
        assert!(q.next().is_none());

        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i, 0)).unwrap();
        }
        for i in 1..CidQueue::LEN as u64 {
            let (_, retire) = q.next().unwrap();
            assert_eq!(q.active_seq(), i);
            assert_eq!(retire.previous, i - 1..i);
            assert!(retire.skipped().is_empty());
        }
        assert!(q.next().is_none());
    }
    #[test]
    fn next_sparse() {
        let mut q = CidQueue::new(initial_cid());
        let seqs = (1..CidQueue::LEN as u64).filter(|x| x % 2 == 0);
        for i in seqs.clone() {
            q.insert(cid(i, 0)).unwrap();
        }
        for i in seqs {
            let (_, retire) = q.next().unwrap();
            assert_eq!(q.active_seq(), i);
            // The identifier that was active and the never-received one between are retired.
            assert_eq!(retire.previous, i - 2..i - 1);
            assert_eq!(retire.skipped(), vec![i - 1]);
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn wrap() {
        let mut q = CidQueue::new(initial_cid());

        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i, 0)).unwrap();
        }
        for _ in 1..(CidQueue::LEN as u64 - 1) {
            q.next().unwrap();
        }
        for i in CidQueue::LEN as u64..(CidQueue::LEN as u64 + 3) {
            q.insert(cid(i, 0)).unwrap();
        }
        for i in (CidQueue::LEN as u64 - 1)..(CidQueue::LEN as u64 + 3) {
            q.next().unwrap();
            assert_eq!(q.active_seq(), i);
        }
        assert!(q.next().is_none());
    }

    #[test]
    fn retire_dense() {
        let mut q = CidQueue::new(initial_cid());

        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i, 0)).unwrap();
        }
        assert_eq!(q.active_seq(), 0);

        assert_eq!(q.insert(cid(4, 2)).unwrap().unwrap().0, 0..2);
        assert_eq!(q.active_seq(), 2);
        assert_eq!(q.insert(cid(4, 2)), Ok(None));

        for i in 2..(CidQueue::LEN as u64 - 1) {
            let _ = q.next().unwrap();
            assert_eq!(q.active_seq(), i + 1);
            assert_eq!(q.insert(cid(i + 1, i + 1)), Ok(None));
        }

        assert!(q.next().is_none());
    }

    #[test]
    fn retire_sparse() {
        // Retiring CID 0 when CID 1 is not known should retire CID 1 as we move to CID 2
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(2, 0)).unwrap();
        assert_eq!(q.insert(cid(3, 1)).unwrap().unwrap().0, 0..2,);
        assert_eq!(q.active_seq(), 2);
    }

    /// Switching while holding keeps the old ID aside: it stays out of the ring, the peer's
    /// window still starts at it, and restoring it makes it active again while the ID used
    /// meanwhile is the one to retire.
    #[test]
    fn a_held_id_is_restored_and_the_one_used_meanwhile_retired() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i, 0)).unwrap();
        }
        let (_, retired) = q.next_holding().unwrap();
        assert!(
            retired.is_empty(),
            "nothing retired: 0 is held, 1 follows it"
        );
        assert_eq!(q.active_seq(), 1);
        assert_eq!(q.held().unwrap().seq, 0);
        assert_eq!(q.held().unwrap().id, initial_cid());
        // The held ID still counts against the peer's limit: LEN identifiers are present.
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64, 0)),
            Err(InsertError::ExceedsLimit)
        );
        assert_eq!(q.restore_held(), Some(1));
        assert_eq!(q.active_seq(), 0);
        assert_eq!(q.active(), initial_cid());
        assert!(q.held().is_none());
        // 1 is gone (refused as retired should it come again); 2 is the next unused.
        assert_eq!(q.insert(cid(1, 0)), Err(InsertError::Retired));
        let (_, retired) = q.next().unwrap();
        assert_eq!(retired.previous, 0..1);
        assert!(retired.skipped().is_empty(), "1 was retired already");
        assert_eq!(q.active_seq(), 2);
    }

    /// An identifier kept aside counts against the limit like any other, and letting it go makes
    /// room for one more.
    #[test]
    fn a_held_id_counts_against_the_limit_until_it_is_let_go() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i, 0)).unwrap();
        }
        q.next_holding().unwrap(); // held 0, active 1, unused 2..4: five in hand
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64, 0)),
            Err(InsertError::ExceedsLimit),
            "a sixth identifier is more than we advertised"
        );
        assert_eq!(q.retire_held(), Some(0));
        assert_eq!(q.insert(cid(CidQueue::LEN as u64, 0)), Ok(None));
        assert!(q.next_holding().is_some(), "holding is possible again");
    }

    /// A retire_prior_to that covers an aside ID takes it away before the frame is applied.
    #[test]
    fn retire_prior_to_takes_aside_ids() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..4 {
            q.insert(cid(i, 0)).unwrap();
        }
        q.next_holding().unwrap(); // held 0, active 1
        let reserved = q.reserve().unwrap(); // reserved 2
        assert_eq!(reserved.seq, 2);
        assert_eq!(q.retire_aside(2).kept_aside(), [Some(0), None]);
        assert_eq!(q.retire_aside(3).kept_aside(), [None, Some(2)]);
        assert!(q.held().is_none() && q.reserved().is_none());
        let (retired, _) = q.insert(cid(4, 3)).unwrap().unwrap();
        assert_eq!(retired, 1..3);
        assert_eq!(q.active_seq(), 3);
    }

    /// A reserved ID is invisible to `next` and `has_unused`, and promoting it retires the active
    /// ID and every ID in between.
    #[test]
    fn a_reserved_id_is_skipped_until_promoted() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(1, 0)).unwrap();
        let reserved = q.reserve().unwrap();
        assert_eq!(reserved.seq, 1);
        assert!(!q.has_unused());
        assert!(q.next().is_none());
        assert!(q.reserve().is_none(), "one reservation at a time");
        q.insert(cid(2, 0)).unwrap();
        assert!(q.has_unused());
        let (_, retired) = q.promote_reserved().unwrap();
        assert_eq!(retired.previous, 0..1);
        assert!(retired.skipped().is_empty());
        assert_eq!(q.active_seq(), 1);
        assert_eq!(q.reserved(), None);
        // 2 is still there to switch to.
        let (_, retired) = q.next().unwrap();
        assert_eq!(retired.previous, 1..2);
    }

    /// Promoting after the ring moved past the reservation puts it back in front; the released
    /// alternative just drops it.
    #[test]
    fn a_reservation_survives_switches_and_can_be_released() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..4 {
            q.insert(cid(i, 0)).unwrap();
        }
        let reserved = q.reserve().unwrap(); // 1
        let (_, retired) = q.next().unwrap(); // active 2
        assert_eq!(retired.previous, 0..1);
        assert!(
            retired.skipped().is_empty(),
            "the reserved 1 is not skipped, it is kept"
        );
        assert_eq!(q.active_seq(), 2);
        assert_eq!(q.reserved(), Some(reserved));
        let (_, retired) = q.promote_reserved().unwrap();
        assert_eq!(retired.previous, 2..3);
        assert!(retired.skipped().is_empty());
        assert_eq!(q.active_seq(), 1);
        assert_eq!(q.active(), reserved.id);
        // 3 remains unused after it; 2 was retired already.
        let (_, retired) = q.next().unwrap();
        assert_eq!(retired.previous, 1..2);
        assert!(retired.skipped().is_empty());
        assert_eq!(q.active_seq(), 3);

        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(1, 0)).unwrap();
        q.reserve().unwrap();
        assert_eq!(q.release_reserved(), Some(1));
        assert!(!q.has_unused());
        assert_eq!(
            q.insert(cid(1, 0)),
            Err(InsertError::Retired),
            "a released reservation is retired for good"
        );
        assert_eq!(
            q.insert(cid(2, 0)),
            Ok(None),
            "its slot goes to the next one"
        );
        assert!(q.has_unused());
    }

    /// Numbers never received between two active identifiers are retired, except those kept
    /// aside (held or reserved), which stay bound to their paths.
    #[test]
    fn skipped_numbers_leave_out_the_aside_ones() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(1, 0)).unwrap();
        q.insert(cid(4, 0)).unwrap();
        q.next_holding().unwrap(); // held 0, active 1
        q.insert(cid(2, 0)).unwrap();
        q.reserve().unwrap(); // reserved 2 (the lowest unused)
        let (_, retired) = q.next().unwrap(); // active 4
        assert_eq!(retired.previous, 1..2);
        assert_eq!(
            retired.skipped(),
            vec![3],
            "2 is reserved, 3 was never received"
        );
        assert_eq!(q.held().unwrap().seq, 0);
        assert_eq!(q.reserved().unwrap().seq, 2);
        // Late arrival of 3: already retired.
        assert_eq!(q.insert(cid(3, 0)), Err(InsertError::Retired));
    }

    /// Numbers on both sides of an identifier the connection keeps are retired, in the two runs
    /// around it.
    #[test]
    fn skipped_runs_go_around_a_kept_id() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(2, 0)).unwrap();
        q.next_holding().unwrap(); // held 0, active 2, 1 retired
        assert_eq!(q.retire_held(), Some(0));
        q.insert(cid(4, 0)).unwrap();
        q.reserve_seq(4).expect("4 is unused");
        q.insert(cid(6, 0)).unwrap();
        let (_, retired) = q.next_holding().unwrap(); // held 2, active 6
        assert!(retired.previous.is_empty(), "2 is kept, not retired");
        assert_eq!(
            retired.skipped(),
            vec![3, 5],
            "4 is reserved; 3 and 5 were never received and sit on either side of it"
        );
        assert_eq!(q.held().map(|c| c.seq), Some(2));
        assert_eq!(q.reserved().map(|c| c.seq), Some(4));
    }

    /// A specific unused identifier can be set aside, not only the lowest one.
    #[test]
    fn a_named_sequence_can_be_reserved() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(1, 0)).unwrap();
        q.insert(cid(2, 0)).unwrap();
        let reserved = q.reserve_seq(2).expect("2 is unused");
        assert_eq!(reserved.seq, 2);
        assert!(q.reserve_seq(2).is_none(), "one reservation at a time");
        // 1 is still there to switch to.
        let (_, retired) = q.next().unwrap();
        assert_eq!(q.active_seq(), 1);
        assert_eq!(retired.previous, 0..1);
        assert!(retired.skipped().is_empty());
        assert!(
            q.reserve_seq(9).is_none(),
            "an unknown sequence is not unused"
        );
    }

    /// Promoting a reservation past never-received numbers retires those as well as the identifier
    /// that was active.
    #[test]
    fn promoting_forward_retires_what_it_passes() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(1, 0)).unwrap();
        q.insert(cid(4, 0)).unwrap();
        let reserved = q.reserve_seq(4).expect("4 is unused");
        assert_eq!(reserved.seq, 4);
        let (_, retired) = q.promote_reserved().unwrap();
        assert_eq!(q.active_seq(), 4);
        assert_eq!(retired.previous, 0..1);
        assert_eq!(
            retired.skipped(),
            vec![2, 3],
            "1 is still ours, only the numbers we never received are retired"
        );
        assert!(q.has_unused(), "the identifier we hold stays usable");
        let (_, retired) = q.next().unwrap();
        assert_eq!(q.active_seq(), 1, "and it can still be switched to");
        assert_eq!(retired.previous, 4..5);
        assert!(retired.skipped().is_empty());
    }

    /// `retire_prior_to` retires the numbers below it and leaves the one at it in place.
    #[test]
    fn retire_prior_to_keeps_the_id_at_its_own_number() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(1, 0)).unwrap();
        q.insert(cid(2, 0)).unwrap();
        q.next_holding().unwrap(); // held 0, active 1
        let reserved = q.reserve().unwrap(); // reserved 2
        assert_eq!(reserved.seq, 2);
        assert_eq!(
            q.retire_aside(0).kept_aside(),
            [None, None],
            "nothing is below zero"
        );
        assert_eq!(
            q.retire_aside(1).kept_aside(),
            [Some(0), None],
            "0 goes, 2 stays"
        );
        assert_eq!(q.reserved().map(|c| c.seq), Some(2));
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(1, 0)).unwrap();
        q.insert(cid(2, 0)).unwrap();
        q.next().unwrap(); // active 1
        q.reserve_seq(2).unwrap();
        assert_eq!(
            q.retire_aside(2).kept_aside(),
            [None, None],
            "the identifier at the bound stays"
        );
        assert_eq!(q.reserved().map(|c| c.seq), Some(2));
    }

    /// RFC 9000 §10.3.1 as an invariant of the identifier rather than of the connection: what a
    /// datagram has gone out with stays sent through every change of role, what has not been sent
    /// gains nothing by being moved, and retirement ends it.
    #[test]
    fn send_history_travels_with_the_identifier_and_no_role_change_invents_it() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..5 {
            q.insert(cid_token(i, 0)).unwrap();
        }
        q.set_initial_reset_token(token(0));
        let here: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let there: SocketAddr = "127.0.0.1:4434".parse().unwrap();
        let used = |q: &CidQueue, remote: SocketAddr| -> Vec<ResetToken> {
            q.used_reset_tokens(remote)
                .iter()
                .flatten()
                .copied()
                .collect()
        };
        q.mark_sent(0, here, 1, OwnedRemotes::default());
        assert_eq!(
            used(&q, here),
            vec![token(0)],
            "only the identifier the handshake sent with"
        );
        assert!(
            used(&q, there).is_empty(),
            "and only towards the address it was sent to"
        );

        // Switching to an unused identifier is not sending with it.
        q.next().expect("an unused identifier");
        assert_eq!(q.active_seq(), 1);
        assert!(!q.is_sent(1), "nothing has gone out with it yet");
        assert!(used(&q, here).is_empty(), "so nothing can reset us");
        q.mark_sent(1, here, 2, OwnedRemotes::default());
        assert_eq!(used(&q, here), vec![token(1)]);

        // Held: the one in use goes aside with its history, the replacement arrives without one.
        // An unconditional `held` would invent a history here.
        q.next_holding()
            .expect("an unused identifier, keeping the current");
        assert_eq!(q.held().map(|c| c.seq), Some(1));
        assert_eq!(q.active_seq(), 2);
        assert!(q.is_sent(1), "the one put aside had been sent");
        assert!(!q.is_sent(2), "the replacement had not");
        assert_eq!(
            used(&q, here),
            vec![token(1)],
            "the replacement's token resets nothing until it is sent"
        );

        // Restoring keeps each side of that straight.
        q.restore_held();
        assert_eq!(q.active_seq(), 1);
        assert!(q.is_sent(1));
        assert!(!q.is_sent(2) || q.held().is_none(), "2 gained no history");

        // Reserve then promote: a reservation is unsent when it becomes active.
        let reserved = q.reserve().expect("an unused identifier");
        assert!(!q.is_sent(reserved.seq));
        q.promote_reserved();
        assert_eq!(q.active_seq(), reserved.seq);
        assert!(!q.is_sent(reserved.seq), "promotion is not sending");
        assert!(!used(&q, here).contains(&token(reserved.seq as u8)));
        q.mark_sent(reserved.seq, here, 3, OwnedRemotes::default());
        assert!(used(&q, here).contains(&token(reserved.seq as u8)));

        // Binding to a path of its own: same rule, and retirement ends it.
        q.insert(cid_token(7, 0)).unwrap();
        let bound = q.bind_unused(0).expect("an unused identifier");
        assert!(!q.is_sent(bound.seq));
        q.mark_sent(bound.seq, there, 4, OwnedRemotes::default());
        assert!(q.is_sent(bound.seq));
        assert!(
            used(&q, there).contains(&token(bound.seq as u8)),
            "the address it was bound to recognises it"
        );
        assert!(
            !used(&q, here).contains(&token(bound.seq as u8)),
            "the address it was never sent to does not"
        );
        let aside = q.retire_aside(bound.seq + 1);
        assert!(
            aside.bound.iter().flatten().any(|&seq| seq == bound.seq),
            "the peer's retirement covered it"
        );
        assert!(!q.is_sent(bound.seq), "a retired identifier has no history");
        assert!(
            !used(&q, there).contains(&token(bound.seq as u8)),
            "and its token is no longer ours"
        );
    }

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, last], 4433))
    }

    /// The roles that own an address for an identifier at one moment.
    fn roles(current: SocketAddr, fallback: Option<SocketAddr>) -> OwnedRemotes {
        OwnedRemotes {
            current: Some(current),
            fallback,
        }
    }

    /// One identifier sent to a sequence of addresses, keeping a route for each until something
    /// has to give way. Returns the queue and the identifier's sequence number.
    fn queue_with_one_used_cid() -> (CidQueue, u64) {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid_token(1, 0)).unwrap();
        q.next().expect("an unused identifier");
        (q, 1)
    }

    /// Recency is not proof that an address stopped being relevant. Moving off a path that was
    /// never validated keeps the *original* as the fallback, so the address in the middle is the
    /// one that goes — never the one a path role still owns.
    #[test]
    fn a_role_owned_address_is_never_displaced_by_transient_history() {
        let (mut q, seq) = queue_with_one_used_cid();
        let (a, b, c, d) = (addr(1), addr(2), addr(3), addr(4));

        // A, then an unvalidated move to B, then on to C: A is still the fallback throughout.
        q.mark_sent(seq, a, 1, roles(a, None));
        q.mark_sent(seq, b, 2, roles(b, Some(a)));
        q.mark_sent(seq, c, 3, roles(c, Some(a)));
        for remote in [a, b, c] {
            assert!(q.is_sent_to(seq, remote), "{remote} is recognised");
        }

        // A fourth address has to displace something. B is the one no role owns.
        let (delta, _) = q
            .mark_sent(seq, d, 4, roles(d, Some(a)))
            .expect("a route to install");
        assert_eq!(
            delta.released.map(|r| r.remote),
            Some(b),
            "the address that stopped being relevant gives way"
        );
        assert!(
            q.is_sent_to(seq, a),
            "the fallback keeps its route: it is still live"
        );
        assert!(q.is_sent_to(seq, d), "and the address now in use has one");
        assert!(!q.is_sent_to(seq, b), "the one in between does not");
        assert_eq!(q.live_associations(), RemCid::REMOTES);
    }

    /// The small recency case: an address returned to is in use again, so the one that has gone
    /// longest without a send is the one that gives way.
    #[test]
    fn a_returning_address_keeps_its_route_and_the_idle_one_goes() {
        let (mut q, seq) = queue_with_one_used_cid();
        let (a, b, c, d) = (addr(1), addr(2), addr(3), addr(4));
        q.mark_sent(seq, a, 1, roles(a, None));
        q.mark_sent(seq, b, 2, roles(b, Some(a)));
        // Back to A: it is in use again, so B is now the idle one.
        q.mark_sent(seq, a, 3, roles(a, Some(b)));
        q.mark_sent(seq, c, 4, roles(c, Some(a)));
        let (delta, _) = q
            .mark_sent(seq, d, 5, roles(d, Some(a)))
            .expect("a route to install");
        assert_eq!(
            delta.released.map(|r| r.remote),
            Some(b),
            "B went longest without a send and no role owns it"
        );
        assert!(
            q.is_sent_to(seq, a),
            "A was used after B and is the fallback"
        );
        assert!(q.is_sent_to(seq, c));
        assert!(q.is_sent_to(seq, d));
    }

    /// However many times the peer moves, one identifier never holds more routes than the roles
    /// that can own it, and every displacement is reported so the endpoint can follow.
    #[test]
    fn many_moves_never_leave_more_routes_than_the_roles_can_own() {
        let (mut q, seq) = queue_with_one_used_cid();
        let home = addr(1);
        let mut installed = 0i64;
        q.mark_sent(seq, home, 0, roles(home, None));
        installed += 1;
        for step in 0..40u8 {
            let remote = addr(10 + step);
            let owned = roles(remote, Some(home));
            let Some((delta, _)) = q.mark_sent(seq, remote, step as u64 + 1, owned) else {
                continue;
            };
            installed += i64::from(delta.added.is_some());
            installed -= i64::from(delta.released.is_some());
            assert!(
                q.live_associations() <= RemCid::REMOTES,
                "step {step} left {} routes",
                q.live_associations()
            );
            assert!(
                q.is_sent_to(seq, home),
                "step {step} dropped the fallback nobody replaced"
            );
        }
        assert_eq!(
            installed,
            q.live_associations() as i64,
            "what was published matches what is held, so the endpoint cannot accumulate"
        );
    }

    /// The policy is that a switch retires the numbers it skipped, so a peer that jumps to the
    /// highest legal sequence number really does name a 2^62-wide run. Nothing here clamps it: what
    /// keeps that from becoming work is the retirement queue, which refuses an oversized range by
    /// arithmetic (see `a_range_too_wide_to_walk_is_refused_without_touching_the_queue`).
    #[test]
    fn a_distant_sequence_number_is_skipped_as_a_whole() {
        let mut q = CidQueue::new(initial_cid());
        let far = (1u64 << 62) - 1;
        q.insert(cid(far, 0)).expect("a distant number is legal");
        let (_, retired) = q.next().expect("the connection switches to it");
        assert_eq!(q.active_seq(), far);
        let runs: Vec<_> = retired.iter().collect();
        assert!(
            runs.iter().any(|r| r.end - r.start > CidQueue::LEN as u64),
            "the skipped numbers are named in full: {runs:?}"
        );
        // The numbers in between are refused from now on, which is the floor's work.
        assert!(matches!(
            q.insert(cid(far / 2, 0)),
            Err(InsertError::Retired)
        ));
    }

    /// Giving up a reservation at the highest sequence the peer has issued must not make a
    /// retransmission of an identifier we still hold fail: the limit is pinned by what we hold,
    /// not by a floor that has moved past the newest number.
    #[test]
    fn a_released_top_reservation_leaves_earlier_ids_insertable() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..5 {
            q.insert(cid(i, 0)).unwrap();
        }
        let reserved = q.reserve_seq(4).expect("4 is unused");
        assert_eq!(reserved.seq, 4);
        assert_eq!(q.release_reserved(), Some(4));
        // A retransmitted NEW_CONNECTION_ID for an identifier we still hold.
        assert_eq!(q.insert(cid(1, 0)), Ok(None));
        assert_eq!(q.active_seq(), 0);
        assert!(q.has_unused());
        // And one we let go of stays gone.
        assert_eq!(q.insert(cid(4, 0)), Err(InsertError::Retired));
    }

    /// The same shape with the highest identifier held rather than reserved, and with the active
    /// one restored from a held slot: neither makes a later insert fail or panic.
    #[test]
    fn a_restored_hold_leaves_the_window_pinned_by_what_we_hold() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..5 {
            q.insert(cid(i, 0)).unwrap();
        }
        q.next_holding().unwrap(); // held 0, active 1
        assert_eq!(q.restore_held(), Some(1));
        assert_eq!(q.active_seq(), 0);
        assert_eq!(q.insert(cid(2, 0)), Ok(None), "2 is still ours");
        assert_eq!(q.insert(cid(1, 0)), Err(InsertError::Retired));
        // We hold 0, 2, 3 and 4: one more fits, a second does not.
        assert_eq!(q.insert(cid(CidQueue::LEN as u64, 0)), Ok(None));
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64 + 1, 0)),
            Err(InsertError::ExceedsLimit)
        );
    }

    #[test]
    fn retire_many() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(2, 0)).unwrap();
        assert_eq!(
            q.insert(cid(1_000_000, 1_000_000)).unwrap().unwrap().0,
            0..CidQueue::LEN as u64,
        );
        assert_eq!(q.active_seq(), 1_000_000);
    }

    #[test]
    fn insert_limit() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..CidQueue::LEN as u64 {
            assert_eq!(q.insert(cid(i, 0)), Ok(None));
        }
        // The active one plus `LEN - 1` unused ones is the whole allowance.
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64, 0)),
            Err(InsertError::ExceedsLimit)
        );
        // Retiring one makes room again, and a frame that retires makes room for itself.
        q.next().unwrap();
        assert_eq!(q.insert(cid(CidQueue::LEN as u64, 0)), Ok(None));
    }

    #[test]
    fn insert_duplicate() {
        let mut q = CidQueue::new(initial_cid());
        q.insert(cid(0, 0)).unwrap();
        q.insert(cid(0, 0)).unwrap();
    }

    #[test]
    fn insert_retired() {
        let mut q = CidQueue::new(initial_cid());
        assert_eq!(
            q.insert(cid(0, 0)),
            Ok(None),
            "reinserting active CID succeeds"
        );
        assert!(q.next().is_none(), "active CID isn't requeued");
        q.insert(cid(1, 0)).unwrap();
        q.next().unwrap();
        assert_eq!(
            q.insert(cid(0, 0)),
            Err(InsertError::Retired),
            "previous active CID is already retired"
        );
    }

    #[test]
    fn retire_then_insert_next() {
        let mut q = CidQueue::new(initial_cid());
        for i in 1..CidQueue::LEN as u64 {
            q.insert(cid(i, 0)).unwrap();
        }
        q.next().unwrap();
        q.insert(cid(CidQueue::LEN as u64, 0)).unwrap();
        assert_eq!(
            q.insert(cid(CidQueue::LEN as u64 + 1, 0)),
            Err(InsertError::ExceedsLimit)
        );
    }

    #[test]
    fn always_valid() {
        let mut q = CidQueue::new(initial_cid());
        assert!(q.next().is_none());
        assert_eq!(q.active(), initial_cid());
        assert_eq!(q.active_seq(), 0);
    }
}
