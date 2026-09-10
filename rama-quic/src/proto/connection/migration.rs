//! Path transitions: following a peer that moves, moving this side, and the identifiers and
//! challenges each path carries while it is validated.

use std::{
    cmp, mem,
    net::{IpAddr, SocketAddr},
};

use rama_core::telemetry::tracing::trace;

use rand::RngExt;

use crate::proto::{
    Instant, TransportError,
    connection::{
        Connection, ConnectionSide, paths::PathData, preferred::PreferredAddressState, timer::Timer,
    },
    packet::SpaceId,
    shared::ConnectionId,
};

impl Connection {
    /// The peer's connection ID this connection may send on the path (`remote`, `local`), with its
    /// sequence number. A path this connection does not send on has none.
    pub(super) fn cid_for_path(
        &mut self,
        remote: SocketAddr,
        local: Option<SocketAddr>,
    ) -> Option<(ConnectionId, u64)> {
        if remote == self.path.remote && self.same_local(local) {
            return Some((self.rem_cids.active(), self.rem_cids.active_seq()));
        }
        if let Some(bound) = self
            .path_cids
            .iter()
            .flatten()
            .find(|bound| bound.remote == remote && bound.local == local)
        {
            return Some((bound.id, bound.seq));
        }
        if let Some(prev) = self.prev_path.as_ref()
            && prev.path.remote == remote
            && match (prev.path.local, local) {
                (Some(theirs), Some(ours)) => theirs == ours,
                _ => true,
            }
        {
            match prev.cid {
                PrevCid::Held => {
                    if let Some(held) = self.rem_cids.held() {
                        return Some((held.id, held.seq));
                    }
                }
                // A rebinding kept the identifier: the previous address already saw it.
                PrevCid::Active => {
                    return Some((self.rem_cids.active(), self.rem_cids.active_seq()));
                }
                // The identifier that path had is retired: it may take a fresh one of its own.
                PrevCid::Gone => {}
            }
        }
        self.bind_path_cid(remote, local)
    }

    /// Bind an unused identifier to the path (`remote`, `local`) so that what goes out there
    /// carries one that is sent from no other local address (RFC 9000 §9.5). The binding lasts as
    /// long as the identifier does: it never returns to the unused pool, and the connection can
    /// answer on as many such paths as the peer left it identifiers for. `None` means exhaustion.
    fn bind_path_cid(
        &mut self,
        remote: SocketAddr,
        local: Option<SocketAddr>,
    ) -> Option<(ConnectionId, u64)> {
        let slot = self.path_cids.iter().position(Option::is_none)?;
        // One identifier stays unused whatever arrives: a path we do not send on cannot spend
        // what a move of our own needs.
        let cid = self.rem_cids.bind_unused(1)?;
        // The endpoint routes a reset carrying this identifier's token to us from now on, so no
        // reset can arrive before the route exists; whether we treat such a reset as ours waits
        // for a datagram with it to have gone out.
        self.install_reset_route(cid.seq, remote);
        self.path_cids[slot] = Some(PathCid {
            remote,
            local,
            id: cid.id,
            seq: cid.seq,
        });
        trace!(%remote, ?local, seq = cid.seq, "bound a connection ID to that path");
        Some((cid.id, cid.seq))
    }

    /// Let go of the identifier numbered `seq` and of the path it was bound to.
    pub(super) fn drop_path_cid(&mut self, seq: u64) {
        for slot in &mut self.path_cids {
            if slot.is_some_and(|bound| bound.seq == seq) {
                *slot = None;
            }
        }
    }

    /// Whether this endpoint may migrate actively now (RFC 9000 §9, §18.2). Meaningful once the
    /// handshake is confirmed. The peer's `disable_active_migration` covers the address used
    /// during the handshake; a client that has moved to the address the server advertised as
    /// preferred is no longer on that address and may migrate from there (RFC 9000 §9.6.3).
    pub(crate) fn may_migrate_actively(&self) -> bool {
        !self.peer_params.disable_active_migration
            || self.preferred_state == PreferredAddressState::Validated
    }

    /// Whether a datagram arriving at our `local` address from an address other than the current
    /// path's may be followed to a new path (RFC 9000 §9, §18.2). A client follows no move of the
    /// peer's; a server that advertised no support for active migration follows none away from the
    /// address used during the handshake, but the peer moving on the address it advertised as
    /// preferred is not that move (RFC 9000 §9.6.3). Following it still validates the path and
    /// takes an unused identifier for it, as any other move does.
    pub(super) fn may_follow_peer_move(&self, local: Option<SocketAddr>) -> bool {
        match &self.side {
            ConnectionSide::Server { server_config } => {
                server_config.migration || Self::is_preferred_local(server_config, local)
            }
            ConnectionSide::Client { .. } => false,
        }
    }

    /// The latest socket address for this connection's peer
    pub(crate) fn remote_address(&self) -> SocketAddr {
        self.path.remote
    }

    /// The local IP address this connection's packets currently arrive on.
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// It is the local IP of the connection's current path, so it follows a migration between
    /// local sockets. `None` when no local address was passed to
    /// [`Endpoint::handle()`](crate::proto::Endpoint::handle) for this path's datagrams.
    /// The local address of the path this connection is sending on, when it knows it. The driver
    /// sends that path's datagrams from the socket bound there.
    /// Whether this connection has something to send on a path other than the one it sends on:
    /// an answer to a challenge that arrived elsewhere (RFC 9000 §8.2.2), or a path it has left
    /// whose challenge may still be answered (§9.3).
    pub(crate) fn serves_another_path(&self) -> bool {
        self.path_responses
            .has_off_path(self.path.remote, self.path.local)
            || self.prev_path.is_some()
    }

    pub(crate) fn path_local(&self) -> Option<SocketAddr> {
        self.path.local
    }

    pub(crate) fn local_ip(&self) -> Option<IpAddr> {
        self.path
            .local
            .map(|local| local.ip())
            .filter(|ip| !ip.is_unspecified())
    }

    /// Resets path-specific settings.
    ///
    /// This will force-reset several subsystems related to a specific network path.
    /// Currently this is the congestion controller, round-trip estimator, and the MTU
    /// discovery.
    ///
    /// This is useful when it is known the underlying network path has changed and the old
    /// state of these subsystems is no longer valid or optimal. In this case it might be
    /// faster or reduce loss to settle on optimal values by restarting from the initial
    /// configuration in the [`TransportConfig`](crate::proto::config::TransportConfig).
    pub(crate) fn path_changed(&mut self, now: Instant) {
        self.path.reset(now, &self.config);
    }

    /// Follow a peer move to `remote`/`local` (RFC 9000 §9.3). A NAT rebinding keeps the current
    /// connection ID; any other move takes an unused one first, so nothing is ever sent to the new
    /// tuple with an identifier used elsewhere. Returns `Ok(false)`, changing nothing, when the
    /// move needs an identifier and none is unused.
    pub(super) fn follow_peer_move(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        received_dcid: ConnectionId,
        nat_rebinding: bool,
    ) -> Result<bool, TransportError> {
        if !nat_rebinding && !self.rem_cids.has_unused() {
            return Ok(false);
        }
        // The path being replaced is kept as a fallback only while it was validated: an
        // unvalidated one is dropped, and an older kept path stays as it is.
        let keep_replaced = self.path.challenge.is_none();
        let (prev_cid, token) = if nat_rebinding {
            (PrevCid::Active, self.rem_cids.active_reset_token())
        } else {
            // Keeping the replaced path needs an identifier set aside for it; without one the
            // path is simply not kept, which is always safe.
            let (token, retired, prev_cid) = match keep_replaced
                .then(|| self.rem_cids.next_holding())
                .flatten()
            {
                Some((token, retired)) => (token, retired, PrevCid::Held),
                None => match self.rem_cids.next() {
                    Some((token, retired)) => (token, retired, PrevCid::Gone),
                    None => return Ok(false),
                },
            };
            self.retire_rem_cids(&retired)?;
            // An older path that was being sent with the identifier this switch just left behind
            // has no identifier of its own any more.
            if let Some(prev) = self.prev_path.as_mut()
                && prev.cid == PrevCid::Active
            {
                prev.cid = PrevCid::Gone;
            }
            (prev_cid, Some(token))
        };
        self.migrate(now, remote, local, PreviousPath::Keep(prev_cid));
        self.path.received_dcid = Some(received_dcid);
        if let Some(token) = token {
            self.set_reset_token(remote, token);
        }
        self.deferred_migration = None;
        self.spin = false;
        Ok(true)
    }

    /// The current path is validated: the previous one is abandoned and the identifier kept for
    /// it is retired (RFC 9000 §9.5).
    pub(super) fn drop_previous_path(&mut self) {
        if let Some(PrevPath { cid, .. }) = self.prev_path.take()
            && cid == PrevCid::Held
            && let Some(seq) = self.rem_cids.retire_held()
            && let Err(error) = self.retire_rem_cid(seq)
        {
            self.defer_error(error);
        }
    }

    /// The current path failed validation: return to the previous path when it is kept and has a
    /// connection ID to be sent with (RFC 9000 §9.5), otherwise stay on the current one.
    pub(super) fn abandon_current_path(&mut self, now: Instant) {
        if let Some(PrevPath { path: prev, cid }) = self.prev_path.take() {
            let usable = match cid {
                PrevCid::Held => match self.rem_cids.restore_held() {
                    Some(abandoned) => {
                        // The restored identifier is bound to the previous address again; the
                        // one used towards the failed path is retired.
                        if let Err(error) = self.retire_rem_cid(abandoned) {
                            self.defer_error(error);
                        }
                        if let Some(token) = self.rem_cids.active_reset_token() {
                            self.set_reset_token(prev.remote, token);
                        }
                        true
                    }
                    None => false,
                },
                PrevCid::Active => {
                    if let Some(token) = self.rem_cids.active_reset_token() {
                        self.set_reset_token(prev.remote, token);
                    }
                    true
                }
                PrevCid::Gone => match self.rem_cids.next() {
                    // The peer retired the previous path's identifier: return with a fresh one.
                    Some((token, retired)) => {
                        if let Err(error) = self.retire_rem_cids(&retired) {
                            self.defer_error(error);
                        }
                        self.set_reset_token(prev.remote, token);
                        true
                    }
                    None => false,
                },
            };
            if usable {
                self.path = prev;
                self.set_loss_detection_timer(now);
            } else {
                trace!("no connection ID for the previous path: staying on the unvalidated one");
            }
        }
        self.path.challenge = None;
        self.path.challenge_pending = false;
    }

    /// Whether a datagram received at `local` belongs to the current path's local address. An
    /// address unknown on either side tells us nothing, so only two known and different ones are
    /// off the current path.
    pub(super) fn same_local(&self, local: Option<SocketAddr>) -> bool {
        match (local, self.path.local) {
            (Some(arrived), Some(current)) => arrived == current,
            _ => true,
        }
    }

    /// Whether `remote` is an address this client is probing: a response is accepted from there
    /// though the connection has not moved.
    pub(super) fn probing_address(&self, remote: SocketAddr) -> bool {
        self.candidate.as_ref().is_some_and(|c| c.remote == remote)
    }

    pub(super) fn migrate(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        previous: PreviousPath,
    ) {
        trace!(%remote, ?local, "migration initiated");
        self.path_counter = self.path_counter.wrapping_add(1);
        // Reset rtt/congestion state for new path unless it looks like a NAT rebinding.
        // Note that the congestion window will not grow until validation terminates. Helps mitigate
        // amplification attacks performed by spoofing source addresses.
        let mut new_path = if remote.is_ipv4() && remote.ip() == self.path.remote.ip() {
            PathData::from_previous(remote, local, &self.path, self.path_counter, now)
        } else {
            let peer_max_udp_payload_size =
                u16::try_from(self.peer_params.max_udp_payload_size.into_inner())
                    .unwrap_or(u16::MAX);
            PathData::new(
                remote,
                local,
                self.allow_mtud,
                Some(peer_max_udp_payload_size),
                self.path_counter,
                now,
                &self.config,
            )
        };
        new_path.challenge = Some(self.rng.random());
        new_path.challenge_pending = true;
        let prev_pto = self.pto(SpaceId::Data);

        let mut prev = mem::replace(&mut self.path, new_path);
        match previous {
            // Don't clobber the original path if the previous one hasn't been validated yet
            PreviousPath::Keep(cid) if prev.challenge.is_none() => {
                prev.challenge = Some(self.rng.random());
                prev.challenge_pending = true;
                self.prev_path = Some(PrevPath { path: prev, cid });
            }
            PreviousPath::Keep(_) => {}
            // Our own move: the path we leave is not kept, nor is an older one.
            PreviousPath::Discard => self.drop_previous_path(),
        }

        self.timers.set(
            Timer::PathValidation,
            now + 3 * cmp::max(self.pto(SpaceId::Data), prev_pto),
        );
        // The path swap moves congestion state only: every ack-eliciting packet already sent, on
        // the path just replaced or on one dropped here, stays outstanding in its packet number
        // space and keeps driving the loss timer; re-evaluate it against that outstanding set.
        self.set_loss_detection_timer(now);
    }

    /// Whether this connection can start using a new local address now: RFC 9000 §9.5 forbids
    /// reusing a non-zero-length destination connection ID across local addresses, so an unused
    /// one must be available; a peer using zero-length connection IDs needs none.
    pub(crate) fn can_migrate_locally(&self) -> bool {
        self.rem_cids.active().is_empty() || self.rem_cids.has_unused()
    }

    /// Commit an active migration to a new local address: switch to an unused destination
    /// connection ID (retiring the current one) and probe the path. Returns `false`, changing
    /// nothing, when no unused connection ID is available and the peer's are not zero-length;
    /// the caller must then keep sending from the old address (see
    /// [`can_migrate_locally`](Self::can_migrate_locally)).
    pub(crate) fn migrate_local_address(&mut self) -> bool {
        if !self.rem_cids.active().is_empty() && !self.update_rem_cid() {
            return false;
        }
        // A candidate path's identifier may not be sent from another local address (RFC 9000
        // §9.5): the attempt starts over with a fresh identifier, or ends when none is unused.
        self.restart_candidate();
        self.ping();
        true
    }

    /// Tests: whether a peer move is waiting for an unused destination connection ID.
    #[cfg(test)]
    pub(crate) fn deferred_move_pending(&self) -> bool {
        self.deferred_migration.is_some()
    }

    /// Mark the path as validated, and enqueue NEW_TOKEN frames to be sent as appropriate
    pub(super) fn on_path_validated(&mut self) {
        self.path.validated = true;
        let ConnectionSide::Server { server_config } = &self.side else {
            return;
        };
        let new_tokens = &mut self.spaces[SpaceId::Data as usize].pending.new_tokens;
        new_tokens.clear();
        for _ in 0..server_config.validation_token.sent {
            new_tokens.push(self.path.remote);
        }
    }
}

/// The path the connection sent on before the current one, kept while the current one is being
/// validated so the connection can return to it.
pub(super) struct PrevPath {
    pub(super) path: PathData,
    /// Which destination connection ID that path is sent with.
    pub(super) cid: PrevCid,
}

/// What becomes of the path a migration replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreviousPath {
    /// Keep it as a fallback, challenged with the identifier bound to it.
    Keep(PrevCid),
    /// Leave it behind: we moved deliberately and will not send there again.
    Discard,
}

/// The destination connection ID bound to the previous path (RFC 9000 §9.5: never one that is
/// also sent to another address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrevCid {
    /// The identifier used there, kept aside in the connection ID queue.
    Held,
    /// The current identifier: the peer moved without changing the ID it sends (NAT rebinding).
    Active,
    /// The peer retired the identifier meanwhile; returning needs a fresh one.
    Gone,
}

/// A peer move that waits for an unused destination connection ID.
#[derive(Debug, Clone, Copy)]
pub(super) struct DeferredMigration {
    pub(super) remote: SocketAddr,
    pub(super) local: Option<SocketAddr>,
    /// The destination connection ID the peer used for the move.
    pub(super) received_dcid: ConnectionId,
    /// Packet number of the newest non-probing packet asking for the move.
    pub(super) number: u64,
    /// Path generation the move was recorded against; a path change makes it obsolete.
    pub(super) generation: u64,
}

/// How many paths a connection will bind an identifier to at once. A path this connection does
/// not otherwise send on is one it answers a challenge on, nothing more, and every binding costs
/// an identifier the peer issued: a few is generous and keeps the reset token set small.
pub(super) const PATH_CIDS: usize = 2;

/// A peer connection ID bound to one path, so that what this connection sends there carries an
/// identifier it sends from no other local address (RFC 9000 §9.5).
#[derive(Debug, Clone, Copy)]
pub(super) struct PathCid {
    /// The address the identifier is sent to.
    remote: SocketAddr,
    /// The local address it is sent from, when known.
    local: Option<SocketAddr>,
    id: ConnectionId,
    seq: u64,
}
