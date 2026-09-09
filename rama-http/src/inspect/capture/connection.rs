use super::*;

impl CaptureStore {
    #[cfg(test)]
    pub fn begin_connection(&self, socket: Option<SocketInfo>, ingress: Protocol) -> u64 {
        self.begin_connection_labeled(socket, ingress, None)
    }

    pub fn begin_connection_if_enabled(
        &self,
        socket: Option<SocketInfo>,
        ingress: Protocol,
        label: Option<String>,
    ) -> Option<u64> {
        let _permit = self.0.inspection.try_capture()?;
        self.begin_connection_labeled_inner(socket, ingress, label, true, None)
    }

    #[cfg(test)]
    pub fn begin_connection_labeled(
        &self,
        socket: Option<SocketInfo>,
        ingress: Protocol,
        label: Option<String>,
    ) -> u64 {
        self.begin_connection_labeled_inner(socket, ingress, label, false, None)
            .expect("unbounded test connection admission")
    }

    pub(super) fn begin_connection_labeled_inner(
        &self,
        socket: Option<SocketInfo>,
        ingress: Protocol,
        label: Option<String>,
        enforce_limit: bool,
        id: Option<u64>,
    ) -> Option<u64> {
        let id = id.unwrap_or_else(|| self.0.next_connection_id.fetch_add(1, Ordering::Relaxed));
        let (local_address, peer_address) = socket
            .map(|socket| (socket.local_addr(), Some(socket.peer_addr())))
            .unwrap_or_default();
        let connection = Arc::new(CapturedConnection {
            metadata: rama_inspect::Observations::default(),
            akamai_h2: OnceLock::new(),
            summary_template: HttpConnectionSummary {
                request_count: 0,
                akamai_h2: None,
                transport: rama_net::inspect::ConnectionSummary {
                    id,
                    display_id: 0,
                    label,
                    started_at: jiff::Timestamp::now(),
                    local_address,
                    peer_address,
                    ingress_protocol: ingress.clone(),
                    active: true,
                    ended_at: None,
                    bytes_in: 0,
                    bytes_out: 0,
                    metadata: rama_inspect::Observations::default(),
                },
            },
            display_id: OnceLock::new(),
            ingress_protocol: RwLock::new(ingress),
            confirmed: AtomicBool::new(false),
            transport_finished: AtomicBool::new(false),
            active: AtomicBool::new(true),
            ended_at: OnceLock::new(),
            request_count: AtomicUsize::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        });
        let mut connections = self.0.connections.write();
        if enforce_limit {
            while connections.order.len() >= self.0.max_connections {
                let remove =
                    connections
                        .order
                        .iter()
                        .copied()
                        .enumerate()
                        .find_map(|(index, id)| {
                            let active = connections
                                .entries
                                .get(&id)
                                .is_some_and(|entry| entry.active.load(Ordering::Relaxed));
                            (!active).then_some((index, id))
                        });
                let (index, id) = remove?;
                connections.order.remove(index);
                connections.entries.remove(&id);
            }
        }
        connections.entries.insert(id, connection);
        connections.order.push_back(id);
        Some(id)
    }

    pub fn connection_guard(&self, id: u64) -> CaptureConnectionGuard {
        CaptureConnectionGuard {
            store: self.clone(),
            id,
        }
    }

    pub fn upgrade_guard(&self, id: u64) -> HttpUpgradeCaptureGuard {
        HttpUpgradeCaptureGuard {
            store: self.clone(),
            id,
        }
    }

    pub fn upgrade_guard_for_response(
        &self,
        id: u64,
        status: u16,
    ) -> Option<HttpUpgradeCaptureGuard> {
        let entry = self.0.exchanges.read().entries.get(&id).cloned()?;
        if !successful_upgrade_response(&entry, status) {
            return None;
        }
        entry
            .upgrade_lifecycle_started
            .store(true, Ordering::Release);
        Some(self.upgrade_guard(id))
    }

    pub(super) fn http_exchange_guard(&self, id: u64) -> CaptureHttpExchangeGuard {
        CaptureHttpExchangeGuard {
            store: self.clone(),
            id,
            armed: true,
        }
    }

    pub async fn clear(&self) {
        let exchanges = {
            let mut registry = self.0.exchanges.write();
            self.0.generation.fetch_add(1, Ordering::AcqRel);
            std::mem::take(&mut *registry)
        };
        let connections = {
            let mut registry = self.0.connections.write();
            std::mem::take(&mut *registry)
        };
        self.0.search_caches.lock().entries.clear();
        self.changed();
        // Destruction may release thousands of captures and their metadata.
        _ = tokio::task::spawn_blocking(move || drop((exchanges, connections))).await;
    }

    /// Publish a provisionally accepted socket once it is known to carry
    /// proxy traffic rather than the inspector's own shared-port HTTP traffic.
    pub fn confirm_connection(&self, id: u64) {
        let connection = self.0.connections.read().entries.get(&id).cloned();
        if let Some(connection) = connection
            && self.confirm_connection_entry(&connection)
        {
            self.trim_connections();
            self.changed();
        }
    }

    pub fn confirm_connection_if_enabled(&self, id: u64) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return;
        };
        self.confirm_connection(id);
    }

    pub(super) fn confirm_connection_entry(&self, connection: &CapturedConnection) -> bool {
        connection.display_id.get_or_init(|| {
            self.0
                .next_display_connection_id
                .fetch_add(1, Ordering::Relaxed)
        });
        !connection.confirmed.swap(true, Ordering::Release)
    }

    pub fn set_connection_protocol(&self, id: u64, protocol: Protocol) {
        if let Some(connection) = self.0.connections.read().entries.get(&id).cloned() {
            *connection.ingress_protocol.write() = protocol;
            if connection.confirmed.load(Ordering::Relaxed) {
                self.changed();
            }
        }
    }

    pub fn set_connection_protocol_if_enabled(&self, id: u64, protocol: Protocol) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return;
        };
        self.set_connection_protocol(id, protocol);
    }

    pub fn finish_connection(&self, id: u64) {
        let Some(connection) = self.0.connections.read().entries.get(&id).cloned() else {
            return;
        };
        let confirmed = connection.confirmed.load(Ordering::Relaxed);
        if !confirmed {
            let mut connections = self.0.connections.write();
            connections.entries.remove(&id);
            connections.order.retain(|candidate| *candidate != id);
            return;
        }
        connection.transport_finished.store(true, Ordering::SeqCst);
        if self.has_active_upgrade(id) {
            return;
        }
        self.finish_upgraded_connection(&connection);
    }

    pub(super) fn has_active_upgrade(&self, connection_id: u64) -> bool {
        self.0.exchanges.read().entries.values().any(|entry| {
            entry.summary_template.connection_id == connection_id
                && entry.upgraded
                && entry.active.load(Ordering::SeqCst)
        })
    }

    pub(super) fn finish_upgraded_connection(&self, connection: &CapturedConnection) {
        if connection.transport_finished.load(Ordering::SeqCst)
            && connection.active.swap(false, Ordering::SeqCst)
        {
            _ = connection.ended_at.set(jiff::Timestamp::now());
            self.trim_connections();
            self.changed();
        }
    }

    pub fn finish_upgrade(&self, id: u64) {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        if entry.active.swap(false, Ordering::SeqCst) {
            _ = entry.completed_at.set(jiff::Timestamp::now());
            if let Some(connection) = &entry.connection {
                self.finish_upgraded_connection(connection);
            }
            self.trim_exchanges();
            self.changed();
        }
    }

    /// Forget a connection that has only served the inspector itself.
    ///
    /// A shared proxy/UI listener cannot distinguish the two at accept time.
    /// The first parsed origin-form dashboard request can, and is allowed to
    /// remove the provisional entry as long as no proxied exchange has been
    /// associated with it.
    pub fn discard_connection_if_empty(&self, id: u64) -> bool {
        {
            let mut connections = self.0.connections.write();
            let is_empty = connections
                .entries
                .get(&id)
                .is_some_and(|entry| entry.request_count.load(Ordering::Relaxed) == 0);
            if !is_empty {
                false
            } else {
                connections.entries.remove(&id);
                if let Some(index) = connections
                    .order
                    .iter()
                    .position(|candidate| *candidate == id)
                {
                    connections.order.remove(index);
                }
                true
            }
        }
    }

    pub(super) fn trim_connections(&self) {
        let mut connections = self.0.connections.write();
        loop {
            if connections.order.len() <= self.0.max_connections {
                break;
            }
            let remove = connections
                .order
                .iter()
                .copied()
                .enumerate()
                .find_map(|(index, id)| {
                    let active = match connections.entries.get(&id) {
                        Some(entry) => entry.active.load(Ordering::Relaxed),
                        None => false,
                    };
                    (!active).then_some((index, id))
                });
            let Some((index, id)) = remove else { break };
            connections.order.remove(index);
            connections.entries.remove(&id);
        }
    }
}
