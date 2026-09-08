use super::*;

impl CaptureStore {
    pub async fn snapshot(&self, filter: &CaptureFilter) -> CaptureSnapshot {
        self.snapshot_limited(filter, usize::MAX, usize::MAX).await
    }

    pub async fn snapshot_limited(
        &self,
        filter: &CaptureFilter,
        connection_limit: usize,
        exchange_limit: usize,
    ) -> CaptureSnapshot {
        self.snapshot_limited_for_connections(
            filter,
            &BTreeSet::new(),
            0,
            connection_limit,
            exchange_limit,
        )
        .await
    }

    pub async fn snapshot_limited_for_connections(
        &self,
        filter: &CaptureFilter,
        selected_connections: &BTreeSet<u64>,
        connection_offset: usize,
        connection_limit: usize,
        exchange_limit: usize,
    ) -> CaptureSnapshot {
        self.snapshot_limited_for_connection_window(
            filter,
            selected_connections,
            ConnectionWindow::Offset(connection_offset),
            connection_limit,
            exchange_limit,
        )
        .await
    }

    pub async fn snapshot_limited_before_connection(
        &self,
        filter: &CaptureFilter,
        selected_connections: &BTreeSet<u64>,
        before_connection_id: Option<u64>,
        connection_limit: usize,
        exchange_limit: usize,
    ) -> CaptureSnapshot {
        self.snapshot_limited_for_connection_window(
            filter,
            selected_connections,
            ConnectionWindow::Before(before_connection_id),
            connection_limit,
            exchange_limit,
        )
        .await
    }

    pub(super) async fn snapshot_limited_for_connection_window(
        &self,
        filter: &CaptureFilter,
        selected_connections: &BTreeSet<u64>,
        connection_window: ConnectionWindow,
        connection_limit: usize,
        exchange_limit: usize,
    ) -> CaptureSnapshot {
        let (exchange_summaries, total_requests, matching_connections) =
            if filter.is_empty() && selected_connections.is_empty() {
                let exchanges = self.0.exchanges.read();
                (
                    exchanges
                        .entries
                        .values()
                        .rev()
                        .take(exchange_limit)
                        .map(|entry| entry.snapshot())
                        .collect(),
                    exchanges.entries.len(),
                    None,
                )
            } else if filter.is_empty() {
                let exchanges = self.0.exchanges.read();
                let mut summaries = Vec::with_capacity(exchange_limit.min(exchanges.entries.len()));
                let mut total = 0;
                for exchange in exchanges.entries.values().rev() {
                    let summary = exchange.snapshot();
                    if !selected_connections.contains(&summary.connection_id) {
                        continue;
                    }
                    total += 1;
                    if summaries.len() < exchange_limit {
                        summaries.push(summary);
                    }
                }
                (summaries, total, None)
            } else {
                // Filtering captured payload can await disk reads. Clone only the
                // retained Arc handles here so no synchronous guard crosses await.
                let exchanges = self
                    .0
                    .exchanges
                    .read()
                    .entries
                    .values()
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>();
                let mut summaries = Vec::with_capacity(exchange_limit.min(exchanges.len()));
                let mut matching_connections = std::collections::BTreeSet::new();
                let mut total = 0;
                for exchange in exchanges {
                    let summary = exchange.snapshot();
                    if !filter.matches_dimensions(&summary) {
                        continue;
                    }
                    if !filter.search_matches_summary(&summary)
                        && !self
                            .exchange_matches_search(&exchange, &filter.search)
                            .await
                    {
                        continue;
                    }
                    matching_connections.insert(summary.connection_id);
                    if !selected_connections.is_empty()
                        && !selected_connections.contains(&summary.connection_id)
                    {
                        continue;
                    }
                    total += 1;
                    if summaries.len() < exchange_limit {
                        summaries.push(summary);
                    }
                }
                (summaries, total, Some(matching_connections))
            };

        let connection_exchange_states = self.connection_exchange_states();
        let connections = self.0.connections.read();
        let mut connection_summaries =
            Vec::with_capacity(connection_limit.min(connections.entries.len()));
        let mut total_connections = 0;
        let mut active_connections = 0;
        let mut bytes_in = 0_u64;
        let mut bytes_out = 0_u64;
        let mut cursor_offset = 0;
        for connection in connections.entries.values().rev() {
            if !connection.confirmed.load(Ordering::Relaxed) {
                continue;
            }
            let mut summary = connection.snapshot();
            let connection_id = summary.id;
            reconcile_connection_summary(
                &mut summary,
                connection_exchange_states.get(&connection_id),
            );
            if matching_connections
                .as_ref()
                .is_some_and(|ids| !ids.contains(&summary.id))
            {
                continue;
            }
            let connection_index = total_connections;
            total_connections += 1;
            active_connections += usize::from(summary.active);
            bytes_in = bytes_in.saturating_add(summary.bytes_in);
            bytes_out = bytes_out.saturating_add(summary.bytes_out);
            let inside_window = match connection_window {
                ConnectionWindow::Offset(offset) => connection_index >= offset,
                ConnectionWindow::Before(Some(before)) => {
                    if summary.id >= before {
                        cursor_offset += 1;
                        false
                    } else {
                        true
                    }
                }
                ConnectionWindow::Before(None) => true,
            };
            if inside_window && connection_summaries.len() < connection_limit {
                connection_summaries.push(summary);
            }
        }

        let connection_offset = match connection_window {
            ConnectionWindow::Offset(offset) => offset.min(total_connections),
            ConnectionWindow::Before(_) => cursor_offset,
        };
        let next_connection_cursor = (connection_offset + connection_summaries.len()
            < total_connections)
            .then(|| connection_summaries.last().map(|summary| summary.id))
            .flatten();

        CaptureSnapshot {
            connections: connection_summaries,
            connection_offset,
            next_connection_cursor,
            exchanges: exchange_summaries,
            total_connections,
            active_connections,
            total_requests,
            bytes_in,
            bytes_out,
        }
    }

    pub(super) async fn exchange_matches_search(
        &self,
        exchange: &CapturedExchange,
        needle: &str,
    ) -> bool {
        let revision = exchange.search_revision.load(Ordering::Acquire);
        if let Some(matched) =
            self.0
                .search_caches
                .lock()
                .get(needle, exchange.summary_template.id, revision)
        {
            return matched;
        }

        #[cfg(test)]
        self.0.record_reads.fetch_add(1, Ordering::Relaxed);
        let mut matched = self.0.observer.matches_search(&exchange.metadata, needle);
        let record_count = exchange.records.read().len();
        for index in 0..record_count {
            if matched {
                break;
            }
            let location = exchange.records.read()[index];
            let Ok(record) = read_record_at(&exchange.collection, location).await else {
                continue;
            };
            matched = records_match_search(std::slice::from_ref(&record), needle);
        }
        if !matched {
            let indices: Vec<_> = exchange
                .extension_records
                .read()
                .values()
                .map(|index| (index.ids.clone(), index.matches))
                .collect();
            'records: for (ids, matches) in indices {
                for id in ids {
                    let Ok(mut reader) = exchange.collection.read(id).await else {
                        continue;
                    };
                    let mut data = Vec::new();
                    if reader.read_to_end(&mut data).await.is_ok() && matches(&data, needle) {
                        matched = true;
                        break 'records;
                    }
                }
            }
        }
        let current_revision = exchange.search_revision.load(Ordering::Acquire);
        if current_revision == revision {
            self.0.search_caches.lock().insert(
                needle,
                exchange.summary_template.id,
                revision,
                matched,
            );
        }
        matched
    }
}
