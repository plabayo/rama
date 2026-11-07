//! Start one bounded collector for the configured fingerprint store.

use std::time::SystemTime;

use rama::{
    error::BoxError,
    graceful::WeakScope,
    telemetry::tracing,
    tls::boring::core::rand::rand_bytes,
    ua::profile::{
        capture::joint::JointCaptureLimits, evidence::transaction::IngestionBatchLimits,
        model::time::profile_utc_day,
    },
    utils::octets::{gib, kib},
};

use super::{
    counted::{self, StoreLimits},
    legacy,
    postgres::Pool,
    worker::{self, CollectionQueue, PostgresSink, QueueConfig},
};

pub(super) fn current_day() -> Result<u32, BoxError> {
    Ok(profile_utc_day(SystemTime::now())?)
}

fn nonce() -> Result<[u8; 12], BoxError> {
    let mut nonce = [0; 12];
    rand_bytes(&mut nonce)?;
    Ok(nonce)
}

pub(super) async fn start(pool: Pool, scope: &WeakScope) -> Result<CollectionQueue, BoxError> {
    let limits = store_limits();
    let config = QueueConfig::default();
    let mut candidates = [[0; 32]; 2];
    for seed in &mut candidates {
        rand_bytes(seed)?;
    }
    let seeds = {
        let mut client = pool.get().await?;
        counted::sampler_seeds(&mut client, candidates).await?
    };
    // Legacy backlog must not delay new collection or prevent serving requests.
    scope
        .try_hold()?
        .into_spawn_cancellable_task(legacy::backfill_partitions(pool.clone(), seeds, limits));
    let (queue, receiver) = CollectionQueue::new(config, limits)?;
    let shutdown = scope.cancelled();
    scope.try_hold()?.into_spawn_task(async move {
        if worker::run(
            receiver,
            PostgresSink {
                pool,
                seeds,
                limits,
            },
            limits,
            config,
            shutdown,
            current_day,
            nonce,
        )
        .await
        .is_err()
        {
            tracing::error!("fingerprint collection worker stopped");
        }
    });
    Ok(queue)
}

pub(super) fn store_limits() -> StoreLimits {
    StoreLimits {
        ingestion: IngestionBatchLimits::default(),
        capture: JointCaptureLimits::default(),
        retained: [
            16_384,
            131_072,
            262_144,
            1_048_576,
            16_384,
            1_048_576,
            gib(1),
        ],
        checkpoint_bytes: kib(16),
    }
}
