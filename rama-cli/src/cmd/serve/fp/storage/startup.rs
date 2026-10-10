//! Start one bounded collector for the configured fingerprint store.

use std::{future::pending, time::SystemTime};

use rama::{
    error::BoxError,
    rt::Executor,
    telemetry::tracing,
    tls::boring::core::rand::rand_bytes,
    ua::profile::{IngestionBatchLimits, JointCaptureLimits, profile_utc_day},
    utils::octets::{gib, kib},
};

use super::{
    counted::{self, StoreLimits},
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

pub(super) async fn start(pool: Pool, exec: &Executor) -> Result<CollectionQueue, BoxError> {
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
    let (queue, receiver) = CollectionQueue::new(config, limits)?;
    let guard = exec.guard().cloned();
    exec.spawn_task(async move {
        let shutdown = async move {
            match guard {
                Some(guard) => guard.cancelled().await,
                None => pending().await,
            }
        };
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
