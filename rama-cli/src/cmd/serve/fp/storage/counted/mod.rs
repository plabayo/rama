//! Counted fingerprint writes, serialized within each authorization partition.

mod export;
pub(super) use export::next_profile;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use rama::{
    error::BoxError,
    ua::profile::{
        CanonicalDomain, CanonicalValue, CaptureRunCheckpoint, CaptureRunId, CountedBucketSnapshot,
        CountedObservationBucket, CounterSnapshot, IngestionAttempt, IngestionBatchLimits,
        JointCaptureLimits, LiteralCount, ObservationId, ObservationLosses,
        PendingBucketObservation, PreparedIngestion, PreparedProfileCapture, ProfileBucketInput,
        ProfileCapture, ProfileDataError, ProfileObservationScope, ReservoirEntry,
        StoredObservationBucket, ValueId,
    },
    utils::octets::kib,
};
use tokio_postgres::{Client, Transaction};

/// Entry counts bound row/index overhead separately from canonical payload bytes.
/// These are service configuration, not peer-controlled limits.
#[derive(Debug, Clone, Copy)]
pub(super) struct StoreLimits {
    pub ingestion: IngestionBatchLimits,
    pub capture: JointCaptureLimits,
    /// Profiles, flows, structures, day buckets, active runs, interned_values, canonical bytes.
    pub retained: [usize; 7],
    pub checkpoint_bytes: usize,
}

fn invalid(message: &'static str) -> BoxError {
    ProfileDataError::Invalid(message).into()
}

fn bounded(message: &'static str) -> BoxError {
    ProfileDataError::LimitExceeded(message).into()
}

fn integer(value: usize) -> Result<i64, BoxError> {
    Ok(i64::try_from(value)?)
}

fn count(value: u64) -> Result<i64, BoxError> {
    Ok(i64::try_from(value)?)
}

fn identity(bytes: Vec<u8>) -> Result<ValueId, BoxError> {
    Ok(ValueId(
        bytes
            .try_into()
            .map_err(|_error| invalid("stored identity length"))?,
    ))
}

fn bounded_rows(capacity: usize) -> Result<i64, BoxError> {
    integer(
        capacity
            .checked_add(1)
            .ok_or_else(|| bounded("query rows"))?,
    )
}

fn stored_sampler_seed(
    seed: Option<Vec<u8>>,
    buckets: i64,
    runs: i64,
    values: i64,
) -> Result<Option<[u8; 32]>, BoxError> {
    if seed.is_none() && (buckets != 0 || runs != 0 || values != 0) {
        return Err(invalid("missing persisted sampler seed"));
    }
    seed.map(|seed| {
        seed.try_into()
            .map_err(|_error| invalid("stored sampler seed length"))
    })
    .transpose()
}

/// All fp processes share the retained partition seeds. Candidates come from the
/// service RNG and are used only when the corresponding partition is empty.
pub(super) async fn sampler_seeds(
    client: &mut Client,
    candidates: [[u8; 32]; 2],
) -> Result<[[u8; 32]; 2], BoxError> {
    let transaction = client.transaction().await?;
    let mut seeds = candidates;
    for (index, authorized) in [false, true].into_iter().enumerate() {
        let row = transaction.query_one(
            "SELECT sampler_seed, buckets, runs, interned_values FROM fp_v2.quotas WHERE authorized=$1 FOR UPDATE", &[&authorized],
        ).await?;
        if let Some(seed) = stored_sampler_seed(
            row.try_get(0)?,
            row.try_get(1)?,
            row.try_get(2)?,
            row.try_get(3)?,
        )? {
            seeds[index] = seed;
        } else {
            transaction
                .execute(
                    "UPDATE fp_v2.quotas SET sampler_seed=$2 WHERE authorized=$1",
                    &[&authorized, &&seeds[index][..]],
                )
                .await?;
        }
    }
    transaction.commit().await?;
    Ok(seeds)
}

struct Quota {
    used: [i64; 7],
    maximum: [usize; 7],
}

impl Quota {
    fn change(&mut self, index: usize, delta: i64) -> Result<(), BoxError> {
        let next = self.used[index]
            .checked_add(delta)
            .ok_or_else(|| bounded("storage quota"))?;
        if next < 0 {
            return Err(bounded("storage quota"));
        }
        self.used[index] = next;
        Ok(())
    }

    fn validate(&self) -> Result<(), BoxError> {
        for (used, maximum) in self.used.iter().zip(self.maximum) {
            if *used < 0 || u64::try_from(*used)? > u64::try_from(maximum)? {
                return Err(bounded("storage quota"));
            }
        }
        Ok(())
    }
}

/// Whether an ingestion error preceded COMMIT or may have lost its reply.
/// Only a rejected, retired job can safely release its unadmitted sequence.
#[derive(Debug)]
pub(super) enum IngestFailure {
    Rejected(BoxError),
    Unconfirmed(BoxError),
}

impl fmt::Display for IngestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(error) => write!(formatter, "profile ingestion rejected: {error}"),
            Self::Unconfirmed(error) => {
                write!(formatter, "profile ingestion commit unconfirmed: {error}")
            }
        }
    }
}

impl std::error::Error for IngestFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(error) | Self::Unconfirmed(error) => Some(error.as_ref()),
        }
    }
}

/// Retries reuse the same trusted writer ID. The transaction owns quota, run and
/// bucket state until every component and the checkpoint have committed together.
pub(super) async fn ingest(
    client: &mut Client,
    current_day: u32,
    attempt: IngestionAttempt,
    capture: &ProfileCapture,
    seed: [u8; 32],
    limits: StoreLimits,
) -> Result<bool, IngestFailure> {
    let Some(transaction) =
        prepare_transaction(client, current_day, attempt, capture, seed, limits)
            .await
            .map_err(IngestFailure::Rejected)?
    else {
        return Ok(false);
    };
    transaction
        .commit()
        .await
        .map_err(|error| IngestFailure::Unconfirmed(error.into()))?;
    Ok(true)
}

async fn prepare_transaction<'a>(
    client: &'a mut Client,
    current_day: u32,
    attempt: IngestionAttempt,
    capture: &ProfileCapture,
    seed: [u8; 32],
    limits: StoreLimits,
) -> Result<Option<Transaction<'a>>, BoxError> {
    limits.ingestion.bucket.validate()?;
    if limits.capture.bytes > limits.ingestion.bucket.input_bytes
        || limits.capture.value_bytes > limits.capture.bytes
    {
        return Err(invalid("capture and bucket input limits"));
    }
    let prepared = capture.prepare(attempt.authorized, limits.capture)?;
    if prepared.buckets.len() > limits.ingestion.buckets {
        return Err(bounded("joint plus component buckets"));
    }
    let transaction = client.transaction().await?;
    let authorized = attempt.authorized;
    let row = transaction.query_one(
        "SELECT watermark, profiles, flows, structures, buckets, runs, interned_values, canonical_bytes, sampler_seed
         FROM fp_v2.quotas WHERE authorized = $1 FOR UPDATE", &[&authorized],
    ).await?;
    if i64::from(current_day) < row.try_get::<_, i64>(0)? {
        return Err(invalid("storage time watermark"));
    }
    let mut quota = Quota {
        used: [0; 7],
        maximum: limits.retained,
    };
    for index in 0..7 {
        quota.used[index] = row.try_get(index + 1)?;
        quota.change(index, 0)?;
    }
    quota.validate()?;
    if stored_sampler_seed(row.try_get(8)?, quota.used[3], quota.used[4], quota.used[5])?
        .is_some_and(|previous| previous != seed)
    {
        return Err(invalid("storage sampler seed"));
    }
    let run_id = CaptureRunId(attempt.observation.run);
    let run_row = transaction.query_opt(
        "SELECT created_day, CASE WHEN octet_length(checkpoint::text)::bigint <= $3 THEN checkpoint::text END
         FROM fp_v2.runs WHERE authorized = $1 AND id = $2",
        &[&authorized, &&run_id.0[..], &integer(limits.checkpoint_bytes)?],
    ).await?;
    let new_run = run_row.is_none();
    let run = if let Some(row) = run_row {
        if row.try_get::<_, i64>(0)? != i64::from(run_id.created_day()) {
            return Err(invalid("stored run creation day"));
        }
        let text: Option<String> = row.try_get(1)?;
        serde_json::from_str::<CaptureRunCheckpoint>(
            &text.ok_or_else(|| bounded("run checkpoint bytes"))?,
        )?
    } else {
        CaptureRunCheckpoint::new(run_id, authorized, current_day, limits.ingestion)?
    };
    let mut remaining = limits.ingestion.input_bytes;
    let mut previous = Vec::new();
    for input in &prepared.buckets {
        remaining = remaining
            .checked_sub(input.value.bytes.len())
            .ok_or_else(|| bounded("batch input bytes"))?;
        previous.push(
            load_bucket(
                &transaction,
                authorized,
                attempt.observation_day,
                input,
                seed,
                limits,
                &mut remaining,
            )
            .await?,
        );
    }
    let pending: Vec<_> = previous
        .iter()
        .zip(prepared.buckets.iter())
        .map(|(previous, input)| PendingBucketObservation {
            expected_scope: &input.scope,
            previous,
            value: &input.value,
        })
        .collect();
    let PreparedIngestion::Commit { run, buckets } =
        run.prepare(current_day, attempt, &pending, seed, limits.ingestion)?
    else {
        return Ok(None);
    };
    let checkpoint = serde_json::to_string(&run)?;
    // PostgreSQL JSONB adds insignificant spaces on output. Bound its representation,
    // too, so a checkpoint written here can always pass the bounded read.
    let checkpoint_size: i32 = transaction
        .query_one("SELECT octet_length($1::text::jsonb::text)", &[&checkpoint])
        .await?
        .try_get(0)?;
    if usize::try_from(checkpoint_size)? > limits.checkpoint_bytes {
        return Err(bounded("run checkpoint bytes"));
    }
    intern_metadata(&transaction, authorized, &prepared, &mut quota).await?;
    for ((input, previous), updated) in prepared.buckets.iter().zip(&previous).zip(&buckets) {
        save_bucket(
            &transaction,
            authorized,
            input,
            previous,
            updated,
            &mut quota,
        )
        .await?;
    }
    if new_run {
        quota.change(4, 1)?;
    }
    transaction
        .execute(
            "INSERT INTO fp_v2.runs (authorized, id, created_day, checkpoint)
         VALUES ($1, $2, $3, $4::text::jsonb)
         ON CONFLICT (authorized, id) DO UPDATE SET checkpoint = EXCLUDED.checkpoint",
            &[
                &authorized,
                &&run_id.0[..],
                &i64::from(run_id.created_day()),
                &checkpoint,
            ],
        )
        .await?;
    quota.validate()?;
    transaction
        .execute(
            "UPDATE fp_v2.quotas SET watermark=$2, profiles=$3, flows=$4, structures=$5,
         buckets=$6, runs=$7, interned_values=$8, canonical_bytes=$9, sampler_seed=$10 WHERE authorized=$1",
            &[
                &authorized,
                &i64::from(current_day),
                &quota.used[0],
                &quota.used[1],
                &quota.used[2],
                &quota.used[3],
                &quota.used[4],
                &quota.used[5],
                &quota.used[6],
                &&seed[..],
            ],
        )
        .await?;
    Ok(Some(transaction))
}

async fn load_bucket(
    transaction: &Transaction<'_>,
    authorized: bool,
    day: u32,
    input: &ProfileBucketInput,
    seed: [u8; 32],
    limits: StoreLimits,
    remaining: &mut usize,
) -> Result<StoredObservationBucket, BoxError> {
    let domain = input
        .value
        .validated_domain(limits.ingestion.bucket.input_bytes)?;
    load_retained_bucket(
        transaction,
        authorized,
        day,
        StoredScope {
            scope: &input.scope,
            structure: &input.structure,
            domain,
        },
        seed,
        limits,
        remaining,
    )
    .await
}

struct StoredScope<'a> {
    scope: &'a CanonicalValue,
    structure: &'a CanonicalValue,
    domain: CanonicalDomain,
}

async fn load_retained_bucket(
    transaction: &Transaction<'_>,
    authorized: bool,
    day: u32,
    input: StoredScope<'_>,
    seed: [u8; 32],
    limits: StoreLimits,
    remaining: &mut usize,
) -> Result<StoredObservationBucket, BoxError> {
    let domain = input.domain;
    let scope = &input.scope.id.0[..];
    let day_sql = i64::from(day);
    let decoded = ProfileObservationScope::from_canonical(input.scope, limits.capture.value_bytes)?;
    if decoded.authorized != authorized {
        return Err(invalid("stored scope access class"));
    }
    let flow: Option<&[u8]> = decoded.flow.as_ref().map(|id| id.0.as_slice());
    let row = transaction
        .query_opt(
            "SELECT scope_canonical = $4, domain, format_version, total, untracked, retained_bytes,
          structure_id = $5 AND profile_id = $6 AND flow_id IS NOT DISTINCT FROM $7,
          dropped_oversize, dropped_retention, history_known,
          CASE WHEN octet_length(untracked_distinct::text)::bigint <= $8 THEN untracked_distinct::text END
         FROM fp_v2.buckets WHERE authorized=$1 AND scope=$2 AND day=$3",
            &[
                &authorized,
                &scope,
                &day_sql,
                &&input.scope.bytes[..],
                &&input.structure.id.0[..],
                &&decoded.profile.0[..],
                &flow,
                &integer(kib(8))?,
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(StoredObservationBucket {
            authorized,
            day,
            bucket: CountedObservationBucket::new(
                domain,
                input.scope.id,
                seed,
                limits.ingestion.bucket,
            )?
            .snapshot(),
        });
    };
    if !row.try_get::<_, bool>(0)?
        || row.try_get::<_, i32>(1)? != i32::from(domain)
        || !row.try_get::<_, bool>(6)?
    {
        return Err(invalid("stored bucket identity"));
    }
    let retained_bytes = usize::try_from(row.try_get::<_, i64>(5)?)?;
    if retained_bytes > limits.ingestion.bucket.retained_bytes || retained_bytes > *remaining {
        return Err(bounded("stored bucket bytes"));
    }
    let count_rows = transaction.query(
        "SELECT value_id, count FROM fp_v2.literal_counts WHERE authorized=$1 AND scope=$2 AND day=$3
         ORDER BY value_id LIMIT $4",
        &[&authorized, &scope, &day_sql, &bounded_rows(limits.ingestion.bucket.literal_values)?],
    ).await?;
    if count_rows.len() > limits.ingestion.bucket.literal_values {
        return Err(bounded("stored literal rows"));
    }
    let mut references = BTreeSet::new();
    let mut counts = Vec::new();
    for row in count_rows {
        let value = identity(row.try_get(0)?)?;
        references.insert(value);
        counts.push(LiteralCount {
            value,
            count: u64::try_from(row.try_get::<_, i64>(1)?)?,
        });
    }
    let sample_rows = transaction
        .query(
            "SELECT run, sequence::text, priority, value_id FROM fp_v2.samples
         WHERE authorized=$1 AND scope=$2 AND day=$3 ORDER BY priority, run, sequence LIMIT $4",
            &[
                &authorized,
                &scope,
                &day_sql,
                &bounded_rows(limits.ingestion.bucket.samples)?,
            ],
        )
        .await?;
    if sample_rows.len() > limits.ingestion.bucket.samples {
        return Err(bounded("stored sample rows"));
    }
    let mut samples = Vec::new();
    for row in sample_rows {
        let run: Vec<u8> = row.try_get(0)?;
        let sequence: &str = row.try_get(1)?;
        let priority: Vec<u8> = row.try_get(2)?;
        let value = identity(row.try_get(3)?)?;
        references.insert(value);
        samples.push(ReservoirEntry {
            observation: ObservationId {
                run: run
                    .try_into()
                    .map_err(|_error| invalid("sample run length"))?,
                sequence: sequence.parse()?,
            },
            priority: priority
                .try_into()
                .map_err(|_error| invalid("sample priority length"))?,
            value,
        });
    }
    let ids: Vec<Vec<u8>> = references.iter().map(|id| id.0.to_vec()).collect();
    let bytes: i64 = transaction.query_one(
        "SELECT COALESCE(sum(octet_length(canonical)), 0)::bigint FROM fp_v2.values WHERE authorized=$1 AND id=ANY($2)",
        &[&authorized, &ids],
    ).await?.try_get(0)?;
    if usize::try_from(bytes)? != retained_bytes {
        return Err(invalid("stored retained byte count"));
    }
    *remaining = remaining
        .checked_sub(retained_bytes)
        .ok_or_else(|| bounded("stored batch bytes"))?;
    let rows = transaction
        .query(
            "SELECT id, domain, CASE WHEN octet_length(canonical)::bigint <= $3 THEN canonical END
         FROM fp_v2.values WHERE authorized=$1 AND id=ANY($2) ORDER BY id LIMIT $4",
            &[
                &authorized,
                &ids,
                &integer(limits.ingestion.bucket.value_bytes)?,
                &bounded_rows(ids.len())?,
            ],
        )
        .await?;
    if rows.len() != ids.len() {
        return Err(invalid("stored value coverage"));
    }
    let mut values = Vec::new();
    for row in rows {
        if row.try_get::<_, i32>(1)? != i32::from(domain) {
            return Err(invalid("stored value domain"));
        }
        let bytes: Option<Vec<u8>> = row.try_get(2)?;
        values.push(CanonicalValue {
            id: identity(row.try_get(0)?)?,
            bytes: bytes.ok_or_else(|| bounded("stored value bytes"))?.into(),
        });
    }
    Ok(StoredObservationBucket {
        authorized,
        day,
        bucket: CountedBucketSnapshot {
            format_version: u16::try_from(row.try_get::<_, i32>(2)?)?,
            domain,
            scope: input.scope.id,
            counts: CounterSnapshot {
                untracked_distinct: serde_json::from_str(
                    &row.try_get::<_, Option<String>>(10)?
                        .ok_or_else(|| bounded("stored distinct bytes"))?,
                )?,
                total: u64::try_from(row.try_get::<_, i64>(3)?)?,
                untracked: u64::try_from(row.try_get::<_, i64>(4)?)?,
                values: counts.into(),
                losses: ObservationLosses {
                    oversize: u64::try_from(row.try_get::<_, i64>(7)?)?,
                    retention: u64::try_from(row.try_get::<_, i64>(8)?)?,
                    history_known: row.try_get(9)?,
                },
            },
            samples: samples.into(),
            values: values.into(),
        },
    })
}

async fn intern_metadata(
    transaction: &Transaction<'_>,
    authorized: bool,
    capture: &PreparedProfileCapture,
    quota: &mut Quota,
) -> Result<(), BoxError> {
    let profile = &capture.profile;
    let added = transaction.execute(
        "INSERT INTO fp_v2.profiles (authorized,id,canonical) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        &[&authorized, &&profile.id.0[..], &&profile.bytes[..]],
    ).await?;
    let equal: bool = transaction
        .query_one(
            "SELECT canonical=$3 FROM fp_v2.profiles WHERE authorized=$1 AND id=$2",
            &[&authorized, &&profile.id.0[..], &&profile.bytes[..]],
        )
        .await?
        .try_get(0)?;
    if !equal {
        return Err(invalid("profile hash collision"));
    }
    if added != 0 {
        quota.change(0, 1)?;
        quota.change(6, integer(profile.bytes.len())?)?;
    }
    if let Some(flow) = &capture.flow {
        let added = transaction.execute(
            "INSERT INTO fp_v2.flows (authorized,profile_id,id,canonical) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            &[&authorized, &&profile.id.0[..], &&flow.id.0[..], &&flow.bytes[..]],
        ).await?;
        let equal: bool = transaction.query_one(
            "SELECT canonical=$4 FROM fp_v2.flows WHERE authorized=$1 AND profile_id=$2 AND id=$3",
            &[&authorized, &&profile.id.0[..], &&flow.id.0[..], &&flow.bytes[..]],
        ).await?.try_get(0)?;
        if !equal {
            return Err(invalid("flow hash collision"));
        }
        if added != 0 {
            quota.change(1, 1)?;
            quota.change(6, integer(flow.bytes.len())?)?;
        }
    }
    for input in &capture.buckets {
        let structure = &input.structure;
        let domain = i32::from(input.value.validated_domain(input.value.bytes.len())?);
        let added = transaction.execute(
            "INSERT INTO fp_v2.structures (authorized,id,normalizer,slot,canonical) VALUES ($1,$2,1,$3,$4) ON CONFLICT DO NOTHING",
            &[&authorized, &&structure.id.0[..], &domain, &&structure.bytes[..]],
        ).await?;
        let equal: bool = transaction.query_one(
            "SELECT canonical=$3 AND normalizer=1 AND slot=$4 FROM fp_v2.structures WHERE authorized=$1 AND id=$2",
            &[&authorized, &&structure.id.0[..], &&structure.bytes[..], &domain],
        ).await?.try_get(0)?;
        if !equal {
            return Err(invalid("structure hash collision or version"));
        }
        if added != 0 {
            quota.change(2, 1)?;
            quota.change(6, integer(structure.bytes.len())?)?;
        }
    }
    Ok(())
}

async fn save_bucket(
    transaction: &Transaction<'_>,
    authorized: bool,
    input: &ProfileBucketInput,
    previous: &StoredObservationBucket,
    updated: &StoredObservationBucket,
    quota: &mut Quota,
) -> Result<(), BoxError> {
    let bucket = &updated.bucket;
    let scope = &bucket.scope.0[..];
    let day = i64::from(updated.day);
    let previous_values: BTreeSet<_> = previous
        .bucket
        .values
        .iter()
        .map(|value| value.id)
        .collect();
    for value in &bucket.values {
        // Loaded bytes were already validated by the shared counting engine.
        if previous_values.contains(&value.id) {
            continue;
        }
        let added = transaction.execute(
            "INSERT INTO fp_v2.values (authorized,id,domain,canonical) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            &[&authorized, &&value.id.0[..], &i32::from(bucket.domain), &&value.bytes[..]],
        ).await?;
        let equal: bool = transaction
            .query_one(
                "SELECT canonical=$3 AND domain=$4 FROM fp_v2.values WHERE authorized=$1 AND id=$2",
                &[
                    &authorized,
                    &&value.id.0[..],
                    &&value.bytes[..],
                    &i32::from(bucket.domain),
                ],
            )
            .await?
            .try_get(0)?;
        if !equal {
            return Err(invalid("value hash collision or domain"));
        }
        if added != 0 {
            quota.change(5, 1)?;
            quota.change(6, integer(value.bytes.len())?)?;
        }
    }
    let decoded = ProfileObservationScope::from_canonical(&input.scope, input.scope.bytes.len())?;
    let flow: Option<&[u8]> = decoded.flow.as_ref().map(|id| id.0.as_slice());
    let retained = bucket.values.iter().try_fold(0usize, |n, value| {
        n.checked_add(value.bytes.len())
            .ok_or_else(|| bounded("retained bytes"))
    })?;
    let added = transaction.execute(
        "INSERT INTO fp_v2.buckets (authorized,scope,day,profile_id,flow_id,structure_id,scope_canonical,domain,format_version,total,untracked,retained_bytes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0,0,0) ON CONFLICT DO NOTHING",
        &[&authorized, &scope, &day, &&decoded.profile.0[..], &flow, &&input.structure.id.0[..],
          &&input.scope.bytes[..], &i32::from(bucket.domain), &i32::from(bucket.format_version)],
    ).await?;
    if added != 0 {
        quota.change(3, 1)?;
        quota.change(6, integer(input.scope.bytes.len())?)?;
    }
    transaction.execute(
        "UPDATE fp_v2.buckets SET total=$4,untracked=$5,retained_bytes=$6,dropped_oversize=$7,dropped_retention=$8,history_known=$9,untracked_distinct=$10::text::jsonb WHERE authorized=$1 AND scope=$2 AND day=$3",
        &[&authorized, &scope, &day, &count(bucket.counts.total)?, &count(bucket.counts.untracked)?, &integer(retained)?,
          &count(bucket.counts.losses.oversize)?, &count(bucket.counts.losses.retention)?, &bucket.counts.losses.history_known, &serde_json::to_string(&bucket.counts.untracked_distinct)?],
    ).await?;
    let old_counts: BTreeMap<_, _> = previous
        .bucket
        .counts
        .values
        .iter()
        .map(|entry| (entry.value, entry.count))
        .collect();
    let retained_counts: BTreeSet<_> = bucket
        .counts
        .values
        .iter()
        .map(|entry| entry.value)
        .collect();
    for value in old_counts.keys() {
        if !retained_counts.contains(value) {
            transaction.execute(
                "DELETE FROM fp_v2.literal_counts WHERE authorized=$1 AND scope=$2 AND day=$3 AND value_id=$4",
                &[&authorized, &scope, &day, &&value.0[..]],
            ).await?;
        }
    }
    for entry in &bucket.counts.values {
        if old_counts.get(&entry.value) == Some(&entry.count) {
            continue;
        }
        transaction.execute(
            "INSERT INTO fp_v2.literal_counts (authorized,scope,day,value_id,count) VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (authorized,scope,day,value_id) DO UPDATE SET count=EXCLUDED.count",
            &[&authorized, &scope, &day, &&entry.value.0[..], &count(entry.count)?],
        ).await?;
    }
    let old_samples: BTreeSet<_> = previous
        .bucket
        .samples
        .iter()
        .map(|entry| entry.observation)
        .collect();
    let new_samples: BTreeSet<_> = bucket
        .samples
        .iter()
        .map(|entry| entry.observation)
        .collect();
    for entry in &previous.bucket.samples {
        if !new_samples.contains(&entry.observation) {
            transaction.execute(
                "DELETE FROM fp_v2.samples WHERE authorized=$1 AND scope=$2 AND day=$3 AND run=$4 AND sequence=$5::text::numeric",
                &[&authorized, &scope, &day, &&entry.observation.run[..], &entry.observation.sequence.to_string()],
            ).await?;
        }
    }
    for entry in &bucket.samples {
        if !old_samples.contains(&entry.observation) {
            transaction.execute(
                "INSERT INTO fp_v2.samples (authorized,scope,day,run,sequence,priority,value_id) VALUES ($1,$2,$3,$4,$5::text::numeric,$6,$7)",
                &[&authorized, &scope, &day, &&entry.observation.run[..], &entry.observation.sequence.to_string(), &&entry.priority[..], &&entry.value.0[..]],
            ).await?;
        }
    }
    let retained_ids: BTreeSet<_> = bucket.values.iter().map(|value| value.id).collect();
    for value in &previous.bucket.values {
        if !retained_ids.contains(&value.id) {
            let deleted = transaction.execute(
                "DELETE FROM fp_v2.values v WHERE authorized=$1 AND id=$2
                 AND NOT EXISTS (SELECT 1 FROM fp_v2.literal_counts c WHERE c.authorized=v.authorized AND c.value_id=v.id)
                 AND NOT EXISTS (SELECT 1 FROM fp_v2.samples s WHERE s.authorized=v.authorized AND s.value_id=v.id)",
                &[&authorized, &&value.id.0[..]],
            ).await?;
            if deleted != 0 {
                quota.change(5, -1)?;
                quota.change(6, -integer(value.bytes.len())?)?;
            }
        }
    }
    Ok(())
}

/// Delete at most `rows` entries from each owned table. Counts and samples expire
/// with their day bucket. Shared values remain until their last retained reference.
/// Returns whether another bounded pass may have work; no legacy table is touched.
pub(super) async fn prune(
    client: &mut Client,
    authorized: bool,
    current_day: u32,
    limits: StoreLimits,
    rows: usize,
) -> Result<bool, BoxError> {
    if rows == 0 {
        return Err(bounded("maintenance rows"));
    }
    let first = i64::from(
        limits
            .ingestion
            .retention
            .first_day(current_day, limits.ingestion.retention.days)?,
    );
    let transaction = client.transaction().await?;
    let stored = transaction.query_one(
        "SELECT watermark,profiles,flows,structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=$1 FOR UPDATE",
        &[&authorized],
    ).await?;
    if i64::from(current_day) < stored.try_get::<_, i64>(0)? {
        return Err(invalid("storage time watermark"));
    }
    let mut quota = Quota {
        used: [0; 7],
        maximum: limits.retained,
    };
    for index in 0..7 {
        quota.used[index] = stored.try_get(index + 1)?;
        quota.change(index, 0)?;
    }
    let maximum = integer(rows)?;
    let mut more = false;
    let expired = transaction.query(
        "DELETE FROM fp_v2.buckets b USING
           (SELECT authorized,scope,day FROM fp_v2.buckets WHERE authorized=$1 AND day<$2 ORDER BY day,scope LIMIT $3) old
         WHERE b.authorized=old.authorized AND b.scope=old.scope AND b.day=old.day RETURNING octet_length(b.scope_canonical)",
        &[&authorized, &first, &maximum],
    ).await?;
    more |= expired.len() == rows;
    for row in expired {
        quota.change(3, -1)?;
        quota.change(6, -i64::from(row.try_get::<_, i32>(0)?))?;
    }
    let expired = transaction.execute(
        "DELETE FROM fp_v2.runs r USING
           (SELECT authorized,id FROM fp_v2.runs WHERE authorized=$1 AND created_day<$2 ORDER BY created_day,id LIMIT $3) old
         WHERE r.authorized=old.authorized AND r.id=old.id",
        &[&authorized, &first, &maximum],
    ).await?;
    quota.change(4, -i64::try_from(expired)?)?;
    more |= usize::try_from(expired)? == rows;
    // Each query has a bounded result and all reference lookups have owned indexes.
    for (index, query) in [
        (5, "DELETE FROM fp_v2.values v USING
             (SELECT v.authorized,v.id FROM fp_v2.values v WHERE v.authorized=$1
              AND NOT EXISTS (SELECT 1 FROM fp_v2.literal_counts c WHERE c.authorized=v.authorized AND c.value_id=v.id)
              AND NOT EXISTS (SELECT 1 FROM fp_v2.samples s WHERE s.authorized=v.authorized AND s.value_id=v.id)
              ORDER BY v.id LIMIT $2) old
             WHERE v.authorized=old.authorized AND v.id=old.id RETURNING octet_length(v.canonical)"),
        (2, "DELETE FROM fp_v2.structures s USING
             (SELECT s.authorized,s.id FROM fp_v2.structures s WHERE s.authorized=$1
              AND NOT EXISTS (SELECT 1 FROM fp_v2.buckets b WHERE b.authorized=s.authorized AND b.structure_id=s.id)
              ORDER BY s.id LIMIT $2) old
             WHERE s.authorized=old.authorized AND s.id=old.id RETURNING octet_length(s.canonical)"),
        (1, "DELETE FROM fp_v2.flows f USING
             (SELECT f.authorized,f.profile_id,f.id FROM fp_v2.flows f WHERE f.authorized=$1
              AND NOT EXISTS (SELECT 1 FROM fp_v2.buckets b WHERE b.authorized=f.authorized AND b.profile_id=f.profile_id AND b.flow_id=f.id)
              ORDER BY f.profile_id,f.id LIMIT $2) old
             WHERE f.authorized=old.authorized AND f.profile_id=old.profile_id AND f.id=old.id RETURNING octet_length(f.canonical)"),
        (0, "DELETE FROM fp_v2.profiles p USING
             (SELECT p.authorized,p.id FROM fp_v2.profiles p WHERE p.authorized=$1
              AND NOT EXISTS (SELECT 1 FROM fp_v2.buckets b WHERE b.authorized=p.authorized AND b.profile_id=p.id)
              AND NOT EXISTS (SELECT 1 FROM fp_v2.flows f WHERE f.authorized=p.authorized AND f.profile_id=p.id)
              ORDER BY p.id LIMIT $2) old
             WHERE p.authorized=old.authorized AND p.id=old.id RETURNING octet_length(p.canonical)"),
    ] {
        let deleted = transaction.query(query, &[&authorized, &maximum]).await?;
        more |= deleted.len() == rows;
        for row in deleted { quota.change(index, -1)?; quota.change(6, -i64::from(row.try_get::<_, i32>(0)?))?; }
    }
    transaction.execute(
        "UPDATE fp_v2.quotas SET watermark=$2,profiles=$3,flows=$4,structures=$5,buckets=$6,runs=$7,interned_values=$8,canonical_bytes=$9 WHERE authorized=$1",
        &[&authorized, &i64::from(current_day), &quota.used[0], &quota.used[1], &quota.used[2], &quota.used[3], &quota.used[4], &quota.used[5], &quota.used[6]],
    ).await?;
    transaction.commit().await?;
    Ok(more)
}

#[cfg(all(test, unix))]
mod tests;
