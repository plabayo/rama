use super::super::migrations;
use super::*;
use rama::{
    http::{HeaderMap, HeaderValue, Method, Version},
    ua::profile::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, ConnectionContext, FlowKey,
        HeaderCapturePolicy, JointCapture, ObservationWeight, OrderCaptureLimits, OrderNamespace,
        OrderedProtocolCapture, ProfileKey,
    },
    utils::octets::{kib, mib},
};
use std::error::Error;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    task::JoinSet,
};
use tokio_postgres::{
    Error as PgError, NoTls,
    config::{Host, SslMode},
    error::SqlState,
};

fn limits() -> StoreLimits {
    StoreLimits {
        ingestion: IngestionBatchLimits::default(),
        capture: JointCaptureLimits::default(),
        retained: [32, 32, 64, 128, 64, 2048, mib(4)],
        checkpoint_bytes: kib(16),
    }
}
fn capture(value: &'static str) -> Result<ProfileCapture, BoxError> {
    let policy = HeaderCapturePolicy::default();
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static(value));
    headers.insert(
        "authorization",
        HeaderValue::from_static("excluded-credential"),
    );
    Ok(ProfileCapture {
        profile: ProfileKey::new("counted-test"),
        flow: Some(FlowKey::Http {
            version: Version::HTTP_3,
            method: Method::GET,
            initiator: None,
            fetch: None,
            connection: ConnectionContext::default(),
        }),
        connection: ConnectionContext::default(),
        joint: JointCapture {
            level: CaptureLevel::Request,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: policy
                    .capture(Version::HTTP_3, &headers, None)?
                    .canonical(&policy)?,
            }]
            .into(),
        },
    })
}
fn attempt(authorized: bool, sequence: u64) -> IngestionAttempt {
    IngestionAttempt {
        authorized,
        observation_day: 100,
        observation: ObservationId {
            run: CaptureRunId::new(100, [1; 12]).0,
            sequence,
        },
    }
}
async fn state(client: &Client) -> Result<Vec<String>, BoxError> {
    let mut output = Vec::new();
    for query in [
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,id), '[]')::text FROM fp_v2.profiles p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,profile_id,id), '[]')::text FROM fp_v2.flows p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,id), '[]')::text FROM fp_v2.structures p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,id), '[]')::text FROM fp_v2.values p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,scope,day), '[]')::text FROM fp_v2.buckets p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,scope,day,value_id), '[]')::text FROM fp_v2.literal_counts p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,scope,day,run,sequence), '[]')::text FROM fp_v2.samples p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized,id), '[]')::text FROM fp_v2.runs p",
        "SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY authorized), '[]')::text FROM fp_v2.quotas p",
    ] {
        output.push(client.query_one(query, &[]).await?.try_get(0)?);
    }
    Ok(output)
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_is_atomic_and_retry_safe() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let limits = limits();
    let capture = capture("text/html").unwrap();
    assert!(
        ingest(
            &mut client,
            100,
            attempt(false, 1),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    let before = state(&client).await.unwrap();
    assert!(
        !ingest(
            &mut client,
            101,
            attempt(false, 1),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    assert_eq!(state(&client).await.unwrap(), before);
    let mut capped = limits;
    capped.retained[3] = 2;
    let mut next = attempt(false, 2);
    next.observation_day = 101;
    ingest(&mut client, 101, next, &capture, [3; 32], capped)
        .await
        .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
    // A fresh scope has no sample-priority guard to mask a missing seed guard.
    let mut other_scope = capture.clone();
    other_scope.profile.client = "another-client".into();
    ingest(
        &mut client,
        100,
        attempt(false, 2),
        &other_scope,
        [4; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
    let prepared = capture.prepare(false, limits.capture).unwrap();
    // A later component overflow rejects the complete prepared batch.
    let scope = &prepared.buckets[1].scope.id.0[..];
    client.execute("UPDATE fp_v2.buckets SET total=9223372036854775807, untracked=9223372036854775806 WHERE authorized=FALSE AND scope=$1", &[&scope]).await.unwrap();
    let corrupt = state(&client).await.unwrap();
    ingest(
        &mut client,
        100,
        attempt(false, 2),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), corrupt);
    client
        .execute(
            "UPDATE fp_v2.buckets SET total=1, untracked=0 WHERE authorized=FALSE AND scope=$1",
            &[&scope],
        )
        .await
        .unwrap();
    assert!(
        ingest(
            &mut client,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    assert!(
        ingest(
            &mut client,
            100,
            attempt(true, 1),
            &capture,
            [9; 32],
            limits
        )
        .await
        .unwrap()
    );
    let totals: Vec<(bool,i64)> = client.query("SELECT authorized, sum(total)::bigint FROM fp_v2.buckets GROUP BY authorized ORDER BY authorized", &[]).await.unwrap().iter().map(|row| (row.get(0),row.get(1))).collect();
    assert_eq!(totals, [(false, 4), (true, 2)]);
    let leaked: bool = client.query_one(
        "SELECT EXISTS(SELECT 1 FROM fp_v2.values WHERE position(convert_to('excluded-credential','UTF8') in canonical)>0)", &[],
    ).await.unwrap().get(0);
    assert!(!leaked);
    let before = state(&client).await.unwrap();
    ingest(
        &mut client,
        114,
        attempt(false, 3),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_serializes_concurrent_duplicate_ids() {
    let (config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut jobs = JoinSet::new();
    for index in 0..24 {
        let config = config.clone();
        jobs.spawn(async move {
            let (mut client, connection) = config.connect(NoTls).await.unwrap();
            tokio::spawn(connection);
            ingest(
                &mut client,
                100,
                attempt(false, index % 8 + 1),
                &capture("text/html").unwrap(),
                [3; 32],
                limits(),
            )
            .await
            .unwrap()
        });
    }
    let mut committed = 0;
    while let Some(result) = jobs.join_next().await {
        committed += usize::from(result.unwrap());
    }
    assert_eq!(committed, 8);
    let rows = client
        .query("SELECT total FROM fp_v2.buckets", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.get::<_, i64>(0) == 8));
    let quota: (i64, i64, i64, i64, i64, i64) = {
        let row = client.query_one("SELECT profiles,flows,structures,buckets,runs,interned_values FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
        (
            row.get(0),
            row.get(1),
            row.get(2),
            row.get(3),
            row.get(4),
            row.get(5),
        )
    };
    assert_eq!(quota, (1, 1, 2, 2, 1, 2));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_rejects_corrupt_identity_and_oversized_rows() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    let prepared = capture.prepare(false, limits.capture).unwrap();
    client
        .execute(
            "UPDATE fp_v2.profiles SET canonical='forged' WHERE authorized=FALSE",
            &[],
        )
        .await
        .unwrap();
    let before = state(&client).await.unwrap();
    ingest(
        &mut client,
        100,
        attempt(false, 2),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
    client
        .execute(
            "UPDATE fp_v2.profiles SET canonical=$1 WHERE authorized=FALSE",
            &[&&prepared.profile.bytes[..]],
        )
        .await
        .unwrap();
    client.execute("UPDATE fp_v2.runs SET checkpoint=checkpoint || jsonb_build_object('padding',repeat('x',$1)) WHERE authorized=FALSE", &[&i32::try_from(kib(20)).unwrap()]).await.unwrap();
    let before = state(&client).await.unwrap();
    ingest(
        &mut client,
        100,
        attempt(false, 2),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_retention_expires_weights_and_reclaims_shared_values() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    let mut recent = attempt(false, 1);
    recent.observation_day = 113;
    recent.observation.run = CaptureRunId::new(113, [2; 12]).0;
    ingest(&mut client, 113, recent, &capture, [3; 32], limits)
        .await
        .unwrap();
    recent.authorized = true;
    ingest(&mut client, 113, recent, &capture, [3; 32], limits)
        .await
        .unwrap();
    let inclusive = state(&client).await.unwrap();
    assert!(!prune(&mut client, false, 113, limits, 128).await.unwrap());
    assert_eq!(state(&client).await.unwrap(), inclusive);
    // One old bucket is removed per pass; shared interned values stay referenced.
    assert!(prune(&mut client, false, 114, limits, 1).await.unwrap());
    assert!(prune(&mut client, false, 114, limits, 1).await.unwrap());
    assert!(!prune(&mut client, false, 114, limits, 1).await.unwrap());
    let row = client
        .query_one(
            "SELECT buckets,runs,interned_values FROM fp_v2.quotas WHERE authorized=FALSE",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (2, 1, 2)
    );
    let total: i64 = client
        .query_one(
            "SELECT sum(total)::bigint FROM fp_v2.buckets WHERE authorized=FALSE",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(total, 2);
    for _ in 0..8 {
        if !prune(&mut client, false, 127, limits, 1).await.unwrap() {
            break;
        }
    }
    let row = client.query_one("SELECT profiles,flows,structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
    for index in 0..7 {
        assert_eq!(row.get::<_, i64>(index), 0);
    }
    let private_total: i64 = client
        .query_one(
            "SELECT sum(total)::bigint FROM fp_v2.buckets WHERE authorized=TRUE",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(private_total, 2);
    // An expired run remains expired after its checkpoint was reclaimed.
    let before = state(&client).await.unwrap();
    ingest(
        &mut client,
        127,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_reservoir_reuses_full_quota_and_survives_restart() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut limits = limits();
    limits.ingestion.bucket.literal_values = 0;
    limits.ingestion.bucket.samples = 1;
    limits.retained[5] = 2;
    let mut last = None;
    for sequence in 1_u64..=10_000 {
        let value = OrderedProtocolCapture::capture(
            OrderNamespace::QuicParameter,
            [(27, sequence.to_be_bytes().as_slice())],
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        let capture = ProfileCapture {
            profile: ProfileKey::new("varying-parameters"),
            flow: None,
            connection: ConnectionContext::default(),
            joint: JointCapture {
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::QuicParameters,
                    value,
                }]
                .into(),
            },
        };
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, sequence),
                &capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
        if sequence == 1 {
            let bytes: i64 = client
                .query_one(
                    "SELECT canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            limits.retained[6] = usize::try_from(bytes).unwrap();
        }
        last = Some(capture);
    }
    let prepared = last.unwrap().prepare(false, limits.capture).unwrap();
    let transaction = client.transaction().await.unwrap();
    let mut remaining = limits.ingestion.input_bytes;
    for input in &prepared.buckets {
        let restored = load_bucket(
            &transaction,
            false,
            100,
            input,
            [3; 32],
            limits,
            &mut remaining,
        )
        .await
        .unwrap();
        let bucket = CountedObservationBucket::from_snapshot(
            &restored.bucket,
            [3; 32],
            limits.ingestion.bucket,
        )
        .unwrap();
        let snapshot = bucket.snapshot();
        assert_eq!(snapshot.counts.total, 10_000);
        assert_eq!(snapshot.counts.untracked, 10_000);
        assert_eq!(snapshot.values.len(), 1);
        assert_eq!(snapshot.samples.len(), 1);
    }
    transaction.rollback().await.unwrap();
    let row = client.query_one("SELECT structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3)
        ),
        (2, 2, 1, 2)
    );
    assert_eq!(
        usize::try_from(row.get::<_, i64>(4)).unwrap(),
        limits.retained[6]
    );
    let orphaned: bool = client.query_one("SELECT EXISTS(SELECT 1 FROM fp_v2.values v WHERE NOT EXISTS(SELECT 1 FROM fp_v2.samples s WHERE s.authorized=v.authorized AND s.value_id=v.id))", &[]).await.unwrap().get(0);
    assert!(!orphaned);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_rolls_back_after_a_database_write_failure() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    let prepared = capture.prepare(false, limits.capture).unwrap();
    // The joint bucket is saved before the leaf. This trigger fails the second write.
    let hex: String = prepared.buckets[1]
        .scope
        .id
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    client.batch_execute(&format!(
        "CREATE FUNCTION fp_v2.fail_leaf() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.scope=decode('{hex}','hex') AND NEW.total=2 THEN RAISE EXCEPTION 'injected second bucket failure'; END IF;
          RETURN NEW; END $$;
         CREATE TRIGGER fail_leaf BEFORE UPDATE ON fp_v2.buckets FOR EACH ROW EXECUTE FUNCTION fp_v2.fail_leaf();"
    )).await.unwrap();
    let before = state(&client).await.unwrap();
    ingest(
        &mut client,
        100,
        attempt(false, 2),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
    client
        .batch_execute("DROP TRIGGER fail_leaf ON fp_v2.buckets; DROP FUNCTION fp_v2.fail_leaf()")
        .await
        .unwrap();
    assert!(
        ingest(
            &mut client,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_verifies_every_interned_identity() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    let prepared = capture.prepare(false, limits.capture).unwrap();
    for (update, restore, bytes, error_text) in [
        (
            "UPDATE fp_v2.profiles SET canonical='forged' WHERE authorized=FALSE",
            "UPDATE fp_v2.profiles SET canonical=$1 WHERE authorized=FALSE",
            prepared.profile.bytes.as_ref(),
            "profile hash collision",
        ),
        (
            "UPDATE fp_v2.flows SET canonical='forged' WHERE authorized=FALSE",
            "UPDATE fp_v2.flows SET canonical=$1 WHERE authorized=FALSE",
            prepared.flow.as_ref().unwrap().bytes.as_ref(),
            "flow hash collision",
        ),
    ] {
        client.execute(update, &[]).await.unwrap();
        let before = state(&client).await.unwrap();
        let error = ingest(
            &mut client,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(error_text), "{error}");
        assert_eq!(state(&client).await.unwrap(), before);
        client.execute(restore, &[&bytes]).await.unwrap();
    }
    for input in &prepared.buckets {
        let id = &input.structure.id.0[..];
        client
            .execute(
                "UPDATE fp_v2.structures SET canonical='forged' WHERE authorized=FALSE AND id=$1",
                &[&id],
            )
            .await
            .unwrap();
        let before = state(&client).await.unwrap();
        let error = ingest(
            &mut client,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("structure hash collision"),
            "{error}"
        );
        assert_eq!(state(&client).await.unwrap(), before);
        client
            .execute(
                "UPDATE fp_v2.structures SET canonical=$2 WHERE authorized=FALSE AND id=$1",
                &[&id, &&input.structure.bytes[..]],
            )
            .await
            .unwrap();
    }
    let next = self::capture("application/json").unwrap();
    let prepared = next.prepare(false, limits.capture).unwrap();
    let incoming = &prepared.buckets[1].value;
    client.execute("INSERT INTO fp_v2.values (authorized,id,domain,canonical) VALUES (FALSE,$1,$2,'forged')",&[&&incoming.id.0[..],&i32::from(incoming.validated_domain(limits.capture.bytes).unwrap())]).await.unwrap();
    client.execute("UPDATE fp_v2.quotas SET interned_values=interned_values+1,canonical_bytes=canonical_bytes+6 WHERE authorized=FALSE",&[]).await.unwrap();
    let before = state(&client).await.unwrap();
    let error = ingest(&mut client, 100, attempt(false, 2), &next, [3; 32], limits)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("value hash collision"),
        "{error}"
    );
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_retains_unsigned_sequences_without_truncation() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    // Restore a writer cursor near the unsigned boundary; retained samples need
    // not cover the cursor's entire history, which also includes other scopes.
    client.execute("UPDATE fp_v2.runs SET checkpoint=jsonb_set(checkpoint,'{sequences,prefix}','18446744073709551614') WHERE authorized=FALSE",&[]).await.unwrap();
    assert!(
        ingest(
            &mut client,
            100,
            attempt(false, u64::MAX),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    let rows = client
        .query(
            "SELECT sequence::text FROM fp_v2.samples WHERE sequence>9223372036854775807",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.get::<_, String>(0), u64::MAX.to_string());
    }
    assert!(
        !ingest(
            &mut client,
            100,
            attempt(false, u64::MAX),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    let before = state(&client).await.unwrap();
    // A new run has no later run watermark to mask the partition watermark.
    let mut earlier = attempt(false, 1);
    earlier.observation_day = 99;
    earlier.observation.run = CaptureRunId::new(99, [8; 12]).0;
    ingest(&mut client, 99, earlier, &capture, [3; 32], limits)
        .await
        .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_bounds_payload_reads_before_decoding() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    let prepared = capture.prepare(false, limits.capture).unwrap();
    let input = &prepared.buckets[0];
    let oversized = vec![0_u8; limits.ingestion.bucket.value_bytes + 1];
    client
        .execute(
            "UPDATE fp_v2.values SET canonical=$2 WHERE authorized=FALSE AND id=$1",
            &[&&input.value.id.0[..], &oversized],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE fp_v2.buckets SET retained_bytes=$2 WHERE authorized=FALSE AND scope=$1",
            &[
                &&input.scope.id.0[..],
                &i64::try_from(oversized.len()).unwrap(),
            ],
        )
        .await
        .unwrap();
    let before = state(&client).await.unwrap();
    let error = ingest(
        &mut client,
        100,
        attempt(false, 2),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    // A later digest error would mean the oversized payload was already fetched.
    assert!(error.to_string().contains("stored value bytes"), "{error}");
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_rejects_inconsistent_bucket_metadata() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    let prepared = capture.prepare(false, limits.capture).unwrap();
    let input = &prepared.buckets[0];
    let scope = &input.scope.id.0[..];
    let flow = &prepared.flow.as_ref().unwrap().id.0[..];
    let domain = i32::from(input.value.validated_domain(limits.capture.bytes).unwrap());
    for query in [
        "UPDATE fp_v2.buckets SET scope_canonical='forged' WHERE authorized=FALSE AND scope=$1",
        "UPDATE fp_v2.buckets SET domain=2 WHERE authorized=FALSE AND scope=$1",
        "UPDATE fp_v2.buckets SET flow_id=NULL WHERE authorized=FALSE AND scope=$1",
        "UPDATE fp_v2.buckets SET format_version=2 WHERE authorized=FALSE AND scope=$1",
        "UPDATE fp_v2.buckets SET retained_bytes=retained_bytes+1 WHERE authorized=FALSE AND scope=$1",
    ] {
        client.execute(query, &[&scope]).await.unwrap();
        let before = state(&client).await.unwrap();
        ingest(
            &mut client,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits,
        )
        .await
        .unwrap_err();
        assert_eq!(state(&client).await.unwrap(), before);
        client.execute("UPDATE fp_v2.buckets SET scope_canonical=$2,domain=$3,flow_id=$4,format_version=1,retained_bytes=$5 WHERE authorized=FALSE AND scope=$1",
            &[&scope,&&input.scope.bytes[..],&domain,&flow,&i64::try_from(input.value.bytes.len()).unwrap()]).await.unwrap();
    }
    assert!(
        ingest(
            &mut client,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_locks_partition_before_loading_or_writing() {
    let (config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    // If the initial quota lock is absent, the writer reaches this deterministic
    // sentinel instead of waiting for the held row. No scheduling race is needed.
    client.batch_execute("CREATE FUNCTION fp_v2.lock_sentinel() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'writer reached metadata before taking its quota lock'; END $$;
        CREATE TRIGGER lock_sentinel BEFORE INSERT ON fp_v2.profiles FOR EACH ROW EXECUTE FUNCTION fp_v2.lock_sentinel();").await.unwrap();
    let held = client.transaction().await.unwrap();
    held.query_one(
        "SELECT authorized FROM fp_v2.quotas WHERE authorized=FALSE FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    let (mut contender, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    contender
        .batch_execute("SET lock_timeout='100ms'")
        .await
        .unwrap();
    let capture = capture("text/html").unwrap();
    let error = ingest(
        &mut contender,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .source()
            .and_then(|error| error.downcast_ref::<PgError>())
            .and_then(PgError::code),
        Some(&SqlState::LOCK_NOT_AVAILABLE)
    );
    held.rollback().await.unwrap();
    client
        .batch_execute(
            "DROP TRIGGER lock_sentinel ON fp_v2.profiles; DROP FUNCTION fp_v2.lock_sentinel()",
        )
        .await
        .unwrap();
    assert!(
        ingest(
            &mut contender,
            100,
            attempt(false, 1),
            &capture,
            [3; 32],
            limits()
        )
        .await
        .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_does_not_replace_a_missing_persisted_seed() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut capture = capture("text/html").unwrap();
    let limits = limits();
    ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    client
        .execute(
            "UPDATE fp_v2.quotas SET sampler_seed=NULL WHERE authorized=FALSE",
            &[],
        )
        .await
        .unwrap();
    capture.profile.client = "fresh-scope-without-samples".into();
    let before = state(&client).await.unwrap();
    let error = ingest(
        &mut client,
        100,
        attempt(false, 2),
        &capture,
        [4; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("missing persisted sampler seed"),
        "{error}"
    );
    assert_eq!(state(&client).await.unwrap(), before);
    // Restore the original seed; the rejected observation ID remains available.
    client
        .execute(
            "UPDATE fp_v2.quotas SET sampler_seed=$1 WHERE authorized=FALSE",
            &[&&[3_u8; 32][..]],
        )
        .await
        .unwrap();
    assert!(
        ingest(
            &mut client,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_writer_retries_a_lost_commit_reply_without_double_counting() {
    let (mut config, mut control) = migrations::tests::isolated_database().await.unwrap();
    control
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut control).await.unwrap();
    let limits = limits();
    let capture = capture("text/html").unwrap();
    let Host::Unix(path) = &config.get_hosts()[0] else {
        panic!("private database must have a Unix socket")
    };
    let socket = path.join(format!(
        ".s.PGSQL.{}",
        config.get_ports().first().copied().unwrap_or(5432)
    ));
    let backend = UnixStream::connect(socket).await.unwrap();
    let (frontend, relay) = io::duplex(kib(64));
    config.ssl_mode(SslMode::Disable);
    let proxy = tokio::spawn(async move {
        let (mut from_client, mut to_client) = io::split(relay);
        let (mut from_server, mut to_server) = backend.into_split();
        tokio::select! {
            result = io::copy(&mut from_client, &mut to_server) => panic!("client closed before COMMIT: {result:?}"),
            () = async {
                loop {
                    let mut header = [0; 5];
                    from_server.read_exact(&mut header).await.unwrap();
                    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
                    assert!((4..=mib(1)).contains(&length));
                    let mut payload = vec![0; length - 4];
                    from_server.read_exact(&mut payload).await.unwrap();
                    if header[0] == b'C' && payload == b"COMMIT\0" {
                        // PostgreSQL has committed. Close only this test socket before
                        // forwarding CommandComplete, so the client cannot know the result.
                        break;
                    }
                    to_client.write_all(&header).await.unwrap();
                    to_client.write_all(&payload).await.unwrap();
                }
            } => {}
        }
    });
    let (mut client, connection) = config.connect_raw(frontend, NoTls).await.unwrap();
    let connection = tokio::spawn(connection);
    let error = ingest(
        &mut client,
        100,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, IngestFailure::Unconfirmed(_)), "{error}");
    proxy.await.unwrap();
    connection.await.unwrap().unwrap_err();
    let before = state(&control).await.unwrap();
    let totals: Vec<i64> = control
        .query("SELECT total FROM fp_v2.buckets ORDER BY scope", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(totals, vec![1, 1]);
    assert!(
        !ingest(
            &mut control,
            100,
            attempt(false, 1),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    assert_eq!(state(&control).await.unwrap(), before);
    let mut capped = limits;
    capped.retained[0] = 0;
    let error = ingest(
        &mut control,
        100,
        attempt(false, 2),
        &capture,
        [3; 32],
        capped,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, IngestFailure::Rejected(_)), "{error}");
    assert_eq!(state(&control).await.unwrap(), before);
    assert!(
        ingest(
            &mut control,
            100,
            attempt(false, 2),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_sampler_seed_is_shared_across_startups_and_never_replaced() {
    let (config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut jobs = JoinSet::new();
    for candidate in 1..=8 {
        let config = config.clone();
        jobs.spawn(async move {
            let (mut client, connection) = config.connect(NoTls).await.unwrap();
            tokio::spawn(connection);
            sampler_seeds(&mut client, [[candidate; 32], [candidate + 16; 32]])
                .await
                .unwrap()
        });
    }
    let first = jobs.join_next().await.unwrap().unwrap();
    while let Some(result) = jobs.join_next().await {
        assert_eq!(result.unwrap(), first);
    }
    assert_ne!(first[0], first[1]);
    assert_eq!(
        sampler_seeds(&mut client, [[0; 32]; 2]).await.unwrap(),
        first
    );
    let capture = capture("text/html").unwrap();
    ingest(
        &mut client,
        100,
        attempt(true, 1),
        &capture,
        first[1],
        limits(),
    )
    .await
    .unwrap();
    // Failure in the second partition also rolls back creation in the first.
    client
        .batch_execute("UPDATE fp_v2.quotas SET sampler_seed=NULL")
        .await
        .unwrap();
    let before = state(&client).await.unwrap();
    let error = sampler_seeds(&mut client, [[9; 32]; 2]).await.unwrap_err();
    assert!(
        error.to_string().contains("missing persisted sampler seed"),
        "{error}"
    );
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_sampler_locks_before_choosing_a_seed() {
    let (config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    client.batch_execute("CREATE FUNCTION fp_v2.seed_lock_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'seed update preceded initial partition lock'; END $$;
        CREATE TRIGGER seed_lock_probe BEFORE UPDATE ON fp_v2.quotas FOR EACH STATEMENT EXECUTE FUNCTION fp_v2.seed_lock_probe()").await.unwrap();
    let held = client.transaction().await.unwrap();
    held.query_one(
        "SELECT authorized FROM fp_v2.quotas WHERE NOT authorized FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    let (mut contender, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    contender
        .batch_execute("SET lock_timeout='100ms'")
        .await
        .unwrap();
    let error = sampler_seeds(&mut contender, [[3; 32]; 2])
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<PgError>().and_then(PgError::code),
        Some(&SqlState::LOCK_NOT_AVAILABLE)
    );
    held.rollback().await.unwrap();
    client
        .batch_execute(
            "DROP TRIGGER seed_lock_probe ON fp_v2.quotas; DROP FUNCTION fp_v2.seed_lock_probe()",
        )
        .await
        .unwrap();
    assert_eq!(
        sampler_seeds(&mut contender, [[3; 32]; 2]).await.unwrap(),
        [[3; 32]; 2]
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_literal_eviction_reclaims_rows_before_the_next_load() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut limits = limits();
    limits.ingestion.bucket.literal_values = 1;
    limits.ingestion.bucket.samples = 0;
    let capture = |byte| ProfileCapture {
        profile: ProfileKey::new("literal-eviction"),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::QuicParameters,
                value: OrderedProtocolCapture::capture(
                    OrderNamespace::QuicParameter,
                    [(27, [byte])],
                    OrderCaptureLimits::default(),
                )
                .unwrap()
                .canonical(OrderCaptureLimits::default())
                .unwrap(),
            }]
            .into(),
        },
    };
    let (mut a, mut b) = (capture(1), capture(2));
    if a.joint.slots[0].value.id < b.joint.slots[0].value.id {
        std::mem::swap(&mut a, &mut b);
    }
    for (index, capture) in [&a, &b, &b].into_iter().enumerate() {
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, index as u64 + 1),
                capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
    }
    let prepared_a = a.prepare(false, limits.capture).unwrap();
    let prepared_b = b.prepare(false, limits.capture).unwrap();
    for (a, b) in prepared_a.buckets.iter().zip(&prepared_b.buckets) {
        assert_eq!(a.scope.id, b.scope.id);
        let expected = a.value.id.min(b.value.id);
        let rows = client
            .query(
                "SELECT value_id,count FROM fp_v2.literal_counts WHERE NOT authorized AND scope=$1",
                &[&&a.scope.id.0[..]],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, Vec<u8>>(0), expected.0);
        assert_eq!(
            rows[0].get::<_, i64>(1),
            if expected == b.value.id { 2 } else { 1 }
        );
    }
    let values: i64 = client
        .query_one("SELECT count(*) FROM fp_v2.values", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(values, 2);
    let quota: i64 = client
        .query_one(
            "SELECT interned_values FROM fp_v2.quotas WHERE NOT authorized",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(quota, 2);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_loss_accounting_survives_retry_restart_and_old_history() {
    let (config, mut client) = migrations::tests::isolated_database().await.unwrap();
    for oversize in [true, false] {
        client
            .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
            .await
            .unwrap();
        migrations::apply(&mut client).await.unwrap();
        let mut limits = limits();
        if oversize {
            limits.ingestion.bucket.value_bytes = 1;
        } else {
            limits.ingestion.retained_bytes = 0;
        }
        let capture = capture("text/html").unwrap();
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, 1),
                &capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
        let before = state(&client).await.unwrap();
        assert!(
            !ingest(
                &mut client,
                100,
                attempt(false, 1),
                &capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
        assert_eq!(state(&client).await.unwrap(), before);
        let (mut restarted, connection) = config.connect(NoTls).await.unwrap();
        tokio::spawn(connection);
        assert!(
            !ingest(
                &mut restarted,
                100,
                attempt(false, 1),
                &capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
        assert!(
            ingest(
                &mut restarted,
                100,
                attempt(false, 2),
                &capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
        let rows = client.query("SELECT total,untracked,dropped_oversize,dropped_retention,history_known FROM fp_v2.buckets ORDER BY scope", &[]).await.unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row.get::<_, i64>(0), 2);
            assert_eq!(row.get::<_, i64>(1), 2);
            assert_eq!(row.get::<_, i64>(2), if oversize { 2 } else { 0 });
            assert_eq!(row.get::<_, i64>(3), if oversize { 0 } else { 2 });
            assert!(row.get::<_, bool>(4));
        }
        for table in ["values", "samples", "literal_counts"] {
            let count: i64 = client
                .query_one(&format!("SELECT count(*) FROM fp_v2.{table}"), &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(count, 0);
        }
        let error = client
            .execute("UPDATE fp_v2.buckets SET dropped_retention=3", &[])
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
        client
            .execute("UPDATE fp_v2.buckets SET history_known=FALSE", &[])
            .await
            .unwrap();
        assert!(
            ingest(
                &mut restarted,
                100,
                attempt(false, 3),
                &capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
        let unknown: bool = client
            .query_one("SELECT bool_and(NOT history_known) FROM fp_v2.buckets", &[])
            .await
            .unwrap()
            .get(0);
        assert!(unknown);
        let prepared = capture.prepare(false, limits.capture).unwrap();
        let transaction = restarted.transaction().await.unwrap();
        let mut remaining = limits.ingestion.input_bytes;
        for input in &prepared.buckets {
            let loaded = load_bucket(
                &transaction,
                false,
                100,
                input,
                [3; 32],
                limits,
                &mut remaining,
            )
            .await
            .unwrap();
            let bucket = CountedObservationBucket::from_snapshot(
                &loaded.bucket,
                [3; 32],
                limits.ingestion.bucket,
            )
            .unwrap();
            assert!(matches!(
                bucket.counts().weight(input.value.id),
                ObservationWeight::UnknownHistory { .. }
            ));
        }
        transaction.rollback().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_default_joint_limit_counts_oversize_without_losing_its_components() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let limits = limits();
    let orders = OrderCaptureLimits::default();
    let capture = ProfileCapture {
        profile: ProfileKey::new("large-joint"),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            level: CaptureLevel::Connection,
            slots: vec![
                CapturedSlot {
                    kind: CapturedSlotKind::QuicParameters,
                    value: OrderedProtocolCapture::capture(
                        OrderNamespace::QuicParameter,
                        [(27, vec![b'a'; kib(15)])],
                        orders,
                    )
                    .unwrap()
                    .canonical(orders)
                    .unwrap(),
                },
                CapturedSlot {
                    kind: CapturedSlotKind::Http3Settings,
                    value: OrderedProtocolCapture::capture(
                        OrderNamespace::Http3Setting,
                        (100..200).map(|id| (id, 1u64.to_be_bytes())),
                        orders,
                    )
                    .unwrap()
                    .canonical(orders)
                    .unwrap(),
                },
            ]
            .into(),
        },
    };
    let prepared = capture.prepare(false, limits.capture).unwrap();
    assert_eq!(
        prepared
            .buckets
            .iter()
            .filter(|input| input.value.bytes.len() > limits.ingestion.bucket.value_bytes)
            .count(),
        1
    );
    for sequence in 1..=2 {
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, sequence),
                &capture,
                [3; 32],
                limits
            )
            .await
            .unwrap()
        );
    }
    for input in &prepared.buckets {
        let row = client.query_one("SELECT total,dropped_oversize FROM fp_v2.buckets WHERE authorized=FALSE AND scope=$1", &[&&input.scope.id.0[..]]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
        assert_eq!(
            row.get::<_, i64>(1),
            if input.value.bytes.len() > limits.ingestion.bucket.value_bytes {
                2
            } else {
                0
            }
        );
    }
    let before = state(&client).await.unwrap();
    let mut invalid = limits;
    invalid.ingestion.bucket.input_bytes = invalid.capture.bytes - 1;
    ingest(
        &mut client,
        100,
        attempt(false, 3),
        &capture,
        [3; 32],
        invalid,
    )
    .await
    .unwrap_err();
    assert_eq!(before, state(&client).await.unwrap());
}
