use super::super::migrations;
use super::*;
use rama::{
    http::{HeaderMap, HeaderName, HeaderValue, Method, Version},
    quic::proto::{Version as QuicVersion, version::VersionInformation},
    ua::profile::{
        CanonicalDomain, CaptureLevel, CapturedSlot, CapturedSlotKind, ConnectionContext, FlowKey,
        H2Capture, H2CaptureLimits, H2CapturedFrame, H2CapturedSetting, HeaderCapture,
        HeaderCapturePolicy, JointCapture, ObservationWeight, OrderCaptureLimits, OrderNamespace,
        OrderedProtocolCapture, ProfileAnalysisLimits, ProfileCaptureCompleteness, ProfileKey,
        ProtocolValue, RequestInitiator, TlsCapture, TlsCaptureLimits, TlsCaptureTransport,
        TlsCapturedExtension, TlsCapturedExtensionValue, UntrackedDistinctSnapshot,
        analyze_profile_evidence,
    },
    utils::octets::{kib, mib},
};
use std::{
    error::Error,
    io::{Write as _, stdout},
    time::Instant,
};
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
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: policy
                    .capture(
                        ProfileCaptureCompleteness::Complete,
                        Version::HTTP_3,
                        &headers,
                        None,
                    )?
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
    let error = ingest(
        &mut client,
        127,
        attempt(false, 1),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    let IngestFailure::Rejected(error) = error else {
        panic!("expired attempt reached COMMIT")
    };
    assert!(matches!(
        error.downcast_ref::<ProfileDataError>(),
        Some(ProfileDataError::Expired)
    ));
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
    limits.retained[..6].copy_from_slice(&[1, 0, 2, 2, 1, 2]);
    let mut last = None;
    for sequence in 1_u64..=10_000 {
        let grease = 0x0a0a0a0a | (((sequence as u32) & 0xf) << 28);
        let mut versions = vec![QuicVersion::V1, QuicVersion::V2];
        // Reserved placement varies; the known-version preference stays fixed.
        versions.insert(sequence as usize % 3, QuicVersion::from_u32(grease));
        let mut information = Vec::new();
        VersionInformation::new(QuicVersion::V1, versions).write(&mut information);
        // The first sample reserves enough bytes for every later 0..16-byte value.
        let random = vec![sequence as u8; 16 - (sequence as usize - 1) % 17];
        let mut fields = vec![
            (31 * sequence + 27, random.as_slice()),
            (0x11, information.as_slice()),
        ];
        fields.rotate_left(sequence as usize % 2);
        let value = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            fields,
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
                completeness: ProfileCaptureCompleteness::Complete,
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
    let row = client.query_one("SELECT profiles,flows,structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
    for (index, expected) in [1_i64, 0, 2, 2, 1, 2].into_iter().enumerate() {
        assert_eq!(row.get::<_, i64>(index), expected);
    }
    assert!(usize::try_from(row.get::<_, i64>(6)).unwrap() <= limits.retained[6]);
    let last = last.unwrap();
    let mut changed = last.clone();
    let mut parameters = OrderedProtocolCapture::from_canonical(
        &changed.joint.slots[0].value,
        OrderCaptureLimits::default(),
    )
    .unwrap();
    let mut information = Vec::new();
    VersionInformation::new(QuicVersion::V1, vec![QuicVersion::V2, QuicVersion::V1])
        .write(&mut information);
    parameters
        .fields
        .iter_mut()
        .find(|field| field.id == 0x11)
        .unwrap()
        .value = ProtocolValue::Literal(information.into());
    changed.joint.slots[0].value = parameters.canonical(OrderCaptureLimits::default()).unwrap();
    let prepared = last.prepare(false, limits.capture).unwrap();
    assert_ne!(
        prepared.buckets[0].structure.id,
        changed.prepare(false, limits.capture).unwrap().buckets[0]
            .structure
            .id
    );
    let before = state(&client).await.unwrap();
    let failure = ingest(
        &mut client,
        100,
        attempt(false, 10_001),
        &changed,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert!(matches!(failure, IngestFailure::Rejected(_)));
    assert_eq!(state(&client).await.unwrap(), before);
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
            input
                .value
                .validated_domain(limits.ingestion.bucket.input_bytes)
                .unwrap(),
            input.scope.id,
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
    let retained_bytes = usize::try_from(row.get::<_, i64>(4)).unwrap();
    assert!(retained_bytes <= limits.retained[6]);
    let stored_bytes: i64 = client.query_one("SELECT COALESCE(sum(octet_length(canonical)),0)::bigint FROM (SELECT canonical FROM fp_v2.profiles WHERE authorized=FALSE UNION ALL SELECT canonical FROM fp_v2.flows WHERE authorized=FALSE UNION ALL SELECT canonical FROM fp_v2.structures WHERE authorized=FALSE UNION ALL SELECT canonical FROM fp_v2.values WHERE authorized=FALSE UNION ALL SELECT scope_canonical FROM fp_v2.buckets WHERE authorized=FALSE) AS stored", &[]).await.unwrap().get(0);
    assert_eq!(retained_bytes, usize::try_from(stored_bytes).unwrap());
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
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::QuicParameters,
                value: OrderedProtocolCapture::capture(
                    ProfileCaptureCompleteness::Complete,
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
                input
                    .value
                    .validated_domain(limits.ingestion.bucket.input_bytes)
                    .unwrap(),
                input.scope.id,
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
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![
                CapturedSlot {
                    kind: CapturedSlotKind::QuicParameters,
                    value: OrderedProtocolCapture::capture(
                        ProfileCaptureCompleteness::Complete,
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
                        ProfileCaptureCompleteness::Complete,
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

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_header_permutations_share_rows_at_full_quota() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut limits = limits();
    limits.ingestion.bucket.literal_values = 0;
    limits.ingestion.bucket.samples = 1;
    limits.retained[..6].copy_from_slice(&[1, 1, 2, 2, 1, 2]);
    let policy = HeaderCapturePolicy::default();
    let mut state = 1_u64;
    let mut last = None;
    let mut identities = BTreeSet::new();
    for sequence in 1..=10_000 {
        let mut order: Vec<_> = (0..12).collect();
        for index in (1..order.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            order.swap(index, (state % (index as u64 + 1)) as usize);
        }
        let mut headers = HeaderMap::new();
        for index in order {
            headers.insert(
                HeaderName::from_bytes(format!("x-mode-{index:02}").as_bytes()).unwrap(),
                HeaderValue::from_static("constant"),
            );
        }
        let raw = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_3,
                &headers,
                None,
            )
            .unwrap()
            .canonical(&policy)
            .unwrap();
        identities.insert(raw.id);
        let mut captured = capture("unused").unwrap();
        captured.joint.slots[0].value = raw;
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, sequence),
                &captured,
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
        last = Some(captured);
    }
    assert!(identities.len() > 9_000);
    let row = client.query_one("SELECT profiles,flows,structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
    for (index, expected) in [
        1_i64,
        1,
        2,
        2,
        1,
        2,
        i64::try_from(limits.retained[6]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(row.get::<_, i64>(index), expected);
    }
    let captured = last.unwrap();
    assert!(
        !ingest(
            &mut client,
            100,
            attempt(false, 10_000),
            &captured,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    let prepared = captured.prepare(false, limits.capture).unwrap();
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
        assert_eq!(restored.bucket.counts.total, 10_000);
        assert_eq!(restored.bucket.counts.untracked, 10_000);
        assert_eq!(restored.bucket.samples.len(), 1);
        assert_eq!(restored.bucket.values.len(), 1);
        let raw = &restored.bucket.values[0];
        if input.value.validated_domain(limits.capture.bytes).unwrap() == CanonicalDomain::Headers {
            let decoded = HeaderCapture::from_canonical(raw, &policy).unwrap();
            assert_eq!(decoded.fields.len(), 12);
            assert!(identities.contains(&raw.id));
        } else {
            JointCapture::from_canonical(raw, limits.capture).unwrap();
        }
    }
    transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_distinct_evidence_survives_restart_and_bounds_corrupt_rows() {
    let (config, _fixture_guard) = migrations::tests::isolated_database().await.unwrap();
    let (mut client, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut limits = limits();
    limits.ingestion.bucket.literal_values = 0;
    let capture = capture("fixed").unwrap();
    for sequence in 1..=3 {
        ingest(
            &mut client,
            100,
            attempt(false, sequence),
            &capture,
            [3; 32],
            limits,
        )
        .await
        .unwrap();
    }
    drop(client);
    let (mut client, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    let rows = client
        .query("SELECT untracked_distinct::text FROM fp_v2.buckets", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let evidence: UntrackedDistinctSnapshot =
            serde_json::from_str(&row.get::<_, String>(0)).unwrap();
        assert_eq!(evidence.values.len(), 1);
        assert!(evidence.history_known);
        assert!(!evidence.saturated);
    }
    let snapshot = state(&client).await.unwrap();
    assert!(
        !ingest(
            &mut client,
            100,
            attempt(false, 3),
            &capture,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    assert_eq!(state(&client).await.unwrap(), snapshot);
    client.execute("UPDATE fp_v2.buckets SET untracked_distinct=jsonb_build_object('values',jsonb_build_array(),'saturated',FALSE,'history_known',TRUE)", &[]).await.unwrap();
    let before = state(&client).await.unwrap();
    ingest(
        &mut client,
        100,
        attempt(false, 4),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
    client.execute("UPDATE fp_v2.buckets SET untracked_distinct=jsonb_build_object('values',jsonb_build_array(),'saturated',FALSE,'history_known',FALSE,'padding',repeat('x',$1))", &[&i32::try_from(kib(8) + 1).unwrap()]).await.unwrap();
    let IngestFailure::Rejected(error) = ingest(
        &mut client,
        100,
        attempt(false, 4),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap_err() else {
        panic!("corrupt evidence reached COMMIT")
    };
    assert!(matches!(
        error.downcast_ref::<ProfileDataError>(),
        Some(ProfileDataError::LimitExceeded("stored distinct bytes"))
    ));
    client.execute("UPDATE fp_v2.buckets SET untracked_distinct=jsonb_build_object('values',jsonb_build_array(),'saturated',FALSE,'history_known',FALSE)", &[]).await.unwrap();
    ingest(
        &mut client,
        100,
        attempt(false, 4),
        &capture,
        [3; 32],
        limits,
    )
    .await
    .unwrap();
    for row in client
        .query(
            "SELECT untracked_distinct::text,total FROM fp_v2.buckets",
            &[],
        )
        .await
        .unwrap()
    {
        let evidence: UntrackedDistinctSnapshot =
            serde_json::from_str(&row.get::<_, String>(0)).unwrap();
        assert_eq!(evidence.values.len(), 1);
        assert!(!evidence.history_known);
        assert_eq!(row.get::<_, i64>(1), 4);
    }
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_scope_access_class_must_match_the_row_partition() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    for authorized in [false, true] {
        let prepared = capture("text/plain")
            .unwrap()
            .prepare(authorized, limits().capture)
            .unwrap();
        let transaction = client.transaction().await.unwrap();
        let mut remaining = limits().ingestion.input_bytes;
        let error = load_bucket(
            &transaction,
            !authorized,
            100,
            &prepared.buckets[0],
            [3; 32],
            limits(),
            &mut remaining,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProfileDataError>(),
            Some(ProfileDataError::Invalid("stored scope access class"))
        ));
        transaction.rollback().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_tls_permutations_share_rows_at_full_quota() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut limits = limits();
    limits.ingestion.bucket.literal_values = 0;
    limits.ingestion.bucket.samples = 1;
    limits.retained[..6].copy_from_slice(&[1, 0, 2, 2, 1, 2]);
    let tls_limits = TlsCaptureLimits::default();
    let mut state = 1_u64;
    let mut last = None;
    let mut identities = BTreeSet::new();
    for sequence in 1..=10_000 {
        let mut order: Vec<_> = (0..12).collect();
        for index in (1..order.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            order.swap(index, (state % (index as u64 + 1)) as usize);
        }
        let mut extensions: Vec<_> = order
            .into_iter()
            .map(|index| TlsCapturedExtension {
                id: 100 + index,
                value: TlsCapturedExtensionValue::Literal(Box::new([1, 2, 3])),
            })
            .collect();
        extensions.push(TlsCapturedExtension {
            id: 0x0a0a + 0x1010 * (sequence % 16) as u16,
            value: TlsCapturedExtensionValue::Literal(Box::new([
                sequence as u8,
                (sequence >> 8) as u8,
            ])),
        });
        extensions.extend([
            TlsCapturedExtension {
                id: 0,
                value: TlsCapturedExtensionValue::ServerName { present: true },
            },
            TlsCapturedExtension {
                id: 21,
                value: TlsCapturedExtensionValue::ConnectionLength(0),
            },
            TlsCapturedExtension {
                id: 35,
                value: TlsCapturedExtensionValue::ConnectionLength((1 + sequence % 1000) as u16),
            },
            TlsCapturedExtension {
                id: 65037,
                value: TlsCapturedExtensionValue::EchOuter {
                    kdf: 1,
                    aead: 1,
                    enc: 32,
                    payload: (1 + sequence % 511) as u16,
                },
            },
            TlsCapturedExtension {
                id: 41,
                value: TlsCapturedExtensionValue::PreSharedKeys {
                    identities: Box::new([(1 + sequence % 1000) as u16]),
                    binders: Box::new([32]),
                },
            },
        ]);
        let raw = TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport: TlsCaptureTransport::Quic,
            protocol_version: 0x0303,
            ciphers: Box::new([0x1301]),
            compression: Box::new([0]),
            extensions: extensions.into(),
        }
        .canonical(tls_limits)
        .unwrap();
        identities.insert(raw.id);
        let mut captured = capture("unused").unwrap();
        captured.flow = None;
        captured.joint.level = CaptureLevel::Connection;
        captured.joint.slots = Box::new([CapturedSlot {
            kind: CapturedSlotKind::QuicTls,
            value: raw,
        }]);
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, sequence),
                &captured,
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
        last = Some(captured);
    }
    assert!(identities.len() > 9_000);
    let row = client.query_one("SELECT profiles,flows,structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
    for (index, expected) in [
        1_i64,
        0,
        2,
        2,
        1,
        2,
        i64::try_from(limits.retained[6]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(row.get::<_, i64>(index), expected);
    }
    let captured = last.unwrap();
    assert!(
        !ingest(
            &mut client,
            100,
            attempt(false, 10_000),
            &captured,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    let prepared = captured.prepare(false, limits.capture).unwrap();
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
        assert_eq!(restored.bucket.counts.total, 10_000);
        assert_eq!(restored.bucket.counts.untracked, 10_000);
        assert_eq!(restored.bucket.samples.len(), 1);
        assert_eq!(restored.bucket.values.len(), 1);
        let raw = &restored.bucket.values[0];
        if input.value.validated_domain(limits.capture.bytes).unwrap() == CanonicalDomain::Tls {
            let decoded = TlsCapture::from_canonical(raw, tls_limits).unwrap();
            assert_eq!(decoded.extensions.len(), 18);
            assert!(identities.contains(&raw.id));
        } else {
            JointCapture::from_canonical(raw, limits.capture).unwrap();
        }
    }
    transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_h2_permutations_share_rows_at_full_quota() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut limits = limits();
    limits.ingestion.bucket.literal_values = 0;
    limits.ingestion.bucket.samples = 1;
    limits.retained[..6].copy_from_slice(&[1, 0, 2, 2, 1, 2]);
    let h2_limits = H2CaptureLimits::default();
    let mut state = 1_u64;
    let mut last = None;
    let mut identities = BTreeSet::new();
    for sequence in 1..=10_000 {
        let mut order: Vec<_> = (0..12).collect();
        for index in (1..order.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            order.swap(index, (state % (index as u64 + 1)) as usize);
        }
        let entries: Vec<_> = order
            .into_iter()
            .map(|index| H2CapturedSetting {
                id: 100 + index,
                value: 32,
            })
            .chain([
                H2CapturedSetting { id: 1, value: 1024 },
                H2CapturedSetting { id: 1, value: 4096 },
            ])
            .collect();
        let raw = H2Capture {
            completeness: ProfileCaptureCompleteness::Complete,
            frames: Box::new([
                H2CapturedFrame::Settings {
                    ack: false,
                    entries: entries.into(),
                },
                H2CapturedFrame::WindowUpdate {
                    stream: 0,
                    increment: 65_535,
                },
            ]),
        }
        .canonical(h2_limits)
        .unwrap();
        identities.insert(raw.id);
        let mut captured = capture("unused").unwrap();
        captured.flow = None;
        captured.joint.level = CaptureLevel::Connection;
        captured.joint.slots = Box::new([CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value: raw,
        }]);
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, sequence),
                &captured,
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
        last = Some(captured);
    }
    assert!(identities.len() > 9_000);
    let row = client.query_one("SELECT profiles,flows,structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
    for (index, expected) in [
        1_i64,
        0,
        2,
        2,
        1,
        2,
        i64::try_from(limits.retained[6]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(row.get::<_, i64>(index), expected);
    }
    let captured = last.unwrap();
    assert!(
        !ingest(
            &mut client,
            100,
            attempt(false, 10_000),
            &captured,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    let prepared = captured.prepare(false, limits.capture).unwrap();
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
        assert_eq!(restored.bucket.counts.total, 10_000);
        assert_eq!(restored.bucket.counts.untracked, 10_000);
        assert_eq!(restored.bucket.samples.len(), 1);
        assert_eq!(restored.bucket.values.len(), 1);
        let raw = &restored.bucket.values[0];
        if input.value.validated_domain(limits.capture.bytes).unwrap() == CanonicalDomain::H2 {
            let decoded = H2Capture::from_canonical(raw, h2_limits).unwrap();
            assert_eq!(decoded.frames.len(), 2);
            let H2CapturedFrame::Settings { entries, .. } = &decoded.frames[0] else {
                panic!("first frame must retain SETTINGS");
            };
            let repeated: Vec<_> = entries
                .iter()
                .filter(|entry| entry.id == 1)
                .map(|entry| entry.value)
                .collect();
            assert_eq!(repeated, [1024, 4096]);
            assert!(identities.contains(&raw.id));
        } else {
            JointCapture::from_canonical(raw, limits.capture).unwrap();
        }
    }
    transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn fp_counted_h3_settings_permutations_share_rows_at_full_quota() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let mut limits = limits();
    limits.ingestion.bucket.literal_values = 0;
    limits.ingestion.bucket.samples = 1;
    limits.retained[..6].copy_from_slice(&[1, 0, 2, 2, 1, 2]);
    let order_limits = OrderCaptureLimits::default();
    let mut state = 1_u64;
    let mut last = None;
    let mut identities = BTreeSet::new();
    for sequence in 1_u64..=10_000 {
        let mut order: Vec<_> = (0..12).collect();
        for index in (1..order.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            order.swap(index, (state % (index as u64 + 1)) as usize);
        }
        let entries: Vec<_> = order
            .into_iter()
            .map(|index| (100 + index, 32u64.to_be_bytes()))
            .chain([
                (1, 4096u64.to_be_bytes()),
                (0x21 + 31 * sequence, sequence.to_be_bytes()),
            ])
            .collect();
        let raw = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            entries,
            order_limits,
        )
        .unwrap()
        .canonical(order_limits)
        .unwrap();
        identities.insert(raw.id);
        let mut captured = capture("unused").unwrap();
        captured.flow = None;
        captured.joint.level = CaptureLevel::Connection;
        captured.joint.slots = Box::new([CapturedSlot {
            kind: CapturedSlotKind::Http3Settings,
            value: raw,
        }]);
        assert!(
            ingest(
                &mut client,
                100,
                attempt(false, sequence),
                &captured,
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
        last = Some(captured);
    }
    assert!(identities.len() > 9_000);
    let row = client.query_one("SELECT profiles,flows,structures,buckets,runs,interned_values,canonical_bytes FROM fp_v2.quotas WHERE authorized=FALSE", &[]).await.unwrap();
    for (index, expected) in [
        1_i64,
        0,
        2,
        2,
        1,
        2,
        i64::try_from(limits.retained[6]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(row.get::<_, i64>(index), expected);
    }
    let captured = last.unwrap();
    assert!(
        !ingest(
            &mut client,
            100,
            attempt(false, 10_000),
            &captured,
            [3; 32],
            limits
        )
        .await
        .unwrap()
    );
    let prepared = captured.prepare(false, limits.capture).unwrap();
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
        assert_eq!(restored.bucket.counts.total, 10_000);
        assert_eq!(restored.bucket.counts.untracked, 10_000);
        assert_eq!(restored.bucket.samples.len(), 1);
        assert_eq!(restored.bucket.values.len(), 1);
        let raw = &restored.bucket.values[0];
        if input.value.validated_domain(limits.capture.bytes).unwrap() == CanonicalDomain::Order {
            let decoded = OrderedProtocolCapture::from_canonical(raw, order_limits).unwrap();
            assert!(matches!(decoded.namespace, OrderNamespace::Http3Setting));
            assert_eq!(decoded.fields.len(), 14);
            assert_eq!(
                decoded.fields.iter().filter(|field| field.id == 1).count(),
                1
            );
            assert_eq!(
                decoded
                    .fields
                    .iter()
                    .filter(|field| field.id >= 0x21 && (field.id - 0x21).is_multiple_of(31))
                    .count(),
                1
            );
            assert!(identities.contains(&raw.id));
        } else {
            JointCapture::from_canonical(raw, limits.capture).unwrap();
        }
    }
    transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn counted_export_reanalyzes_fresh_partitioned_profiles_without_writes() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let stored = capture("text/html").unwrap();
    let limits = limits();
    for sequence in 1..=3 {
        ingest(
            &mut client,
            100,
            attempt(false, sequence),
            &stored,
            [3; 32],
            limits,
        )
        .await
        .unwrap();
    }
    ingest(&mut client, 100, attempt(true, 1), &stored, [4; 32], limits)
        .await
        .unwrap();
    let before = state(&client).await.unwrap();
    let analysis_limits = ProfileAnalysisLimits::default();
    let (public, seed) = next_profile(&mut client, false, None, 100, 14, analysis_limits, limits)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seed, [3; 32]);
    let analyzed =
        analyze_profile_evidence(&public, false, seed, 100, 14, analysis_limits).unwrap();
    assert!(analyzed.components.h3.is_some());
    assert!(analyzed.components.h1.is_none());
    assert!(analyzed.components.tls_tcp.is_none());
    assert_eq!(analyzed.scopes.len(), 2);
    assert!(
        analyzed
            .scopes
            .iter()
            .all(|scope| scope.observations.counts.total == 3)
    );
    assert!(
        !serde_json::to_string(&analyzed)
            .unwrap()
            .contains("excluded-credential")
    );
    assert!(
        next_profile(
            &mut client,
            false,
            Some(public.profile.id),
            100,
            14,
            analysis_limits,
            limits
        )
        .await
        .unwrap()
        .is_none()
    );
    let (private, seed) = next_profile(&mut client, true, None, 100, 14, analysis_limits, limits)
        .await
        .unwrap()
        .unwrap();
    let analyzed =
        analyze_profile_evidence(&private, true, seed, 100, 14, analysis_limits).unwrap();
    assert_eq!(seed, [4; 32]);
    assert!(
        analyzed
            .scopes
            .iter()
            .all(|scope| scope.observations.counts.total == 1)
    );
    analyze_profile_evidence(&private, false, seed, 100, 14, analysis_limits).unwrap_err();
    assert!(
        next_profile(&mut client, false, None, 101, 1, analysis_limits, limits)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        next_profile(&mut client, false, None, 114, 14, analysis_limits, limits)
            .await
            .unwrap()
            .is_none()
    );
    next_profile(
        &mut client,
        false,
        None,
        100,
        14,
        ProfileAnalysisLimits {
            scopes: 1,
            ..analysis_limits
        },
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(state(&client).await.unwrap(), before);
}

#[tokio::test]
#[ignore = "measures the private PostgreSQL fixture; run without competing builds"]
async fn measure_counted_profile_day_storage_and_fourteen_day_merge() {
    let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
    client
        .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    let store_limits = super::super::startup::store_limits();
    let seed = [37; 32];
    let policy = HeaderCapturePolicy::default();
    let versions = [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];
    for day in 100..114 {
        for (protocol, version) in versions.into_iter().enumerate() {
            for sample in 0..64 {
                let mut headers = HeaderMap::new();
                // Deterministic cyclic/reversed order and four observed values.
                // This is a stated synthetic header workload, not browser traffic.
                for position in 0..8 {
                    let position = if sample & 8 == 0 {
                        position
                    } else {
                        7 - position
                    };
                    let index = (position + sample) % 8;
                    headers.insert(
                        HeaderName::from_bytes(format!("x-profile-field-{index}").as_bytes())
                            .unwrap(),
                        HeaderValue::from_str(&format!("value-{}", sample / 16)).unwrap(),
                    );
                }
                let captured = ProfileCapture {
                    profile: ProfileKey::new(format!("storage-size-{protocol}")),
                    flow: Some(FlowKey::Http {
                        version,
                        method: Method::GET,
                        initiator: Some(RequestInitiator::Navigate),
                        fetch: None,
                        connection: ConnectionContext::default(),
                    }),
                    connection: ConnectionContext::default(),
                    joint: JointCapture {
                        completeness: ProfileCaptureCompleteness::Complete,
                        level: CaptureLevel::Request,
                        slots: Box::new([CapturedSlot {
                            kind: CapturedSlotKind::Headers,
                            value: policy
                                .capture(
                                    ProfileCaptureCompleteness::Complete,
                                    version,
                                    &headers,
                                    None,
                                )
                                .unwrap()
                                .canonical(&policy)
                                .unwrap(),
                        }]),
                    },
                };
                let attempt = IngestionAttempt {
                    authorized: false,
                    observation_day: day,
                    observation: ObservationId {
                        run: CaptureRunId::new(100, [protocol as u8 + 1; 12]).0,
                        sequence: u64::from((day - 100) * 64 + sample + 1),
                    },
                };
                ingest(&mut client, day, attempt, &captured, seed, store_limits)
                    .await
                    .unwrap();
            }
        }
    }
    let mut storage = serde_json::Map::new();
    for table in [
        "profiles",
        "flows",
        "structures",
        "values",
        "buckets",
        "literal_counts",
        "samples",
        "runs",
        "quotas",
    ] {
        client
            .batch_execute(&format!("VACUUM (ANALYZE) fp_v2.{table}"))
            .await
            .unwrap();
        let row = client.query_one(&format!("SELECT count(*)::bigint, COALESCE(sum(pg_column_size(t)),0)::bigint, pg_total_relation_size('fp_v2.{table}') FROM fp_v2.{table} t"), &[]).await.unwrap();
        storage.insert(table.into(), serde_json::json!({"rows":row.get::<_,i64>(0),"tuple_bytes":row.get::<_,i64>(1),"relation_and_index_bytes":row.get::<_,i64>(2)}));
    }
    let mut per_day = serde_json::Map::new();
    for table in ["buckets", "literal_counts", "samples"] {
        let row = client.query_one(&format!("SELECT count(*)::bigint, COALESCE(sum(pg_column_size(t)),0)::bigint FROM fp_v2.{table} t WHERE day=113"), &[]).await.unwrap();
        per_day.insert(table.into(), serde_json::json!({"rows_three_profiles":row.get::<_,i64>(0),"tuple_bytes_three_profiles":row.get::<_,i64>(1)}));
    }
    let mut measurements = Vec::new();
    for _ in 0..7 {
        let started = Instant::now();
        let mut after = None;
        let mut profiles = 0;
        while let Some((evidence, seed)) = next_profile(
            &mut client,
            false,
            after,
            113,
            14,
            ProfileAnalysisLimits::default(),
            store_limits,
        )
        .await
        .unwrap()
        {
            after = Some(evidence.profile.id);
            let analysis = analyze_profile_evidence(
                &evidence,
                false,
                seed,
                113,
                14,
                ProfileAnalysisLimits::default(),
            )
            .unwrap();
            // Four literal value sets each retain a header and a request-joint
            // structure. Each sees sixteen orders per day; order does not split it.
            assert_eq!(analysis.scopes.len(), 8);
            for domain in [CanonicalDomain::Headers, CanonicalDomain::Joint] {
                let scopes: Vec<_> = analysis
                    .scopes
                    .iter()
                    .filter(|scope| scope.observations.domain == domain)
                    .collect();
                assert_eq!(scopes.len(), 4);
                assert!(
                    scopes
                        .iter()
                        .all(|scope| scope.observations.counts.total == 14 * 16)
                );
                assert_eq!(
                    scopes
                        .iter()
                        .map(|scope| scope.observations.counts.total)
                        .sum::<u64>(),
                    14 * 64
                );
            }
            profiles += 1;
        }
        assert_eq!(profiles, 3);
        measurements.push(started.elapsed().as_micros());
    }
    let postgres: String = client
        .query_one("SELECT version()", &[])
        .await
        .unwrap()
        .get(0);
    writeln!(
        stdout().lock(),
        "PR10_STORAGE_SIZING {}",
        serde_json::json!({
            "fixture":"three protocol profiles; one GET/navigation flow each; four literal value sets times sixteen eight-field header orders per UTC day; 14 days; four header and four request-joint scopes per profile",
            "profiles":3,"days":14,"observations_per_profile_day":64,"postgres":postgres,
            "tables":storage,"last_day":per_day,"three_profile_fourteen_day_read_and_analysis_microseconds":measurements,
            "timing_assertions":false
        })
    ).unwrap();
}
