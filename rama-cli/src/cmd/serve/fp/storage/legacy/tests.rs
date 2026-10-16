use super::super::migrations::tests::{connect, isolated_database};
use super::super::{CountedProfileSource, export::export_counted_profiles};
use super::*;
use crate::cmd::ua::ExportProfilesCommand;
use rama::{
    graceful::Shutdown,
    http::{HeaderMap, HeaderValue},
    rt::Executor,
    ua::profile::{
        analysis::profile::{ProfileAnalysisLimits, analyze_profile_evidence},
        evidence::counts::ObservationWeight,
        format::{
            archive::{ProfileArchiveLimits, load_profile_archive_snapshot},
            canonical::CanonicalDomain,
        },
        model::{
            http::{Http1Settings, Http2Settings},
            ua::UserAgentProfile,
        },
        selection::database::UserAgentDatabase,
    },
    utils::fs::TempDir,
};
use std::{
    fs,
    io::{Write as _, stdout},
    time::Duration,
};
use tokio::{sync::oneshot, time::timeout};
use tokio_postgres::Config;

async fn setup() -> Client {
    let (_config, mut client) = isolated_database().await.unwrap();
    client.batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE; DROP TABLE IF EXISTS public.\"ua-profiles\", public.\"public-ua-profiles\"").await.unwrap();
    client
        .batch_execute(include_str!(
            "../migrations/20250915152637_create_ua_profiles.sql"
        ))
        .await
        .unwrap();
    migrations::apply(&mut client).await.unwrap();
    client
}

fn profile(name: &str) -> UserAgentProfileInput {
    let mut row = UserAgentProfileInput::new(name);
    row.h1_settings = Some(Http1Settings {
        title_case_headers: true,
    });
    row.h2_settings = Some(Http2Settings {
        http_pseudo_headers: None,
        early_frames: None,
    });
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("text/html"));
    headers.insert("cookie", HeaderValue::from_static("legacy-secret-canary"));
    row.h1_headers_navigate = Some(headers.clone());
    row.h2_headers_navigate = Some(headers);
    row
}

async fn insert(client: &Client, authorized: bool, day: u32, row: &UserAgentProfileInput) {
    let table = if authorized {
        "ua-profiles"
    } else {
        "public-ua-profiles"
    };
    let settings1 = serde_json::to_string(&row.h1_settings).unwrap();
    let settings2 = serde_json::to_string(&row.h2_settings).unwrap();
    let headers1 = serde_json::to_string(&row.h1_headers_navigate).unwrap();
    let headers2 = serde_json::to_string(&row.h2_headers_navigate).unwrap();
    client.execute(&format!("INSERT INTO public.\"{table}\" (uastr,updated_at,h1_settings,h2_settings,h1_headers_navigate,h2_headers_navigate) VALUES ($1,to_timestamp($2::bigint * 86400),$3::text::json,$4::text::json,$5::text::json,$6::text::json)"), &[&row.uastr.as_str(), &i64::from(day), &settings1, &settings2, &headers1, &headers2]).await.unwrap();
}

async fn legacy_snapshot(client: &Client) -> Vec<String> {
    let mut rows = Vec::new();
    for table in ["ua-profiles", "public-ua-profiles"] {
        rows.push(client.query_one(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY uastr),'[]')::text FROM public.\"{table}\" p"), &[]).await.unwrap().get(0));
    }
    rows
}

async fn stored_totals(client: &Client) -> (i64, i64, i64, i64) {
    let row = client.query_one("SELECT (SELECT count(*) FROM fp_v2.buckets), (SELECT COALESCE(sum(total),0)::bigint FROM fp_v2.buckets), (SELECT count(*) FROM fp_v2.runs), (SELECT count(*) FROM fp_v2.legacy_imports)", &[]).await.unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_backfill_is_additive_idempotent_revisioned_and_expires_with_evidence() {
    let mut client = setup().await;
    let limits = startup::store_limits();
    let row = profile("legacy-client/1");
    insert(&client, false, 100, &row).await;
    insert(&client, true, 100, &row).await;
    insert(&client, false, 80, &profile("expired-client/1")).await;
    let original = legacy_snapshot(&client).await;
    for authorized in [false, true] {
        let report = backfill(&mut client, authorized, 100, [7; 32], limits)
            .await
            .unwrap();
        assert_eq!((report.read, report.imported), (1, 1));
    }
    assert_eq!(legacy_snapshot(&client).await, original);
    assert_eq!(stored_totals(&client).await, (8, 8, 2, 2));
    client.execute("UPDATE public.\"public-ua-profiles\" SET h2_settings='{\"early_frames\":null,\"http_pseudo_headers\":null}' WHERE uastr=$1", &[&row.uastr.as_str()]).await.unwrap();
    let report = backfill(&mut client, false, 101, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!((report.imported, report.already_imported_or_empty), (0, 1));
    assert_eq!(stored_totals(&client).await, (8, 8, 2, 2));
    client.execute("UPDATE public.\"public-ua-profiles\" SET h1_settings='{\"title_case_headers\":false}', updated_at=to_timestamp(101 * 86400) WHERE uastr=$1", &[&row.uastr.as_str()]).await.unwrap();
    assert_eq!(
        backfill(&mut client, false, 101, [7; 32], limits)
            .await
            .unwrap()
            .imported,
        1
    );
    assert_eq!(stored_totals(&client).await, (12, 12, 3, 3));
    let (evidence, seed) = counted::next_profile(
        &mut client,
        false,
        None,
        101,
        14,
        ProfileAnalysisLimits::default(),
        limits,
    )
    .await
    .unwrap()
    .unwrap();
    let analysis = analyze_profile_evidence(
        &evidence,
        false,
        seed,
        101,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert_eq!(analysis.scopes.len(), 4);
    assert!(analysis.scopes.iter().all(|scope| scope.observations.domain
        == CanonicalDomain::LegacyField
        && scope.observations.counts.total == 2
        && !scope.observations.counts.losses.history_known
        && scope.flow.is_none()));
    let profile = UserAgentProfile::from_captured(analysis);
    assert!(matches!(
        profile.observation_weight().unwrap(),
        ObservationWeight::UnknownHistory {
            observed: 2,
            unassigned: 0
        }
    ));
    let leaked: bool = client.query_one("SELECT EXISTS (SELECT 1 FROM fp_v2.values WHERE position(convert_to('legacy-secret-canary','UTF8') in canonical)>0)", &[]).await.unwrap().get(0);
    assert!(!leaked);
    while counted::prune(&mut client, false, 114, limits, 32)
        .await
        .unwrap()
    {}
    assert_eq!(
        backfill(&mut client, false, 114, [7; 32], limits)
            .await
            .unwrap()
            .imported,
        0
    );
    let checkpoint_count: i64 = client
        .query_one(
            "SELECT count(*) FROM fp_v2.legacy_imports WHERE NOT authorized",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(checkpoint_count, 1);
    let (evidence, seed) = counted::next_profile(
        &mut client,
        false,
        None,
        114,
        14,
        ProfileAnalysisLimits::default(),
        limits,
    )
    .await
    .unwrap()
    .unwrap();
    let analysis = analyze_profile_evidence(
        &evidence,
        false,
        seed,
        114,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert!(
        analysis
            .scopes
            .iter()
            .all(|scope| scope.observations.counts.total == 1)
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_row_rolls_back_all_fields_and_checkpoint_on_quota_failure() {
    let mut client = setup().await;
    let row = profile("legacy-client/1");
    insert(&client, false, 100, &row).await;
    let mut limits = startup::store_limits();
    limits.retained[3] = 1;
    backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap_err();
    assert_eq!(stored_totals(&client).await, (0, 0, 0, 0));
    let empty: bool = client.query_one("SELECT bool_and(profiles=0 AND flows=0 AND structures=0 AND buckets=0 AND runs=0 AND canonical_bytes=0 AND interned_values=0 AND sampler_seed IS NULL) FROM fp_v2.quotas", &[]).await.unwrap().get(0);
    assert!(empty);
    assert_eq!(
        backfill(&mut client, false, 100, [7; 32], startup::store_limits())
            .await
            .unwrap()
            .imported,
        1
    );
    assert_eq!(stored_totals(&client).await, (4, 4, 1, 1));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_concurrent_imports_commit_one_revision_and_reject_run_aliases() {
    let mut client = setup().await;
    let row = profile("legacy-client/1");
    insert(&client, false, 100, &row).await;
    let config = env::var("RAMA_FP_TEST_PG").unwrap().parse().unwrap();
    let mut second = connect(&config).await.unwrap();
    let limits = startup::store_limits();
    let (first, second) = tokio::join!(
        backfill(&mut client, false, 100, [7; 32], limits),
        backfill(&mut second, false, 100, [7; 32], limits)
    );
    assert_eq!(first.unwrap().imported + second.unwrap().imported, 1);
    assert_eq!(stored_totals(&client).await, (4, 4, 1, 1));
    let existing: Vec<u8> = client
        .query_one("SELECT id FROM fp_v2.runs WHERE NOT authorized", &[])
        .await
        .unwrap()
        .get(0);
    let other = profile("other-client/1");
    let revision = LegacyRevision {
        source_table: "public-ua-profiles",
        source_key: sha256(other.uastr.as_bytes()),
        row_digest: [8; 32],
        observation_day: 100,
        nonce: existing[4..].try_into().unwrap(),
    };
    counted::ingest_legacy(&mut client, 100, false, &other, &revision, [7; 32], limits)
        .await
        .unwrap_err();
    counted::ingest_legacy(&mut client, 100, true, &other, &revision, [7; 32], limits)
        .await
        .unwrap_err();
    assert_eq!(stored_totals(&client).await, (4, 4, 1, 1));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_reader_pages_and_rejects_oversize_and_future_rows() {
    let mut client = setup().await;
    let limits = startup::store_limits();
    for index in 0..33 {
        insert(&client, false, 100, &profile(&format!("client-{index:02}"))).await;
    }
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!((report.read, report.imported), (33, 33));
    let before = stored_totals(&client).await;
    insert(&client, false, 101, &profile("future-client")).await;
    client.execute("INSERT INTO public.\"public-ua-profiles\" (uastr,updated_at,source_info) VALUES ('oversize-client',to_timestamp(100 * 86400),json_build_object('device_name',repeat('x',$1)))", &[&i32::try_from(ROW_BYTES+1).unwrap()]).await.unwrap();
    insert(&client, false, 100, &profile(&"z".repeat(KEY_BYTES + 1))).await;
    client.execute("INSERT INTO public.\"public-ua-profiles\" (uastr,updated_at) VALUES ('infinite-client','infinity')", &[]).await.unwrap();
    client.execute("INSERT INTO public.\"public-ua-profiles\" (uastr,updated_at) VALUES ('extreme-future-client','294276-12-31 23:59:59+00')", &[]).await.unwrap();
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (
            report.rejected_invalid,
            report.rejected_oversize,
            report.rejected_fields
        ),
        (3, 2, 1)
    );
    assert_eq!(stored_totals(&client).await, before);
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(report.read, 33);
    assert_eq!((report.rejected_invalid, report.rejected_oversize), (0, 0));
    assert_eq!(stored_totals(&client).await, before);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn startup_serves_and_shuts_down_while_legacy_reads_are_blocked() {
    let client = setup().await;
    let day = startup::current_day().unwrap();
    insert(&client, false, day, &profile("blocked-legacy")).await;
    let url = env::var("RAMA_FP_TEST_PG").unwrap();
    let mut blocker = connect(&url.parse().unwrap()).await.unwrap();
    let held = blocker.transaction().await.unwrap();
    held.batch_execute("LOCK TABLE public.\"public-ua-profiles\" IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let pool = postgres::try_new_pool(url).await.unwrap();
    let (signal, cancelled) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        _ = cancelled.await;
    });
    let exec = Executor::graceful(shutdown.guard());
    let queue = timeout(Duration::from_secs(10), startup::start(pool, &exec))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queue.counts().confirmed, 0);
    signal.send(()).unwrap();
    drop(exec);
    shutdown
        .shutdown_with_limit(Duration::from_secs(10))
        .await
        .unwrap();
    held.rollback().await.unwrap();
    assert_eq!(stored_totals(&client).await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn rejected_legacy_partition_does_not_hide_the_other_partition() {
    let client = setup().await;
    let day = startup::current_day().unwrap();
    insert(&client, false, day, &profile("invalid-legacy")).await;
    client
        .execute(
            "UPDATE public.\"public-ua-profiles\" SET h1_settings='\"invalid\"'",
            &[],
        )
        .await
        .unwrap();
    insert(&client, true, day, &profile("authorized-legacy")).await;
    let pool = postgres::try_new_pool(env::var("RAMA_FP_TEST_PG").unwrap())
        .await
        .unwrap();
    backfill_partitions(pool, [[7; 32]; 2], startup::store_limits()).await;
    assert_eq!(stored_totals(&client).await, (7, 7, 2, 2));
    let public: i64 = client
        .query_one(
            "SELECT count(*) FROM fp_v2.buckets WHERE NOT authorized",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(public, 3);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_cli_export_and_view_source_share_the_counted_analysis() {
    let client = setup().await;
    let harness = env::var("RAMA_FP_TEST_PG")
        .unwrap()
        .parse::<Config>()
        .unwrap();
    assert!(env::var("RAMA_FP_DATABASE_URL").unwrap() == env::var("RAMA_FP_TEST_PG").unwrap());
    let command_database = env::var("RAMA_FP_DATABASE_URL")
        .unwrap()
        .parse::<Config>()
        .unwrap();
    assert!(command_database.get_hosts() == harness.get_hosts());
    assert_eq!(command_database.get_dbname(), Some("rama_fp_m3_test"));
    let day = startup::current_day().unwrap();
    insert(&client, false, day, &profile("cli-legacy/1")).await;
    let original = legacy_snapshot(&client).await;
    let directory = TempDir::new().unwrap();
    let output = directory.path().join("profiles.json");
    let limits = ProfileArchiveLimits::default();
    export_counted_profiles(ExportProfilesCommand {
        output: output.clone(),
        days: 14,
        authorized: false,
        import_legacy: true,
        replace: false,
        max_profiles: limits.profiles,
        max_output_bytes: limits.bytes,
    })
    .await
    .unwrap();
    let bytes = fs::read(&output).unwrap();
    let archive = load_profile_archive_snapshot(&bytes, false, limits).unwrap();
    assert_eq!(archive.len(), 1);
    let mut source = CountedProfileSource::open(false, 14, limits.profiles)
        .await
        .unwrap();
    let entry = source
        .next()
        .await
        .unwrap()
        .unwrap()
        .analyze(false, day, 14, limits.profile)
        .unwrap();
    assert!(source.next().await.unwrap().is_none());
    assert_eq!(
        serde_json::to_value(&entry).unwrap(),
        serde_json::to_value(&archive[0]).unwrap()
    );
    assert_eq!(
        UserAgentDatabase::try_from_json_slice(&bytes)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(legacy_snapshot(&client).await, original);
    assert_eq!(stored_totals(&client).await, (4, 4, 1, 1));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_rejection_checkpoint_preserves_neighbours_restart_and_changed_rows() {
    let mut client = setup().await;
    let limits = startup::store_limits();
    insert(&client, false, 100, &profile("a-valid")).await;
    insert(
        &client,
        false,
        100,
        &UserAgentProfileInput::new("b-invalid"),
    )
    .await;
    client.execute("UPDATE public.\"public-ua-profiles\" SET h1_settings='\"invalid\"' WHERE uastr='b-invalid'", &[]).await.unwrap();
    insert(&client, false, 100, &profile("c-valid")).await;
    let original = legacy_snapshot(&client).await;
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (report.read, report.imported, report.rejected_invalid),
        (3, 2, 1)
    );
    assert_eq!(report.rejected_fields, 1);
    assert_eq!(stored_totals(&client).await, (8, 8, 2, 2));
    let mut restarted = connect(&env::var("RAMA_FP_TEST_PG").unwrap().parse().unwrap())
        .await
        .unwrap();
    let report = backfill(&mut restarted, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (report.read, report.imported, report.rejected_invalid),
        (2, 0, 0)
    );
    assert_eq!(legacy_snapshot(&client).await, original);
    client.execute("UPDATE public.\"public-ua-profiles\" SET h1_settings='{\"title_case_headers\":true}' WHERE uastr='b-invalid'", &[]).await.unwrap();
    let report = backfill(&mut restarted, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (report.read, report.imported, report.rejected_invalid),
        (3, 1, 0)
    );
    assert_eq!(stored_totals(&client).await, (9, 9, 3, 3));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_partial_fields_survive_invalid_and_oversize_neighbours() {
    let mut client = setup().await;
    let limits = startup::store_limits();
    insert(&client, false, 100, &profile("partial")).await;
    client.execute("UPDATE public.\"public-ua-profiles\" SET h1_settings='\"invalid\"', js_web_apis='1e400', source_info=json_build_object('device_name',repeat('x',$1)), tls_ws_client_config_overwrites='{\"alpn\":null}'", &[&i32::try_from(ROW_BYTES+1).unwrap()]).await.unwrap();
    let original = legacy_snapshot(&client).await;
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (
            report.imported,
            report.rejected_oversize,
            report.rejected_fields
        ),
        (1, 1, 4)
    );
    assert_eq!(stored_totals(&client).await, (3, 3, 1, 1));
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!((report.read, report.imported), (0, 0));
    assert_eq!(stored_totals(&client).await, (3, 3, 1, 1));
    assert_eq!(legacy_snapshot(&client).await, original);
    client
        .execute(
            "UPDATE public.\"public-ua-profiles\" SET h1_settings='\"still invalid\"'",
            &[],
        )
        .await
        .unwrap();
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (report.read, report.imported, report.rejected_fields),
        (1, 0, 4)
    );
    let count: i64 = client
        .query_one("SELECT count(*) FROM fp_v2.legacy_rejections", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    assert_eq!(
        client
            .query_one(
                "SELECT legacy_rejections FROM fp_v2.quotas WHERE NOT authorized",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        count
    );
    assert_eq!(stored_totals(&client).await, (3, 3, 1, 1));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_rejection_quota_is_fail_closed_and_maintenance_is_bounded() {
    let mut client = setup().await;
    let mut limits = startup::store_limits();
    limits.retained[4] = 1;
    for key in ["a-invalid", "b-invalid"] {
        insert(&client, false, 100, &UserAgentProfileInput::new(key)).await;
    }
    client
        .execute(
            "UPDATE public.\"public-ua-profiles\" SET h1_settings='\"invalid\"'",
            &[],
        )
        .await
        .unwrap();
    insert(&client, false, 100, &profile("c-valid")).await;
    let error = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap_err();
    assert_eq!(error_category(error.as_ref()), "quota");
    assert_eq!(stored_totals(&client).await, (0, 0, 0, 0));
    let count: i64 = client
        .query_one("SELECT count(*) FROM fp_v2.legacy_rejections", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    assert_eq!(
        client
            .query_one(
                "SELECT legacy_rejections FROM fp_v2.quotas WHERE NOT authorized",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        count
    );
    limits.retained[4] = 2;
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (report.read, report.imported, report.rejected_invalid),
        (2, 1, 1)
    );
    counted::prune(&mut client, false, 114, limits, 1)
        .await
        .unwrap();
    let count: i64 = client
        .query_one("SELECT count(*) FROM fp_v2.legacy_rejections", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    assert_eq!(
        client
            .query_one(
                "SELECT legacy_rejections FROM fp_v2.quotas WHERE NOT authorized",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        count
    );
    while counted::prune(&mut client, false, 114, limits, 1)
        .await
        .unwrap()
    {}
    let count: i64 = client
        .query_one("SELECT count(*) FROM fp_v2.legacy_rejections", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    assert_eq!(
        client
            .query_one(
                "SELECT legacy_rejections FROM fp_v2.quotas WHERE NOT authorized",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        count
    );
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_oversize_keys_advance_across_an_entire_page() {
    let mut client = setup().await;
    for index in 0..PAGE_ROWS + 1 {
        insert(
            &client,
            false,
            100,
            &profile(&format!("a-{index:02}-{}", "x".repeat(KEY_BYTES))),
        )
        .await;
    }
    insert(&client, false, 100, &profile("z-valid")).await;
    let limits = startup::store_limits();
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (report.read, report.imported, report.rejected_oversize),
        (PAGE_ROWS + 2, 1, PAGE_ROWS + 1)
    );
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(
        (report.read, report.imported, report.rejected_oversize),
        (1, 0, 0)
    );
    assert_eq!(stored_totals(&client).await, (4, 4, 1, 1));
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_rejection_retirement_also_works_without_background_maintenance() {
    let mut client = setup().await;
    let mut limits = startup::store_limits();
    limits.retained[4] = 1;
    insert(
        &client,
        false,
        100,
        &UserAgentProfileInput::new("old-invalid"),
    )
    .await;
    client
        .execute(
            "UPDATE public.\"public-ua-profiles\" SET h1_settings='\"invalid\"'",
            &[],
        )
        .await
        .unwrap();
    let report = backfill(&mut client, false, 100, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!(report.rejected_invalid, 1);
    insert(
        &client,
        false,
        114,
        &UserAgentProfileInput::new("new-invalid"),
    )
    .await;
    client
        .execute(
            "UPDATE public.\"public-ua-profiles\" SET h1_settings='\"invalid\"'",
            &[],
        )
        .await
        .unwrap();
    let report = backfill(&mut client, false, 114, [7; 32], limits)
        .await
        .unwrap();
    assert_eq!((report.read, report.rejected_invalid), (1, 1));
    let rows = client
        .query("SELECT rejected_day FROM fp_v2.legacy_rejections", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, i64>(0), 114);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_sql_bounds_each_field_key_and_aggregate_before_client_decoding() {
    let client = setup().await;
    client.execute("INSERT INTO public.\"public-ua-profiles\" (uastr,updated_at,h1_settings,source_info) VALUES ('field-limit',to_timestamp(100*86400),'{\"title_case_headers\":true}',json_build_object('device_name',repeat('x',$1)))", &[&i32::try_from(ROW_BYTES+1).unwrap()]).await.unwrap();
    client.execute("INSERT INTO public.\"public-ua-profiles\" (uastr,updated_at,h1_settings,source_info) VALUES ('row-limit',to_timestamp(100*86400),to_json(repeat('x',$1)),to_json(repeat('y',$1)))", &[&i32::try_from(ROW_BYTES/2+1).unwrap()]).await.unwrap();
    insert(&client, false, 100, &profile(&"z".repeat(KEY_BYTES + 1))).await;
    let rows = client
        .query(
            &source_query(false).unwrap(),
            &[
                &None::<String>,
                &87_i64,
                &32_i64,
                &i64::try_from(KEY_BYTES).unwrap(),
                &i64::try_from(ROW_BYTES).unwrap(),
                &false,
                &"public-ua-profiles",
                &100_i64,
            ],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    let fields = rows[0].get::<_, Option<Vec<Option<String>>>>(3).unwrap();
    assert_eq!(
        rows[0].get::<_, Option<String>>(0).as_deref(),
        Some("field-limit")
    );
    assert_eq!(fields.len(), FIELDS.len());
    assert!(fields[0].is_some());
    assert!(fields[FIELDS.len() - 1].is_none());
    assert_eq!(rows[0].get::<_, i32>(6), 1);
    assert!(fields.iter().flatten().map(String::len).sum::<usize>() <= ROW_BYTES);
    assert_eq!(
        rows[1].get::<_, Option<String>>(0).as_deref(),
        Some("row-limit")
    );
    assert!(rows[1].get::<_, Option<Vec<Option<String>>>>(3).is_none());
    assert!(rows[2].get::<_, Option<String>>(0).is_none());
    assert!(rows[2].get::<_, Option<Vec<Option<String>>>>(3).is_none());
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_database_failures_stop_without_rejection_checkpoints() {
    let mut client = setup().await;
    insert(&client, false, 100, &profile("valid-row")).await;
    client
        .batch_execute("ALTER TABLE public.\"public-ua-profiles\" DROP COLUMN h2_settings")
        .await
        .unwrap();
    let error = backfill(&mut client, false, 100, [7; 32], startup::store_limits())
        .await
        .unwrap_err();
    assert_eq!(error_category(error.as_ref()), "database");
    assert_eq!(stored_totals(&client).await, (0, 0, 0, 0));
    let count: i64 = client
        .query_one("SELECT count(*) FROM fp_v2.legacy_rejections", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore = "requires the private PostgreSQL integration harness"]
async fn legacy_page_cursor_uses_the_sources_own_collation_index() {
    let client = setup().await;
    client.batch_execute("CREATE COLLATION IF NOT EXISTS fp_v2.source_order (provider=libc,locale='C');
        ALTER TABLE public.\"public-ua-profiles\" ALTER COLUMN uastr TYPE text COLLATE fp_v2.source_order;
        INSERT INTO public.\"public-ua-profiles\" (uastr,updated_at) SELECT 'cursor/'||lpad(n::text,4,'0'),to_timestamp(100*86400) FROM generate_series(0,1023) n;
        ANALYZE public.\"public-ua-profiles\";
        SET enable_seqscan=off;").await.unwrap();
    let explain = format!("EXPLAIN {}", source_query(false).unwrap());
    let rows = client
        .query(
            &explain,
            &[
                &Some("cursor/0500"),
                &87_i64,
                &32_i64,
                &i64::try_from(KEY_BYTES).unwrap(),
                &i64::try_from(ROW_BYTES).unwrap(),
                &false,
                &"public-ua-profiles",
                &100_i64,
            ],
        )
        .await
        .unwrap();
    let plan = rows
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    writeln!(stdout().lock(), "legacy cursor plan: {plan}").unwrap();
    assert!(plan.contains("Index Scan"), "{plan}");
    assert!(plan.contains("Index Cond:"), "{plan}");
    assert!(!plan.contains("COLLATE \"C\""), "{plan}");
}
