//! Run in a fresh process for each cold/warm disk-cache measurement.
#![expect(
    clippy::unwrap_used,
    reason = "benchmark setup and evaluations must succeed"
)]
#![expect(clippy::print_stdout, reason = "emit benchmark measurements as CSV")]

use std::{hint::black_box, time::Instant};

use rama_js::JsRuntime;
use rama_net::uri::Uri;
use rama_pac::PacResolver;

#[path = "../tests/support/representative.rs"]
mod representative;

#[expect(
    clippy::panic,
    reason = "invalid benchmark configuration must fail the run"
)]
fn main() {
    let backend = match std::env::var("RAMA_PAC_BENCH_INTERPRETER").as_deref() {
        Err(std::env::VarError::NotPresent) => rama_js::JsBackend::default(),
        Ok("1") => {
            #[cfg(any(target_os = "ios", feature = "js-interpreter"))]
            {
                rama_js::JsBackend::Interpreter
            }
            #[cfg(not(any(target_os = "ios", feature = "js-interpreter")))]
            {
                panic!("enable js-interpreter for interpreter measurements")
            }
        }
        value => panic!("invalid benchmark backend selection: {value:?}"),
    };
    let blueprint = JsRuntime::builder().with_backend(backend);
    let started = Instant::now();
    #[cfg(feature = "js-disk-cache")]
    if let Some(root) = std::env::var_os("RAMA_PAC_BENCH_CACHE") {
        blueprint
            .warm_up_with_disk_cache(std::path::Path::new(&root), "compiled")
            .unwrap();
    } else {
        blueprint.warm_up().unwrap();
    }
    #[cfg(not(feature = "js-disk-cache"))]
    {
        assert!(
            std::env::var_os("RAMA_PAC_BENCH_CACHE").is_none(),
            "enable js-disk-cache"
        );
        blueprint.warm_up().unwrap();
    }
    let engine_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    executor.block_on(async {
        let started = Instant::now();
        let resolver = PacResolver::builder()
            .with_backend(backend)
            .build_static(representative::SCRIPT)
            .unwrap();
        let cases: Vec<(Uri, &str)> = representative::CASES
            .iter()
            .map(|(url, expected)| (url.parse().unwrap(), *expected))
            .collect();
        // The worker loads the PAC lazily on its first evaluation.
        for (url, expected) in &cases {
            assert_eq!(
                resolver.find_proxy(url).await.unwrap().to_string(),
                *expected
            );
        }
        let load_ms = started.elapsed().as_secs_f64() * 1_000.0;
        for _ in 0..20 {
            for (url, _) in &cases {
                black_box(resolver.find_proxy(black_box(url)).await.unwrap());
            }
        }
        let mut samples = Vec::with_capacity(2_000);
        for _ in 0..400 {
            for (url, _) in &cases {
                let started = Instant::now();
                black_box(resolver.find_proxy(black_box(url)).await.unwrap());
                samples.push(started.elapsed().as_secs_f64() * 1_000_000.0);
            }
        }
        samples.sort_by(f64::total_cmp);
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        println!("backend,engine_ms,load_and_first_five_ms,requests,mean_us,p50_us,p95_us");
        println!(
            "{},{engine_ms:.3},{load_ms:.3},{},{mean:.3},{:.3},{:.3}",
            match backend {
                #[cfg(not(target_os = "ios"))]
                rama_js::JsBackend::Native => "winch",
                #[cfg(any(target_os = "ios", feature = "js-interpreter"))]
                rama_js::JsBackend::Interpreter => "pulley",
            },
            samples.len(),
            samples[samples.len() / 2],
            samples[samples.len() * 95 / 100]
        );
    });
}
