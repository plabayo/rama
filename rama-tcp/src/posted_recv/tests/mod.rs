mod harness;

mod posted;

// Characterization and benchmarks: prints only, meaningless off Windows,
// where reads just pass through. Run them with `just characterize-posted-recv`.
#[cfg(target_os = "windows")]
mod characterize;
#[cfg(target_os = "windows")]
mod perf;

#[cfg(target_os = "windows")]
mod spike;
