//! Strict current-run evidence collector for the transparent-proxy dial9 trace.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs::{self, File},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use dial9_trace_format::{decoder::Decoder, types::FieldValueRef};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const SCHEMA_VERSION: u32 = 1;
const MAX_DECODED_TRACE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Artifact {
    name: String,
    index: u32,
    state: ArtifactState,
    encoding: ArtifactEncoding,
    size: u64,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactState {
    Active,
    Sealed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactEncoding {
    Raw,
    Gzip,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Snapshot {
    schema_version: u32,
    max_index: Option<u32>,
    artifacts: Vec<Artifact>,
    issues: Vec<String>,
    schema_complete: bool,
}

#[derive(Clone, Debug, Serialize)]
struct Collection {
    schema_version: u32,
    baseline_max_index: Option<u32>,
    current_segment_count: usize,
    current_indices: Vec<u32>,
    artifacts: Vec<Artifact>,
    tproxy_open_count: usize,
    tproxy_close_count: usize,
    paired_flow_count: usize,
    udp_paired_flow_count: usize,
    required_flow_id: Option<u64>,
    required_protocol: Option<u32>,
    required_pair_count: usize,
    schema_complete: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct PairRequirement {
    flow_id: Option<u64>,
    protocol: Option<u32>,
}

#[derive(Debug, Default)]
struct EventSummary {
    opens: BTreeMap<u64, BTreeSet<u32>>,
    ordered_pairs: BTreeMap<u64, BTreeSet<u32>>,
    open_occurrences: BTreeMap<(u64, u32), usize>,
    close_occurrences: BTreeMap<u64, usize>,
    open_count: usize,
    close_count: usize,
}

impl EventSummary {
    fn absorb_segment(&mut self, segment: Self) {
        self.open_count += segment.open_count;
        self.close_count += segment.close_count;
        for (key, count) in segment.open_occurrences {
            *self.open_occurrences.entry(key).or_default() += count;
        }
        for (flow_id, count) in segment.close_occurrences {
            *self.close_occurrences.entry(flow_id).or_default() += count;
        }
        for (flow_id, protocols) in segment.ordered_pairs {
            self.ordered_pairs
                .entry(flow_id)
                .or_default()
                .extend(protocols);
        }
    }

    fn collection(
        &self,
        baseline_max_index: Option<u32>,
        artifacts: Vec<Artifact>,
        requirement: PairRequirement,
    ) -> Collection {
        let pairs = self
            .ordered_pairs
            .iter()
            .filter(|(flow_id, protocols)| {
                protocols.len() == 1
                    && self.close_occurrences.get(flow_id) == Some(&1)
                    && protocols.iter().any(|protocol| {
                        self.open_occurrences.get(&(**flow_id, *protocol)) == Some(&1)
                    })
            })
            .collect::<Vec<_>>();
        let required_pair_count = pairs
            .iter()
            .filter(|(flow_id, protocols)| {
                requirement
                    .flow_id
                    .is_none_or(|required| **flow_id == required)
                    && requirement.protocol.is_none_or(|required| {
                        protocols.contains(&required)
                            && self.open_occurrences.get(&(**flow_id, required)) == Some(&1)
                    })
            })
            .count();
        let current_indices = artifacts.iter().map(|artifact| artifact.index).collect();
        Collection {
            schema_version: SCHEMA_VERSION,
            baseline_max_index,
            current_segment_count: artifacts.len(),
            current_indices,
            artifacts,
            tproxy_open_count: self.open_count,
            tproxy_close_count: self.close_count,
            paired_flow_count: pairs.len(),
            udp_paired_flow_count: pairs
                .iter()
                .filter(|(_, protocols)| protocols.contains(&2))
                .count(),
            required_flow_id: requirement.flow_id,
            required_protocol: requirement.protocol,
            required_pair_count,
            schema_complete: true,
        }
    }
}

fn parse_artifact_name(
    name: &str,
) -> Result<Option<(u32, ArtifactState, ArtifactEncoding)>, String> {
    let Some(rest) = name.strip_prefix("trace.") else {
        return Ok(None);
    };
    let Some((index, suffix)) = rest.split_once(".bin") else {
        return Err(format!("malformed dial9 trace artifact name {name:?}"));
    };
    let index_text = index;
    let index = index_text
        .parse::<u32>()
        .map_err(|_| format!("invalid dial9 trace index in {name:?}"))?;
    if index.to_string() != index_text {
        return Err(format!("non-canonical dial9 trace index in {name:?}"));
    }
    match suffix {
        "" => Ok(Some((index, ArtifactState::Sealed, ArtifactEncoding::Raw))),
        ".gz" => Ok(Some((index, ArtifactState::Sealed, ArtifactEncoding::Gzip))),
        ".active" => Ok(Some((index, ArtifactState::Active, ArtifactEncoding::Raw))),
        _ => Err(format!("unsupported dial9 trace artifact name {name:?}")),
    }
}

fn hash_file(path: &Path) -> Result<(u64, String), String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let size = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let mut sha256 = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut sha256, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok((size, sha256))
}

fn snapshot(directory: &Path, allow_missing: bool) -> Snapshot {
    let mut artifacts = Vec::new();
    let mut issues = Vec::new();
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
            return Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts,
                issues,
                schema_complete: true,
            };
        }
        Err(error) => {
            issues.push(format!(
                "could not read dial9 trace directory {}: {error}",
                directory.display()
            ));
            return Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts,
                issues,
                schema_complete: true,
            };
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                issues.push(format!(
                    "could not enumerate dial9 trace directory: {error}"
                ));
                continue;
            }
        };
        let Ok(name) = entry.file_name().into_string() else {
            issues.push("dial9 trace directory contains a non-UTF-8 name".to_owned());
            continue;
        };
        let parsed = match parse_artifact_name(&name) {
            Ok(parsed) => parsed,
            Err(error) => {
                issues.push(error);
                continue;
            }
        };
        let Some((index, state, encoding)) = parsed else {
            continue;
        };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            Ok(_) => {
                issues.push(format!(
                    "dial9 trace artifact {name:?} is not a regular file"
                ));
                continue;
            }
            Err(error) => {
                issues.push(format!(
                    "could not stat dial9 trace artifact {name:?}: {error}"
                ));
                continue;
            }
        };
        let (size, sha256) = match hash_file(&entry.path()) {
            Ok(identity) => identity,
            Err(error) => {
                issues.push(error);
                continue;
            }
        };
        if size != metadata.len() {
            issues.push(format!(
                "dial9 trace artifact {name:?} changed while hashing"
            ));
            continue;
        }
        artifacts.push(Artifact {
            name,
            index,
            state,
            encoding,
            size,
            sha256,
        });
    }
    artifacts.sort_by_key(|artifact| (artifact.index, artifact.name.clone()));
    Snapshot {
        schema_version: SCHEMA_VERSION,
        max_index: artifacts.iter().map(|artifact| artifact.index).max(),
        artifacts,
        issues,
        schema_complete: true,
    }
}

fn current_artifacts(
    snapshot: &Snapshot,
    after_index: Option<u32>,
) -> Result<Vec<Artifact>, String> {
    if snapshot.schema_version != SCHEMA_VERSION || !snapshot.schema_complete {
        return Err("dial9 snapshot schema is incomplete or unsupported".to_owned());
    }
    if !snapshot.issues.is_empty() {
        return Err(snapshot.issues.join("; "));
    }
    let mut current = snapshot
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.state == ArtifactState::Sealed
                && after_index.is_none_or(|index| artifact.index > index)
        })
        .cloned()
        .collect::<Vec<_>>();
    current.sort_by_key(|artifact| (artifact.index, artifact.name.clone()));
    let mut seen = BTreeSet::new();
    for artifact in &current {
        if !seen.insert(artifact.index) {
            return Err(format!(
                "dial9 trace index {} has multiple retained representations",
                artifact.index
            ));
        }
    }
    if current.is_empty() {
        return Err("no sealed current-run dial9 trace segment is available".to_owned());
    }
    Ok(current)
}

fn decode_file(
    path: &Path,
    encoding: ArtifactEncoding,
    summary: &mut EventSummary,
) -> Result<(), String> {
    let encoded_size = fs::metadata(path)
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    if encoded_size > MAX_DECODED_TRACE_BYTES {
        return Err(format!(
            "dial9 artifact {} exceeds the decode limit",
            path.display()
        ));
    }
    let bytes = match encoding {
        ArtifactEncoding::Raw => {
            fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?
        }
        ArtifactEncoding::Gzip => {
            let file =
                File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
            let mut bytes = Vec::new();
            GzDecoder::new(file)
                .take(MAX_DECODED_TRACE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("decompress {}: {error}", path.display()))?;
            bytes
        }
    };
    if bytes.len() as u64 > MAX_DECODED_TRACE_BYTES {
        return Err(format!(
            "dial9 artifact {} exceeds the decompressed limit",
            path.display()
        ));
    }
    let mut decoder = Decoder::new(&bytes)
        .ok_or_else(|| format!("decode dial9 header {}: invalid header", path.display()))?;
    decoder
        .for_each_event(|event| match event.name {
            "TproxyFlowOpened" => {
                let mut flow_id = None;
                let mut protocol = None;
                for (name, value) in event.field_names().zip(event.fields.iter()) {
                    if let FieldValueRef::Varint(value) = value {
                        match name {
                            "flow_id" => flow_id = Some(*value),
                            "protocol" => protocol = u32::try_from(*value).ok(),
                            _ => {}
                        }
                    }
                }
                if let (Some(flow_id), Some(protocol)) = (flow_id, protocol) {
                    summary.opens.entry(flow_id).or_default().insert(protocol);
                    *summary
                        .open_occurrences
                        .entry((flow_id, protocol))
                        .or_default() += 1;
                    summary.open_count += 1;
                }
            }
            "TproxyFlowClosed" => {
                for (name, value) in event.field_names().zip(event.fields.iter()) {
                    if name == "flow_id"
                        && let FieldValueRef::Varint(flow_id) = value
                    {
                        if let Some(protocols) = summary.opens.get(flow_id) {
                            summary
                                .ordered_pairs
                                .entry(*flow_id)
                                .or_default()
                                .extend(protocols);
                        }
                        *summary.close_occurrences.entry(*flow_id).or_default() += 1;
                        summary.close_count += 1;
                        break;
                    }
                }
            }
            _ => {}
        })
        .map_err(|error| format!("decode dial9 events {}: {error}", path.display()))
}

fn decode_artifacts(directory: &Path, artifacts: &[Artifact]) -> Result<EventSummary, String> {
    let mut summary = EventSummary::default();
    for artifact in artifacts {
        let mut segment = EventSummary::default();
        decode_file(
            &directory.join(&artifact.name),
            artifact.encoding,
            &mut segment,
        )?;
        summary.absorb_segment(segment);
    }
    Ok(summary)
}

fn copy_once(
    source: &Path,
    destination: &Path,
    baseline: &Snapshot,
    requirement: PairRequirement,
) -> Result<Collection, String> {
    let before_snapshot = snapshot(source, false);
    let before = current_artifacts(&before_snapshot, baseline.max_index)?;
    let temp_destination = destination.with_extension(format!("tmp.{}", std::process::id()));
    if temp_destination.exists() {
        fs::remove_dir_all(&temp_destination).map_err(|error| {
            format!(
                "remove stale temporary dial9 evidence directory {}: {error}",
                temp_destination.display()
            )
        })?;
    }
    fs::create_dir_all(&temp_destination).map_err(|error| {
        format!(
            "create temporary dial9 evidence directory {}: {error}",
            temp_destination.display()
        )
    })?;
    let staged = (|| {
        for artifact in &before {
            fs::copy(
                source.join(&artifact.name),
                temp_destination.join(&artifact.name),
            )
            .map_err(|error| format!("copy dial9 artifact {:?}: {error}", artifact.name))?;
        }
        let after = current_artifacts(&snapshot(source, false), baseline.max_index)?;
        let copied = current_artifacts(&snapshot(&temp_destination, false), baseline.max_index)?;
        if before != after || before != copied {
            return Err("dial9 trace artifacts changed while being copied".to_owned());
        }
        let events = decode_artifacts(&temp_destination, &copied)?;
        let collection = events.collection(baseline.max_index, copied, requirement);
        if collection.required_pair_count == 0 {
            return Err(
                "current dial9 trace lacks one exact ordered open/close flow pair".to_owned(),
            );
        }
        if destination.exists() {
            return Err(format!(
                "dial9 evidence destination {} already exists",
                destination.display()
            ));
        }
        Ok(collection)
    })();
    let collection = match staged {
        Ok(collection) => collection,
        Err(error) => {
            let _ = fs::remove_dir_all(&temp_destination);
            return Err(error);
        }
    };
    fs::rename(&temp_destination, destination).map_err(|error| {
        let _ = fs::remove_dir_all(&temp_destination);
        format!(
            "publish dial9 evidence directory {}: {error}",
            destination.display()
        )
    })?;
    Ok(collection)
}

fn collect(
    source: &Path,
    baseline: &Snapshot,
    destination: &Path,
    requirement: PairRequirement,
    wait: Duration,
) -> Result<Collection, String> {
    let deadline = Instant::now() + wait;
    loop {
        let error = match copy_once(source, destination, baseline, requirement) {
            Ok(collection) => return Ok(collection),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(error);
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn write_json(value: &impl Serialize) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)
        .map_err(|error| format!("serialize evidence: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("write evidence: {error}"))
}

fn parse_collect_args(
    args: &[String],
) -> Result<(PathBuf, PathBuf, PathBuf, PairRequirement, Duration), String> {
    if args.len() < 3 {
        return Err(
            "usage: dial9_evidence collect <trace-dir> <baseline.json> <destination> [--wait-seconds N] [--flow-id N] [--protocol N]"
                .to_owned(),
        );
    }
    let source = PathBuf::from(&args[0]);
    let baseline = PathBuf::from(&args[1]);
    let destination = PathBuf::from(&args[2]);
    let mut requirement = PairRequirement::default();
    let mut wait = Duration::from_secs(0);
    let mut index = 3;
    while index < args.len() {
        let option = &args[index];
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {option}"))?;
        match option.as_str() {
            "--wait-seconds" => {
                wait = Duration::from_secs(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid wait duration {value:?}"))?,
                );
            }
            "--flow-id" => {
                requirement.flow_id = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid flow id {value:?}"))?,
                );
            }
            "--protocol" => {
                requirement.protocol = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| format!("invalid protocol {value:?}"))?,
                );
            }
            _ => return Err(format!("unknown collect option {option:?}")),
        }
        index += 2;
    }
    Ok((source, baseline, destination, requirement, wait))
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return Err("usage: dial9_evidence <snapshot|collect> ...".to_owned());
    }
    match args.remove(0).as_str() {
        "snapshot" => {
            let allow_missing = args.last().is_some_and(|arg| arg == "--allow-missing");
            if allow_missing {
                args.pop();
            }
            if args.len() != 1 {
                return Err(
                    "usage: dial9_evidence snapshot <trace-dir> [--allow-missing]".to_owned(),
                );
            }
            let snapshot = snapshot(Path::new(&args[0]), allow_missing);
            write_json(&snapshot)?;
            if snapshot.issues.is_empty() {
                Ok(())
            } else {
                Err(snapshot.issues.join("; "))
            }
        }
        "collect" => {
            let (source, baseline_path, destination, requirement, wait) =
                parse_collect_args(&args)?;
            let baseline: Snapshot = serde_json::from_reader(
                File::open(&baseline_path)
                    .map_err(|error| format!("open {}: {error}", baseline_path.display()))?,
            )
            .map_err(|error| format!("parse {}: {error}", baseline_path.display()))?;
            if baseline.schema_version != SCHEMA_VERSION
                || !baseline.schema_complete
                || !baseline.issues.is_empty()
            {
                return Err("baseline dial9 snapshot is incomplete or invalid".to_owned());
            }
            let collection = collect(&source, &baseline, &destination, requirement, wait)?;
            write_json(&collection)
        }
        command => Err(format!("unknown command {command:?}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dial9 evidence failed: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dial9_trace_format::{TraceEvent, encoder::Encoder};
    use flate2::{Compression, write::GzEncoder};
    use tempfile::TempDir;

    #[derive(TraceEvent)]
    struct TproxyFlowOpened {
        #[traceevent(timestamp)]
        timestamp_ns: u64,
        flow_id: u64,
        protocol: u32,
        pid: i64,
    }

    #[derive(TraceEvent)]
    struct TproxyFlowClosed {
        #[traceevent(timestamp)]
        timestamp_ns: u64,
        flow_id: u64,
        reason: u64,
        age_ms: u64,
        bytes_in: u64,
        bytes_out: u64,
    }

    fn trace_bytes(flow_id: u64, protocol: u32, include_close: bool) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write(&TproxyFlowOpened {
                timestamp_ns: 1,
                flow_id,
                protocol,
                pid: 42,
            })
            .unwrap();
        if include_close {
            encoder
                .write(&TproxyFlowClosed {
                    timestamp_ns: 2,
                    flow_id,
                    reason: 0,
                    age_ms: 1,
                    bytes_in: 48,
                    bytes_out: 48,
                })
                .unwrap();
        }
        encoder.finish()
    }

    fn reversed_trace_bytes(flow_id: u64, protocol: u32) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write(&TproxyFlowClosed {
                timestamp_ns: 1,
                flow_id,
                reason: 0,
                age_ms: 1,
                bytes_in: 48,
                bytes_out: 48,
            })
            .unwrap();
        encoder
            .write(&TproxyFlowOpened {
                timestamp_ns: 2,
                flow_id,
                protocol,
                pid: 42,
            })
            .unwrap();
        encoder.finish()
    }

    fn close_trace_bytes(flow_id: u64) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write(&TproxyFlowClosed {
                timestamp_ns: 1,
                flow_id,
                reason: 0,
                age_ms: 1,
                bytes_in: 48,
                bytes_out: 48,
            })
            .unwrap();
        encoder.finish()
    }

    fn write_trace(directory: &Path, name: &str, bytes: &[u8]) {
        fs::write(directory.join(name), bytes).unwrap();
    }

    #[test]
    fn baseline_active_segment_later_sealed_is_not_current() {
        let source = TempDir::new().unwrap();
        write_trace(source.path(), "trace.8.bin.active", b"active");
        let baseline = snapshot(source.path(), false);
        fs::remove_file(source.path().join("trace.8.bin.active")).unwrap();
        write_trace(source.path(), "trace.8.bin", &trace_bytes(9, 2, true));
        let current = current_artifacts(&snapshot(source.path(), false), baseline.max_index);
        assert!(current.unwrap_err().contains("no sealed current-run"));
    }

    #[test]
    fn current_gzip_udp_pair_is_copied_and_verified() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.8.bin.active", b"active");
        let baseline = snapshot(source.path(), false);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&trace_bytes(77, 2, true)).unwrap();
        write_trace(source.path(), "trace.9.bin.gz", &encoder.finish().unwrap());
        let destination = output.path().join("dial9-traces");
        let result = collect(
            source.path(),
            &baseline,
            &destination,
            PairRequirement {
                flow_id: Some(77),
                protocol: Some(2),
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result.required_pair_count, 1);
        assert_eq!(result.required_flow_id, Some(77));
        assert_eq!(result.required_protocol, Some(2));
        assert_eq!(result.udp_paired_flow_count, 1);
        assert!(destination.join("trace.9.bin.gz").is_file());
    }

    #[test]
    fn current_open_without_close_is_rejected() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(7, 2, false));
        let error = collect(
            source.path(),
            &Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts: vec![],
                issues: vec![],
                schema_complete: true,
            },
            &output.path().join("dial9-traces"),
            PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
    }

    #[test]
    fn close_before_open_is_not_a_pair() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &reversed_trace_bytes(7, 2));
        let error = collect(
            source.path(),
            &Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts: vec![],
                issues: vec![],
                schema_complete: true,
            },
            &output.path().join("dial9-traces"),
            PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
        assert!(fs::read_dir(output.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("dial9-traces.tmp.")
        }));
    }

    #[test]
    fn open_and_close_in_different_segments_are_not_a_pair() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(7, 2, false));
        write_trace(source.path(), "trace.2.bin", &close_trace_bytes(7));
        let error = collect(
            source.path(),
            &Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts: vec![],
                issues: vec![],
                schema_complete: true,
            },
            &output.path().join("dial9-traces"),
            PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
    }

    #[test]
    fn malformed_and_duplicate_current_artifacts_are_rejected() {
        let directory = TempDir::new().unwrap();
        write_trace(directory.path(), "trace.bad.bin", b"bad");
        let malformed = snapshot(directory.path(), false);
        assert!(!malformed.issues.is_empty());

        fs::remove_file(directory.path().join("trace.bad.bin")).unwrap();
        write_trace(directory.path(), "trace.01.bin", b"bad");
        let noncanonical = snapshot(directory.path(), false);
        assert!(!noncanonical.issues.is_empty());
        fs::remove_file(directory.path().join("trace.01.bin")).unwrap();
        let bytes = trace_bytes(1, 2, true);
        write_trace(directory.path(), "trace.2.bin", &bytes);
        write_trace(directory.path(), "trace.2.bin.gz", &bytes);
        let duplicate = current_artifacts(&snapshot(directory.path(), false), None);
        assert!(duplicate.unwrap_err().contains("multiple retained"));
    }

    #[test]
    fn tcp_pair_does_not_satisfy_udp_requirement() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(11, 1, true));
        let error = collect(
            source.path(),
            &Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts: vec![],
                issues: vec![],
                schema_complete: true,
            },
            &output.path().join("dial9-traces"),
            PairRequirement {
                flow_id: Some(11),
                protocol: Some(2),
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
    }
}
