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
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const SCHEMA_VERSION: u32 = 1;
const MAX_DECODED_TRACE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REQUIREMENTS_BYTES: usize = 1024 * 1024;
const REQUIREMENTS_HEADER: &str = "label\tprovider_pid\tprovider_generation\tflow_id\tprotocol\tsource_pid\tclose_reason\tmin_bytes_in\tmax_bytes_in\tmin_bytes_out\tmax_bytes_out";

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
    required_close_reason: Option<u64>,
    required_close_reason_name: Option<&'static str>,
    required_close_age_ms: Option<u64>,
    required_bytes_in: Option<u64>,
    required_bytes_out: Option<u64>,
    requirements_sha256: Option<String>,
    requirement_count: usize,
    matched_requirement_count: usize,
    required_flows: Vec<RequiredFlowEvidence>,
    schema_complete: bool,
}

#[derive(Clone, Debug, Default)]
struct PairRequirement {
    flow_id: Option<u64>,
    protocol: Option<u32>,
    requirements: Vec<FlowRequirement>,
    requirements_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FlowRequirement {
    label: String,
    identity: FlowIdentity,
    close_reason: u64,
    min_bytes_in: u64,
    max_bytes_in: u64,
    min_bytes_out: u64,
    max_bytes_out: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FlowIdentity {
    provider_pid: u32,
    provider_generation: u64,
    flow_id: u64,
    protocol: u32,
    source_pid: i64,
}

#[derive(Clone, Debug, Serialize)]
struct RequiredFlowEvidence {
    label: String,
    provider_pid: u32,
    provider_generation: u64,
    flow_id: u64,
    protocol: u32,
    source_pid: i64,
    close_reason: u64,
    close_reason_name: &'static str,
    close_age_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Debug, Default)]
struct EventSummary {
    opens: BTreeSet<FlowIdentity>,
    ordered_pairs: BTreeSet<FlowIdentity>,
    open_timestamps: BTreeMap<FlowIdentity, Vec<(u64, u32)>>,
    close_timestamps: BTreeMap<FlowIdentity, Vec<(u64, u32)>>,
    open_occurrences: BTreeMap<FlowIdentity, usize>,
    close_occurrences: BTreeMap<FlowIdentity, usize>,
    close_evidence: BTreeMap<FlowIdentity, Vec<CloseEvidence>>,
    open_count: usize,
    close_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CloseEvidence {
    reason: u64,
    age_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
}

fn close_reason_name(reason: u64) -> Option<&'static str> {
    Some(match reason {
        1 => "shutdown",
        2 => "idle_timeout",
        3 => "peer_eof_left",
        4 => "peer_eof_right",
        5 => "read_error_left",
        6 => "read_error_right",
        7 => "write_error_left",
        8 => "write_error_right",
        9 => "peek_timeout",
        10 => "handler_deadline",
        11 => "paused_timeout",
        12 => "first_byte_timeout",
        13 => "max_lifetime",
        14 => "service_panic",
        _ => return None,
    })
}

impl EventSummary {
    fn collection(
        &self,
        baseline_max_index: Option<u32>,
        artifacts: Vec<Artifact>,
        requirement: &PairRequirement,
    ) -> Collection {
        let pairs = self
            .ordered_pairs
            .iter()
            .filter(|identity| {
                self.close_occurrences.get(identity) == Some(&1)
                    && self.open_occurrences.get(identity) == Some(&1)
            })
            .collect::<Vec<_>>();
        let required_pair_count = pairs
            .iter()
            .filter(|identity| {
                requirement
                    .flow_id
                    .is_none_or(|required| identity.flow_id == required)
                    && requirement
                        .protocol
                        .is_none_or(|required| identity.protocol == required)
            })
            .count();
        let legacy_identity = (required_pair_count == 1)
            .then(|| {
                pairs.iter().find(|identity| {
                    requirement
                        .flow_id
                        .is_none_or(|value| identity.flow_id == value)
                        && requirement
                            .protocol
                            .is_none_or(|value| identity.protocol == value)
                })
            })
            .flatten()
            .copied();
        let required_close = legacy_identity.and_then(|identity| {
            self.close_evidence
                .get(identity)
                .and_then(|values| (values.len() == 1).then_some(values[0]))
        });
        let required_flows = requirement
            .requirements
            .iter()
            .filter_map(|required| {
                if self.open_occurrences.get(&required.identity) != Some(&1)
                    || self.close_occurrences.get(&required.identity) != Some(&1)
                    || !self.ordered_pairs.contains(&required.identity)
                {
                    return None;
                }
                let close = *self.close_evidence.get(&required.identity)?.first()?;
                if close.reason != required.close_reason
                    || !(required.min_bytes_in..=required.max_bytes_in).contains(&close.bytes_in)
                    || !(required.min_bytes_out..=required.max_bytes_out).contains(&close.bytes_out)
                {
                    return None;
                }
                Some(RequiredFlowEvidence {
                    label: required.label.clone(),
                    provider_pid: required.identity.provider_pid,
                    provider_generation: required.identity.provider_generation,
                    flow_id: required.identity.flow_id,
                    protocol: required.identity.protocol,
                    source_pid: required.identity.source_pid,
                    close_reason: close.reason,
                    close_reason_name: close_reason_name(close.reason)?,
                    close_age_ms: close.age_ms,
                    bytes_in: close.bytes_in,
                    bytes_out: close.bytes_out,
                })
            })
            .collect::<Vec<_>>();
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
                .filter(|identity| identity.protocol == 2)
                .count(),
            required_flow_id: requirement.flow_id,
            required_protocol: requirement.protocol,
            required_pair_count,
            required_close_reason: required_close.map(|value| value.reason),
            required_close_reason_name: required_close
                .and_then(|value| close_reason_name(value.reason)),
            required_close_age_ms: required_close.map(|value| value.age_ms),
            required_bytes_in: required_close.map(|value| value.bytes_in),
            required_bytes_out: required_close.map(|value| value.bytes_out),
            requirements_sha256: requirement.requirements_sha256.clone(),
            requirement_count: requirement.requirements.len(),
            matched_requirement_count: required_flows.len(),
            required_flows,
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

fn parse_canonical_u64(value: &str, field: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{field} is not a canonical unsigned integer"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{field} exceeds its integer range"))
}

fn load_requirements(path: &Path) -> Result<(Vec<FlowRequirement>, String), String> {
    let file = File::open(path)
        .map_err(|error| format!("open requirements {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_REQUIREMENTS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read requirements {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > MAX_REQUIREMENTS_BYTES {
        return Err("dial9 requirements TSV must be 1..=1048576 bytes".to_owned());
    }
    // Bind the digest, byte limit, and parsed requirements to this one read.
    // Reopening the path could hash one version and qualify against another.
    let contents = std::str::from_utf8(&bytes)
        .map_err(|error| format!("requirements {} are not UTF-8: {error}", path.display()))?;
    let mut sha256 = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        write!(&mut sha256, "{byte:02x}").expect("writing to String cannot fail");
    }
    if contents.contains('\r') || !contents.ends_with('\n') {
        return Err("dial9 requirements TSV must use LF lines and end with LF".to_owned());
    }
    let mut lines = contents.lines();
    if lines.next() != Some(REQUIREMENTS_HEADER) {
        return Err("dial9 requirements TSV header is incomplete or unsupported".to_owned());
    }
    let mut requirements = Vec::new();
    let mut labels = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut flow_ids = BTreeSet::new();
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 11 || fields.iter().any(|field| field.is_empty()) {
            return Err(format!("malformed dial9 requirement on line {line_number}"));
        }
        let label = fields[0];
        if label.len() > 80
            || !label.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'_' | b'-' | b'.'))
            })
        {
            return Err(format!(
                "invalid dial9 requirement label on line {line_number}"
            ));
        }
        let provider_pid = u32::try_from(parse_canonical_u64(fields[1], "provider_pid")?)
            .map_err(|_| "provider_pid exceeds u32".to_owned())?;
        let provider_generation = parse_canonical_u64(fields[2], "provider_generation")?;
        let flow_id = parse_canonical_u64(fields[3], "flow_id")?;
        let protocol = u32::try_from(parse_canonical_u64(fields[4], "protocol")?)
            .map_err(|_| "protocol exceeds u32".to_owned())?;
        let source_pid = i64::try_from(parse_canonical_u64(fields[5], "source_pid")?)
            .map_err(|_| "source_pid exceeds i64".to_owned())?;
        let close_reason = parse_canonical_u64(fields[6], "close_reason")?;
        let min_bytes_in = parse_canonical_u64(fields[7], "min_bytes_in")?;
        let max_bytes_in = parse_canonical_u64(fields[8], "max_bytes_in")?;
        let min_bytes_out = parse_canonical_u64(fields[9], "min_bytes_out")?;
        let max_bytes_out = parse_canonical_u64(fields[10], "max_bytes_out")?;
        if provider_pid == 0
            || provider_generation == 0
            || flow_id == 0
            || !matches!(protocol, 1 | 2)
            || source_pid <= 0
            || close_reason_name(close_reason).is_none()
            || min_bytes_in > max_bytes_in
            || min_bytes_out > max_bytes_out
        {
            return Err(format!(
                "invalid dial9 requirement bounds on line {line_number}"
            ));
        }
        let identity = FlowIdentity {
            provider_pid,
            provider_generation,
            flow_id,
            protocol,
            source_pid,
        };
        if !labels.insert(label.to_owned())
            || !identities.insert(identity)
            || !flow_ids.insert(flow_id)
        {
            return Err(format!("duplicate dial9 requirement on line {line_number}"));
        }
        requirements.push(FlowRequirement {
            label: label.to_owned(),
            identity,
            close_reason,
            min_bytes_in,
            max_bytes_in,
            min_bytes_out,
            max_bytes_out,
        });
    }
    if requirements.is_empty() || requirements.len() > 1024 {
        return Err("dial9 requirements TSV must contain 1..=1024 rows".to_owned());
    }
    Ok((requirements, sha256))
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

/// Check schema names before considering their decoded values. A duplicate
/// with a wrong type is just as ambiguous as two conflicting valid values.
/// Unknown fields remain available for future trace-schema extensions.
fn duplicate_required_field<'a>(
    names: impl Iterator<Item = &'a str>,
    is_close: bool,
) -> Option<&'a str> {
    let mut seen = 0_u16;
    for name in names {
        let bit = match name {
            "provider_pid" => 1,
            "provider_generation" => 1 << 1,
            "flow_id" => 1 << 2,
            "protocol" => 1 << 3,
            "pid" => 1 << 4,
            "reason" if is_close => 1 << 5,
            "age_ms" if is_close => 1 << 6,
            "bytes_in" if is_close => 1 << 7,
            "bytes_out" if is_close => 1 << 8,
            _ => continue,
        };
        if seen & bit != 0 {
            return Some(name);
        }
        seen |= bit;
    }
    None
}

fn read_bounded_trace(reader: impl std::io::Read, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trace exceeds decoded byte limit",
        ));
    }
    Ok(bytes)
}

fn decode_file(
    path: &Path,
    artifact_index: u32,
    encoding: ArtifactEncoding,
    summary: &mut EventSummary,
) -> Result<(), String> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let encoded_size = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    if encoded_size > MAX_DECODED_TRACE_BYTES {
        return Err(format!(
            "dial9 artifact {} exceeds the decode limit",
            path.display()
        ));
    }
    // Bound reads from this same open handle too: metadata is only an early
    // rejection, not an allocation limit if a producer changes the file.
    let mut encoded = file.take(MAX_DECODED_TRACE_BYTES + 1);
    let bytes = match encoding {
        ArtifactEncoding::Raw => read_bounded_trace(&mut encoded, MAX_DECODED_TRACE_BYTES)
            .map_err(|error| format!("read {}: {error}", path.display()))?,
        ArtifactEncoding::Gzip => {
            // Decode the complete sealed artifact: a single-member decoder
            // silently ignores further members or trailing corruption. The
            // limit applies to the combined output of every gzip member.
            read_bounded_trace(MultiGzDecoder::new(&mut encoded), MAX_DECODED_TRACE_BYTES)
                .map_err(|error| format!("decompress {}: {error}", path.display()))?
        }
    };
    if encoded.limit() == 0 {
        return Err(format!(
            "dial9 artifact {} exceeds the decode limit",
            path.display()
        ));
    }
    let mut decoder = Decoder::new(&bytes)
        .ok_or_else(|| format!("decode dial9 header {}: invalid header", path.display()))?;
    let mut invalid_event = None;
    decoder
        .for_each_event(|event| match event.name {
            "TproxyFlowOpened" => {
                if let Some(name) = duplicate_required_field(event.field_names(), false) {
                    invalid_event = Some(format!(
                        "TproxyFlowOpened has duplicate required field {name:?}"
                    ));
                    return;
                }
                let mut provider_pid = None;
                let mut provider_generation = None;
                let mut flow_id = None;
                let mut protocol = None;
                let mut source_pid = None;
                for (name, value) in event.field_names().zip(event.fields.iter()) {
                    match (name, value) {
                        ("provider_pid", FieldValueRef::Varint(value)) => {
                            provider_pid = u32::try_from(*value).ok();
                        }
                        ("provider_generation", FieldValueRef::Varint(value)) => {
                            provider_generation = Some(*value);
                        }
                        ("flow_id", FieldValueRef::Varint(value)) => flow_id = Some(*value),
                        ("protocol", FieldValueRef::Varint(value)) => {
                            protocol = u32::try_from(*value).ok();
                        }
                        ("pid", FieldValueRef::I64(value)) => source_pid = Some(*value),
                        _ => {}
                    }
                }
                if let (
                    Some(provider_pid @ 1..),
                    Some(provider_generation @ 1..),
                    Some(flow_id @ 1..),
                    Some(protocol @ 1..=2),
                    Some(source_pid @ 0..),
                ) = (provider_pid, provider_generation, flow_id, protocol, source_pid)
                {
                    let identity = FlowIdentity {
                        provider_pid,
                        provider_generation,
                        flow_id,
                        protocol,
                        source_pid,
                    };
                    summary.opens.insert(identity);
                    summary
                        .open_timestamps
                        .entry(identity)
                        .or_default()
                        .push((event.timestamp_ns, artifact_index));
                    *summary.open_occurrences.entry(identity).or_default() += 1;
                    summary.open_count += 1;
                } else {
                    invalid_event = Some(
                        "TproxyFlowOpened lacks valid provider/generation/flow/protocol/source fields"
                            .to_owned(),
                    );
                }
            }
            "TproxyFlowClosed" => {
                if let Some(name) = duplicate_required_field(event.field_names(), true) {
                    invalid_event = Some(format!(
                        "TproxyFlowClosed has duplicate required field {name:?}"
                    ));
                    return;
                }
                let mut provider_pid = None;
                let mut provider_generation = None;
                let mut flow_id = None;
                let mut protocol = None;
                let mut source_pid = None;
                let mut reason = None;
                let mut age_ms = None;
                let mut bytes_in = None;
                let mut bytes_out = None;
                for (name, value) in event.field_names().zip(event.fields.iter()) {
                    match (name, value) {
                        ("provider_pid", FieldValueRef::Varint(value)) => {
                            provider_pid = u32::try_from(*value).ok();
                        }
                        ("provider_generation", FieldValueRef::Varint(value)) => {
                            provider_generation = Some(*value);
                        }
                        ("flow_id", FieldValueRef::Varint(value)) => flow_id = Some(*value),
                        ("protocol", FieldValueRef::Varint(value)) => {
                            protocol = u32::try_from(*value).ok();
                        }
                        ("pid", FieldValueRef::I64(value)) => source_pid = Some(*value),
                        ("reason", FieldValueRef::Varint(value)) => reason = Some(*value),
                        ("age_ms", FieldValueRef::Varint(value)) => age_ms = Some(*value),
                        ("bytes_in", FieldValueRef::Varint(value)) => bytes_in = Some(*value),
                        ("bytes_out", FieldValueRef::Varint(value)) => bytes_out = Some(*value),
                        _ => {}
                    }
                }
                let evidence = match (reason, age_ms, bytes_in, bytes_out) {
                    (Some(reason @ 1..=14), Some(age_ms), Some(bytes_in), Some(bytes_out)) => {
                        Some(CloseEvidence {
                            reason,
                            age_ms,
                            bytes_in,
                            bytes_out,
                        })
                    }
                    _ => None,
                };
                if let (
                    Some(provider_pid @ 1..),
                    Some(provider_generation @ 1..),
                    Some(flow_id @ 1..),
                    Some(protocol @ 1..=2),
                    Some(source_pid @ 0..),
                    Some(evidence),
                ) = (
                    provider_pid,
                    provider_generation,
                    flow_id,
                    protocol,
                    source_pid,
                    evidence,
                ) {
                    let identity = FlowIdentity {
                        provider_pid,
                        provider_generation,
                        flow_id,
                        protocol,
                        source_pid,
                    };
                    *summary.close_occurrences.entry(identity).or_default() += 1;
                    summary
                        .close_timestamps
                        .entry(identity)
                        .or_default()
                        .push((event.timestamp_ns, artifact_index));
                    summary
                        .close_evidence
                        .entry(identity)
                        .or_default()
                        .push(evidence);
                    summary.close_count += 1;
                } else {
                    invalid_event = Some(
                        "TproxyFlowClosed lacks valid provider/generation/flow/protocol/source/reason/age_ms/bytes fields".to_owned(),
                    );
                }
            }
            _ => {}
        })
        .map_err(|error| format!("decode dial9 events {}: {error}", path.display()))?;
    if let Some(error) = invalid_event {
        return Err(format!("decode dial9 events {}: {error}", path.display()));
    }
    Ok(())
}

fn decode_artifacts(directory: &Path, artifacts: &[Artifact]) -> Result<EventSummary, String> {
    let mut summary = EventSummary::default();
    for artifact in artifacts {
        decode_file(
            &directory.join(&artifact.name),
            artifact.index,
            artifact.encoding,
            &mut summary,
        )?;
    }
    // Dial9's per-thread buffers can serialize the close event before the open
    // event. Use event timestamps, not serialized record order, while still
    // binding the pair to the full immutable identity.
    summary.ordered_pairs = summary
        .opens
        .iter()
        .filter(|identity| {
            let Some(opened) = summary.open_timestamps.get(identity) else {
                return false;
            };
            let Some(closed) = summary.close_timestamps.get(identity) else {
                return false;
            };
            opened.iter().min() < closed.iter().max()
        })
        .copied()
        .collect();
    Ok(summary)
}

fn copy_once(
    source: &Path,
    destination: &Path,
    baseline: &Snapshot,
    requirement: &PairRequirement,
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
        if collection.requirement_count > 0
            && collection.matched_requirement_count != collection.requirement_count
        {
            return Err(
                "current dial9 trace does not satisfy every exact flow requirement".to_owned(),
            );
        }
        if collection.requirement_count == 0
            && requirement.flow_id.is_some()
            && collection.required_pair_count != 1
        {
            return Err(
                "current dial9 trace must contain exactly one ordered open/close flow pair matching the legacy requirement".to_owned(),
            );
        }
        if collection.requirement_count == 0
            && requirement.flow_id.is_none()
            && collection.required_pair_count == 0
        {
            return Err(
                "current dial9 bulk diagnostics require at least one ordered open/close flow pair"
                    .to_owned(),
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
    requirement: &PairRequirement,
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
            "usage: dial9_evidence collect <trace-dir> <baseline.json> <destination> [--wait-seconds N] [--flow-id N [--protocol N] | --requirements FILE]; omit selection for bulk diagnostics requiring at least one ordered pair"
                .to_owned(),
        );
    }
    let source = PathBuf::from(&args[0]);
    let baseline = PathBuf::from(&args[1]);
    let destination = PathBuf::from(&args[2]);
    let mut requirement = PairRequirement::default();
    let mut wait = Duration::from_secs(0);
    let mut wait_seen = false;
    let mut index = 3;
    while index < args.len() {
        let option = &args[index];
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {option}"))?;
        match option.as_str() {
            "--wait-seconds" => {
                if wait_seen {
                    return Err("duplicate --wait-seconds option".to_owned());
                }
                wait_seen = true;
                let seconds = parse_canonical_u64(value, "wait_seconds")?;
                if seconds > 600 {
                    return Err("wait_seconds exceeds the 600 second bound".to_owned());
                }
                wait = Duration::from_secs(seconds);
            }
            "--flow-id" => {
                if requirement.flow_id.is_some() {
                    return Err("duplicate --flow-id option".to_owned());
                }
                let flow_id = parse_canonical_u64(value, "flow_id")?;
                if flow_id == 0 {
                    return Err("flow_id must be positive".to_owned());
                }
                requirement.flow_id = Some(flow_id);
            }
            "--protocol" => {
                if requirement.protocol.is_some() {
                    return Err("duplicate --protocol option".to_owned());
                }
                let protocol = u32::try_from(parse_canonical_u64(value, "protocol")?)
                    .map_err(|_| "protocol exceeds u32".to_owned())?;
                if !matches!(protocol, 1 | 2) {
                    return Err("protocol must be 1 (TCP) or 2 (UDP)".to_owned());
                }
                requirement.protocol = Some(protocol);
            }
            "--requirements" => {
                if !requirement.requirements.is_empty() {
                    return Err("duplicate --requirements option".to_owned());
                }
                let (requirements, sha256) = load_requirements(Path::new(value))?;
                requirement.requirements = requirements;
                requirement.requirements_sha256 = Some(sha256);
            }
            _ => return Err(format!("unknown collect option {option:?}")),
        }
        index += 2;
    }
    if !requirement.requirements.is_empty()
        && (requirement.flow_id.is_some() || requirement.protocol.is_some())
    {
        return Err("--requirements cannot be combined with --flow-id/--protocol".to_owned());
    }
    if requirement.flow_id.is_none() && requirement.protocol.is_some() {
        return Err("collect --protocol requires --flow-id".to_owned());
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
            let collection = collect(&source, &baseline, &destination, &requirement, wait)?;
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
    use dial9_trace_format::{
        TraceEvent,
        encoder::Encoder,
        schema::FieldDef,
        types::{FieldType, FieldValue},
    };
    use flate2::{Compression, write::GzEncoder};
    use tempfile::TempDir;

    const PROVIDER_PID: u32 = 9001;
    const PROVIDER_GENERATION: u64 = 17;
    const SOURCE_PID: i64 = 42;

    #[derive(TraceEvent)]
    struct TproxyFlowOpened {
        #[traceevent(timestamp)]
        timestamp_ns: u64,
        provider_pid: u32,
        provider_generation: u64,
        flow_id: u64,
        protocol: u32,
        pid: i64,
    }

    #[derive(TraceEvent)]
    struct TproxyFlowClosed {
        #[traceevent(timestamp)]
        timestamp_ns: u64,
        provider_pid: u32,
        provider_generation: u64,
        flow_id: u64,
        protocol: u32,
        pid: i64,
        reason: u64,
        age_ms: u64,
        bytes_in: u64,
        bytes_out: u64,
    }

    #[derive(TraceEvent)]
    #[traceevent(name = "TproxyFlowClosed")]
    struct IncompleteTproxyFlowClosed {
        #[traceevent(timestamp)]
        timestamp_ns: u64,
        provider_pid: u32,
        provider_generation: u64,
        flow_id: u64,
        protocol: u32,
        pid: i64,
        reason: u64,
        age_ms: u64,
        bytes_in: u64,
    }

    fn trace_bytes(flow_id: u64, protocol: u32, include_close: bool) -> Vec<u8> {
        trace_bytes_for_provider(
            flow_id,
            protocol,
            include_close,
            PROVIDER_PID,
            PROVIDER_GENERATION,
        )
    }

    fn trace_bytes_for_provider(
        flow_id: u64,
        protocol: u32,
        include_close: bool,
        provider_pid: u32,
        provider_generation: u64,
    ) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write(&TproxyFlowOpened {
                timestamp_ns: 1,
                provider_pid,
                provider_generation,
                flow_id,
                protocol,
                pid: SOURCE_PID,
            })
            .unwrap();
        if include_close {
            encoder
                .write(&TproxyFlowClosed {
                    timestamp_ns: 2,
                    provider_pid,
                    provider_generation,
                    flow_id,
                    protocol,
                    pid: SOURCE_PID,
                    reason: 1,
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
                provider_pid: PROVIDER_PID,
                provider_generation: PROVIDER_GENERATION,
                flow_id,
                protocol,
                pid: SOURCE_PID,
                reason: 1,
                age_ms: 1,
                bytes_in: 48,
                bytes_out: 48,
            })
            .unwrap();
        encoder
            .write(&TproxyFlowOpened {
                timestamp_ns: 2,
                provider_pid: PROVIDER_PID,
                provider_generation: PROVIDER_GENERATION,
                flow_id,
                protocol,
                pid: SOURCE_PID,
            })
            .unwrap();
        encoder.finish()
    }

    fn close_trace_bytes(flow_id: u64) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write(&TproxyFlowClosed {
                timestamp_ns: 1,
                provider_pid: PROVIDER_PID,
                provider_generation: PROVIDER_GENERATION,
                flow_id,
                protocol: 2,
                pid: SOURCE_PID,
                reason: 1,
                age_ms: 1,
                bytes_in: 48,
                bytes_out: 48,
            })
            .unwrap();
        encoder.finish()
    }

    fn invalid_close_reason_trace_bytes(flow_id: u64) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write(&TproxyFlowOpened {
                timestamp_ns: 1,
                provider_pid: PROVIDER_PID,
                provider_generation: PROVIDER_GENERATION,
                flow_id,
                protocol: 2,
                pid: SOURCE_PID,
            })
            .unwrap();
        encoder
            .write(&TproxyFlowClosed {
                timestamp_ns: 2,
                provider_pid: PROVIDER_PID,
                provider_generation: PROVIDER_GENERATION,
                flow_id,
                protocol: 2,
                pid: SOURCE_PID,
                reason: 0,
                age_ms: 1,
                bytes_in: 48,
                bytes_out: 48,
            })
            .unwrap();
        encoder.finish()
    }

    fn incomplete_close_trace_bytes(flow_id: u64) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder
            .write(&TproxyFlowOpened {
                timestamp_ns: 1,
                provider_pid: PROVIDER_PID,
                provider_generation: PROVIDER_GENERATION,
                flow_id,
                protocol: 2,
                pid: SOURCE_PID,
            })
            .unwrap();
        encoder
            .write(&IncompleteTproxyFlowClosed {
                timestamp_ns: 2,
                provider_pid: PROVIDER_PID,
                provider_generation: PROVIDER_GENERATION,
                flow_id,
                protocol: 2,
                pid: SOURCE_PID,
                reason: 1,
                age_ms: 1,
                bytes_in: 48,
            })
            .unwrap();
        encoder.finish()
    }

    fn write_trace(directory: &Path, name: &str, bytes: &[u8]) {
        fs::write(directory.join(name), bytes).unwrap();
    }

    fn write_requirements(directory: &Path, generation: u64) -> PathBuf {
        let path = directory.join("requirements.tsv");
        fs::write(
            &path,
            format!(
                "{REQUIREMENTS_HEADER}\necho-0\t{PROVIDER_PID}\t{generation}\t77\t2\t{SOURCE_PID}\t1\t48\t48\t48\t48\n"
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn trace_reader_accepts_the_limit_and_bounds_oversize_reads() {
        const LIMIT: u64 = 32;
        for size in [0, LIMIT - 1, LIMIT] {
            let bytes = vec![0xA5; size as usize];
            assert_eq!(read_bounded_trace(bytes.as_slice(), LIMIT).unwrap(), bytes);
        }

        let mut reader = std::io::Cursor::new(vec![0xA5; 128]);
        let error = read_bounded_trace(&mut reader, LIMIT).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            reader.position(),
            LIMIT + 1,
            "reject without reading the remaining input"
        );
    }

    #[test]
    fn gzip_trace_reader_bounds_the_combined_member_output() {
        let mut encoded = Vec::new();
        for payload in [b"first-member".as_slice(), b"second-member".as_slice()] {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(payload).unwrap();
            encoded.extend(encoder.finish().unwrap());
        }
        let expected = b"first-membersecond-member";
        let read = || MultiGzDecoder::new(encoded.as_slice());
        assert_eq!(
            read_bounded_trace(read(), expected.len() as u64).unwrap(),
            expected
        );
        assert_eq!(
            read_bounded_trace(read(), expected.len() as u64 - 1)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData,
        );
    }

    #[test]
    fn oversized_encoded_trace_is_rejected_before_decoding() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("oversized-trace");
        File::create(&path)
            .unwrap()
            .set_len(MAX_DECODED_TRACE_BYTES + 1)
            .unwrap();
        for encoding in [ArtifactEncoding::Raw, ArtifactEncoding::Gzip] {
            let mut summary = EventSummary::default();
            let error = decode_file(&path, 0, encoding, &mut summary).unwrap_err();
            assert!(error.contains("exceeds the decode limit"));
            assert_eq!(summary.open_count, 0);
            assert_eq!(summary.close_count, 0);
        }
    }

    #[test]
    fn requirements_digest_matches_the_exact_parsed_bytes() {
        let directory = TempDir::new().unwrap();
        let path = write_requirements(directory.path(), PROVIDER_GENERATION);
        let (requirements, sha256) = load_requirements(&path).unwrap();
        assert_eq!(
            sha256,
            "e69c6c670918f74393be0a9f8a083b2952fab3ad7cefe244893229a07070e665"
        );
        assert_eq!(requirements.len(), 1);
        assert_eq!(
            requirements[0].identity.provider_generation,
            PROVIDER_GENERATION
        );

        // A later ordinary load must bind its digest and parsed generation to
        // the new complete contents, without retaining data from the first.
        write_requirements(directory.path(), PROVIDER_GENERATION + 1);
        let (requirements, updated_sha256) = load_requirements(&path).unwrap();
        assert_eq!(
            updated_sha256,
            "34a35a71f46ba6efe0788d9b6a27a25eb40834bac6cdfb61aa952676ec2d2966"
        );
        assert_ne!(updated_sha256, sha256);
        assert_eq!(
            requirements[0].identity.provider_generation,
            PROVIDER_GENERATION + 1
        );
    }

    #[test]
    fn requirements_enforce_the_read_byte_limit() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("requirements.tsv");
        for size in [0, MAX_REQUIREMENTS_BYTES + 1] {
            fs::write(&path, vec![b'x'; size]).unwrap();
            assert!(
                load_requirements(&path)
                    .unwrap_err()
                    .contains("1..=1048576 bytes")
            );
        }

        // At the exact inclusive limit, schema validation must run rather than
        // rejecting the file as oversized. This intentionally has no header.
        let mut at_limit = vec![b'x'; MAX_REQUIREMENTS_BYTES];
        *at_limit.last_mut().unwrap() = b'\n';
        fs::write(&path, at_limit).unwrap();
        assert!(load_requirements(&path).unwrap_err().contains("header"));
    }

    #[test]
    fn requirements_reject_invalid_utf8() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("requirements.tsv");
        fs::write(&path, [0xff, b'\n']).unwrap();
        assert!(load_requirements(&path).unwrap_err().contains("not UTF-8"));
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
            &PairRequirement {
                flow_id: Some(77),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result.required_pair_count, 1);
        assert_eq!(result.required_flow_id, Some(77));
        assert_eq!(result.required_protocol, Some(2));
        assert_eq!(result.required_close_reason, Some(1));
        assert_eq!(result.required_close_reason_name, Some("shutdown"));
        assert_eq!(result.required_close_age_ms, Some(1));
        assert_eq!(result.required_bytes_in, Some(48));
        assert_eq!(result.required_bytes_out, Some(48));
        assert_eq!(result.udp_paired_flow_count, 1);
        assert!(destination.join("trace.9.bin.gz").is_file());
    }

    #[test]
    fn gzip_collection_rejects_duplicate_members_and_trailing_garbage() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&trace_bytes(77, 2, true)).unwrap();
        let member = encoder.finish().unwrap();
        for (label, suffix, expected_error) in [
            (
                "duplicate-member",
                member.as_slice(),
                "does not satisfy every exact flow requirement",
            ),
            ("trailing-garbage", b"CORRUPT TRAILING BYTES", "decompress"),
            (
                "truncated-member",
                &member[..member.len() - 4],
                "decompress",
            ),
        ] {
            let source = TempDir::new().unwrap();
            let output = TempDir::new().unwrap();
            let baseline = snapshot(source.path(), false);
            let mut artifact = member.clone();
            artifact.extend_from_slice(suffix);
            write_trace(source.path(), "trace.1.bin.gz", &artifact);
            let requirements_path = write_requirements(output.path(), PROVIDER_GENERATION);
            let (requirements, sha256) = load_requirements(&requirements_path).unwrap();
            let destination = output.path().join("dial9-traces");
            let error = collect(
                source.path(),
                &baseline,
                &destination,
                &PairRequirement {
                    requirements,
                    requirements_sha256: Some(sha256),
                    ..Default::default()
                },
                Duration::ZERO,
            )
            .expect_err(label);
            assert!(error.contains(expected_error), "{label}: {error}");
            assert!(!destination.exists(), "{label} was published");
        }
    }

    #[test]
    fn gzip_collection_decodes_every_complete_member() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        let baseline = snapshot(source.path(), false);
        let mut artifact = Vec::new();
        for flow_id in [77, 78] {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&trace_bytes(flow_id, 2, true)).unwrap();
            artifact.extend_from_slice(&encoder.finish().unwrap());
        }
        write_trace(source.path(), "trace.1.bin.gz", &artifact);
        let result = collect(
            source.path(),
            &baseline,
            &output.path().join("dial9-traces"),
            &PairRequirement::default(),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result.tproxy_open_count, 2);
        assert_eq!(result.tproxy_close_count, 2);
        assert_eq!(result.paired_flow_count, 2);
    }

    #[test]
    fn parsed_bare_collect_accepts_multiple_arbitrary_pairs() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        let baseline = snapshot(source.path(), false);
        write_trace(source.path(), "trace.1.bin", &trace_bytes(77, 2, true));
        write_trace(source.path(), "trace.2.bin", &trace_bytes(78, 1, true));
        let (source, _, destination, requirement, wait) = parse_collect_args(&[
            source.path().display().to_string(),
            output.path().join("baseline.json").display().to_string(),
            output.path().join("dial9-traces").display().to_string(),
            "--wait-seconds".to_owned(),
            "0".to_owned(),
        ])
        .expect("the soak caller's bare bulk invocation must parse");
        assert!(requirement.flow_id.is_none());
        assert!(requirement.protocol.is_none());
        assert!(requirement.requirements.is_empty());
        let result = collect(&source, &baseline, &destination, &requirement, wait)
            .expect("bulk diagnostics may include multiple arbitrary pairs");
        assert_eq!(result.required_pair_count, 2);
        assert_eq!(result.paired_flow_count, 2);
        assert_eq!(result.udp_paired_flow_count, 1);
        assert_eq!(result.required_close_reason, None);
        assert!(destination.join("trace.1.bin").is_file());
        assert!(destination.join("trace.2.bin").is_file());
    }

    #[test]
    fn parsed_bare_collect_rejects_no_matched_pairs() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        let baseline = snapshot(source.path(), false);
        write_trace(source.path(), "trace.1.bin", &trace_bytes(77, 2, false));
        let (source, _, destination, requirement, wait) = parse_collect_args(&[
            source.path().display().to_string(),
            output.path().join("baseline.json").display().to_string(),
            output.path().join("dial9-traces").display().to_string(),
        ])
        .expect("bare bulk invocation must parse");
        let error = collect(&source, &baseline, &destination, &requirement, wait)
            .expect_err("an unpaired open must not satisfy bulk diagnostics");
        assert!(error.contains("at least one ordered open/close"));
        assert!(!destination.exists(), "unpaired evidence must not publish");
    }

    #[test]
    fn legacy_flow_id_reuse_across_providers_or_generations_is_rejected() {
        for (provider_pid, provider_generation) in [
            (PROVIDER_PID + 1, PROVIDER_GENERATION),
            (PROVIDER_PID, PROVIDER_GENERATION + 1),
        ] {
            let source = TempDir::new().unwrap();
            let output = TempDir::new().unwrap();
            write_trace(source.path(), "trace.1.bin", &trace_bytes(77, 2, true));
            write_trace(
                source.path(),
                "trace.2.bin",
                &trace_bytes_for_provider(77, 2, true, provider_pid, provider_generation),
            );
            let destination = output.path().join("dial9-traces");
            let result = collect(
                source.path(),
                &Snapshot {
                    schema_version: SCHEMA_VERSION,
                    max_index: None,
                    artifacts: vec![],
                    issues: vec![],
                    schema_complete: true,
                },
                &destination,
                &PairRequirement {
                    flow_id: Some(77),
                    protocol: Some(2),
                    ..Default::default()
                },
                Duration::ZERO,
            );
            let error = result.expect_err("two matching legacy pairs are ambiguous");
            assert!(error.contains("exactly one ordered open/close"));
            assert!(!destination.exists(), "ambiguous evidence must not publish");
        }
    }

    #[test]
    fn requirements_bind_provider_generation_source_and_exact_bytes() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(77, 2, true));
        // A provider-wide recorder also sees unrelated ordinary TCP traffic.
        write_trace(source.path(), "trace.2.bin", &trace_bytes(78, 1, true));
        let requirements_path = write_requirements(output.path(), PROVIDER_GENERATION);
        let (requirements, sha256) = load_requirements(&requirements_path).unwrap();
        let result = collect(
            source.path(),
            &Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts: vec![],
                issues: vec![],
                schema_complete: true,
            },
            &output.path().join("dial9-traces"),
            &PairRequirement {
                requirements,
                requirements_sha256: Some(sha256.clone()),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result.requirements_sha256.as_deref(), Some(sha256.as_str()));
        assert_eq!(result.requirement_count, 1);
        assert_eq!(result.matched_requirement_count, 1);
        assert_eq!(result.required_pair_count, 2);
        assert_eq!(result.required_flows.len(), 1);
        assert_eq!(result.required_flows[0].provider_pid, PROVIDER_PID);
        assert_eq!(
            result.required_flows[0].provider_generation,
            PROVIDER_GENERATION
        );
        assert_eq!(result.required_flows[0].bytes_in, 48);
        assert_eq!(result.required_flows[0].bytes_out, 48);
    }

    fn trace_bytes_with_extra_field(
        event_name: &str,
        field_name: &str,
        extra: FieldValue,
        prepend: bool,
    ) -> Vec<u8> {
        let mut fields = vec![
            ("provider_pid", FieldValue::Varint(u64::from(PROVIDER_PID))),
            (
                "provider_generation",
                FieldValue::Varint(PROVIDER_GENERATION),
            ),
            ("flow_id", FieldValue::Varint(77)),
            ("protocol", FieldValue::Varint(2)),
            ("pid", FieldValue::I64(SOURCE_PID)),
        ];
        if event_name == "TproxyFlowClosed" {
            fields.extend([
                ("reason", FieldValue::Varint(1)),
                ("age_ms", FieldValue::Varint(1)),
                ("bytes_in", FieldValue::Varint(48)),
                ("bytes_out", FieldValue::Varint(48)),
            ]);
        }
        fields.insert(if prepend { 0 } else { fields.len() }, (field_name, extra));
        let mut encoder = Encoder::new();
        let schema = encoder
            .register_schema(
                event_name,
                fields
                    .iter()
                    .map(|(name, value)| {
                        let kind = match value {
                            FieldValue::Varint(_) => FieldType::Varint,
                            FieldValue::I64(_) => FieldType::I64,
                            FieldValue::String(_) => FieldType::String,
                            _ => unreachable!("fixture only uses integer and string fields"),
                        };
                        FieldDef::new(*name, kind)
                    })
                    .collect(),
            )
            .unwrap();
        if event_name == "TproxyFlowClosed" {
            encoder
                .write(&TproxyFlowOpened {
                    timestamp_ns: 1,
                    provider_pid: PROVIDER_PID,
                    provider_generation: PROVIDER_GENERATION,
                    flow_id: 77,
                    protocol: 2,
                    pid: SOURCE_PID,
                })
                .unwrap();
        }
        encoder
            .write_event(
                &schema,
                if event_name == "TproxyFlowOpened" {
                    1
                } else {
                    2
                },
                &fields
                    .into_iter()
                    .map(|(_, value)| value)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        if event_name == "TproxyFlowOpened" {
            encoder
                .write(&TproxyFlowClosed {
                    timestamp_ns: 2,
                    provider_pid: PROVIDER_PID,
                    provider_generation: PROVIDER_GENERATION,
                    flow_id: 77,
                    protocol: 2,
                    pid: SOURCE_PID,
                    reason: 1,
                    age_ms: 1,
                    bytes_in: 48,
                    bytes_out: 48,
                })
                .unwrap();
        }
        encoder.finish()
    }

    fn collect_extra_field_fixture(trace: &[u8], destination: &Path) -> Result<Collection, String> {
        let source = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", trace);
        let requirements_path = write_requirements(source.path(), PROVIDER_GENERATION);
        let (requirements, sha256) = load_requirements(&requirements_path).unwrap();
        collect(
            source.path(),
            &Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts: vec![],
                issues: vec![],
                schema_complete: true,
            },
            destination,
            &PairRequirement {
                requirements,
                requirements_sha256: Some(sha256),
                ..Default::default()
            },
            Duration::ZERO,
        )
    }

    fn assert_duplicate_required_fields_rejected(wrong_type: bool) {
        for event_name in ["TproxyFlowOpened", "TproxyFlowClosed"] {
            let fields = if event_name == "TproxyFlowOpened" {
                &[
                    "provider_pid",
                    "provider_generation",
                    "flow_id",
                    "protocol",
                    "pid",
                ][..]
            } else {
                &[
                    "provider_pid",
                    "provider_generation",
                    "flow_id",
                    "protocol",
                    "pid",
                    "reason",
                    "age_ms",
                    "bytes_in",
                    "bytes_out",
                ][..]
            };
            for field in fields {
                for prepend in [true, false] {
                    let extra = if wrong_type {
                        FieldValue::String("contradictory evidence".to_owned())
                    } else if *field == "pid" {
                        FieldValue::I64(SOURCE_PID + 1)
                    } else {
                        FieldValue::Varint(96)
                    };
                    let trace = trace_bytes_with_extra_field(event_name, field, extra, prepend);
                    let output = TempDir::new().unwrap();
                    let destination = output.path().join("dial9-traces");
                    let error = collect_extra_field_fixture(&trace, &destination)
                        .expect_err("duplicate required fields must not qualify as evidence");
                    assert!(
                        error.contains("duplicate required field"),
                        "{event_name}.{field} (wrong_type={wrong_type}, prepend={prepend}): {error}"
                    );
                    assert!(!destination.exists(), "ambiguous evidence must not publish");
                }
            }
        }
    }

    #[test]
    fn duplicate_required_fields_with_conflicting_values_are_rejected() {
        assert_duplicate_required_fields_rejected(false);
    }

    #[test]
    fn duplicate_required_fields_with_wrong_types_are_rejected() {
        assert_duplicate_required_fields_rejected(true);
    }

    #[test]
    fn unrecognized_extension_fields_remain_supported() {
        for event_name in ["TproxyFlowOpened", "TproxyFlowClosed"] {
            let trace = trace_bytes_with_extra_field(
                event_name,
                "future_extension",
                FieldValue::String("future diagnostic".to_owned()),
                false,
            );
            let output = TempDir::new().unwrap();
            let destination = output.path().join("dial9-traces");
            let collection = collect_extra_field_fixture(&trace, &destination).unwrap();
            assert_eq!(collection.matched_requirement_count, 1);
            assert!(destination.is_dir());
        }
    }

    #[test]
    fn wrong_generation_and_duplicate_requirements_are_rejected() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(77, 2, true));
        let requirements_path = write_requirements(output.path(), PROVIDER_GENERATION + 1);
        let (requirements, sha256) = load_requirements(&requirements_path).unwrap();
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
            &PairRequirement {
                requirements,
                requirements_sha256: Some(sha256),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("every exact flow requirement"));

        let duplicate = output.path().join("duplicate.tsv");
        let row = format!(
            "echo-0\t{PROVIDER_PID}\t{PROVIDER_GENERATION}\t77\t2\t{SOURCE_PID}\t1\t48\t48\t48\t48\n"
        );
        fs::write(&duplicate, format!("{REQUIREMENTS_HEADER}\n{row}{row}")).unwrap();
        assert!(
            load_requirements(&duplicate)
                .unwrap_err()
                .contains("duplicate")
        );

        let reused_flow_id = output.path().join("reused-flow-id.tsv");
        let second = format!(
            "echo-1\t{PROVIDER_PID}\t{PROVIDER_GENERATION}\t77\t2\t{}\t1\t48\t48\t48\t48\n",
            SOURCE_PID + 1
        );
        fs::write(
            &reused_flow_id,
            format!("{REQUIREMENTS_HEADER}\n{row}{second}"),
        )
        .unwrap();
        assert!(
            load_requirements(&reused_flow_id)
                .unwrap_err()
                .contains("duplicate")
        );
    }

    #[test]
    fn collect_cli_rejects_ambiguous_or_unbounded_legacy_arguments() {
        for tail in [
            vec!["--protocol", "2"],
            vec!["--flow-id", "01"],
            vec!["--flow-id", "7", "--flow-id", "8"],
            vec!["--flow-id", "7", "--protocol", "3"],
            vec!["--flow-id", "7", "--wait-seconds", "601"],
            vec![
                "--flow-id",
                "7",
                "--wait-seconds",
                "1",
                "--wait-seconds",
                "2",
            ],
        ] {
            let mut args = vec!["source", "baseline", "destination"];
            args.extend(tail);
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(parse_collect_args(&args).is_err(), "accepted {args:?}");
        }
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
            &PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
    }

    #[test]
    fn close_with_unknown_reason_is_rejected_instead_of_counted() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(
            source.path(),
            "trace.1.bin",
            &invalid_close_reason_trace_bytes(7),
        );
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
            &PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("lacks valid"));
    }

    #[test]
    fn close_missing_a_required_evidence_field_is_rejected() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(
            source.path(),
            "trace.1.bin",
            &incomplete_close_trace_bytes(7),
        );
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
            &PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("lacks valid"));
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
            &PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
                ..Default::default()
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
    fn open_and_close_across_ordered_segment_rotation_are_a_pair() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(7, 2, false));
        write_trace(source.path(), "trace.2.bin", &close_trace_bytes(7));
        let result = collect(
            source.path(),
            &Snapshot {
                schema_version: SCHEMA_VERSION,
                max_index: None,
                artifacts: vec![],
                issues: vec![],
                schema_complete: true,
            },
            &output.path().join("dial9-traces"),
            &PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result.required_pair_count, 1);
        assert_eq!(result.required_close_reason_name, Some("shutdown"));
    }

    #[test]
    fn duplicate_open_across_rotated_segments_is_rejected() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(7, 2, false));
        write_trace(source.path(), "trace.2.bin", &trace_bytes(7, 2, true));
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
            &PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
    }

    #[test]
    fn duplicate_close_across_rotated_segments_is_rejected() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        write_trace(source.path(), "trace.1.bin", &trace_bytes(7, 2, true));
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
            &PairRequirement {
                flow_id: Some(7),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
    }

    #[test]
    fn close_reason_names_cover_the_sealed_trace_contract() {
        assert_eq!(close_reason_name(1), Some("shutdown"));
        assert_eq!(close_reason_name(14), Some("service_panic"));
        assert_eq!(close_reason_name(0), None);
        assert_eq!(close_reason_name(15), None);
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
            &PairRequirement {
                flow_id: Some(11),
                protocol: Some(2),
                ..Default::default()
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("ordered open/close"));
    }
}
