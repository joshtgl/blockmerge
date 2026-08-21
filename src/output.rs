//! Rendering and safely writing generated blocklist files.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use reqwest::blocking::Client;

use crate::config::Config;
use crate::generation::{
    GeneratedBlocklistOutputs, RefreshContext, retrieve_blocklists,
    retrieve_blocklists_with_resilience,
};
use crate::ranges::IpRanges;

const TIMESTAMP_HEADER_PREFIX: &str = "# Blockmerge updated at ";
const COMPARISON_BUFFER_SIZE: usize = 64 * 1024;

/// Whether each directional output was replaced during a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputWriteResult {
    pub inbound_updated: bool,
    pub outbound_updated: bool,
}

/// Format networks as one CIDR per line and return the entry count.
pub fn format_blocklist_output(blocklist: &IpRanges) -> (String, usize) {
    let mut output = String::new();
    let mut final_entries = 0;
    for network in blocklist.ipv4_networks() {
        output.push_str(&network.to_string());
        output.push('\n');
        final_entries += 1;
    }
    for network in blocklist.ipv6_networks() {
        output.push_str(&network.to_string());
        output.push('\n');
        final_entries += 1;
    }
    (output, final_entries)
}

/// Generate rendered inbound and outbound blocklists.
pub fn generate_blocklist_outputs(
    client: &Client,
    config: &Config,
) -> Result<GeneratedBlocklistOutputs, Box<dyn std::error::Error>> {
    let retrieved = retrieve_blocklists(client, config)?;
    let (inbound_output, inbound_entries) = format_blocklist_output(&retrieved.blocklists.inbound);
    let (outbound_output, outbound_entries) =
        format_blocklist_output(&retrieved.blocklists.outbound);
    Ok(GeneratedBlocklistOutputs {
        inbound_output,
        outbound_output,
        inbound_entries,
        outbound_entries,
        successful_sources: retrieved.successful_sources,
        source_outcomes: retrieved.source_outcomes,
    })
}

/// Generate rendered blocklists using fresh and eligible cached source bodies.
pub fn generate_blocklist_outputs_with_resilience(
    client: &Client,
    config: &Config,
    context: &mut RefreshContext,
) -> Result<GeneratedBlocklistOutputs, Box<dyn std::error::Error>> {
    let retrieved = retrieve_blocklists_with_resilience(client, config, context)?;
    let (inbound_output, inbound_entries) = format_blocklist_output(&retrieved.blocklists.inbound);
    let (outbound_output, outbound_entries) =
        format_blocklist_output(&retrieved.blocklists.outbound);
    Ok(GeneratedBlocklistOutputs {
        inbound_output,
        outbound_output,
        inbound_entries,
        outbound_entries,
        successful_sources: retrieved.successful_sources,
        source_outcomes: retrieved.source_outcomes,
    })
}

/// Derive inbound and outbound paths from a base output path.
pub fn directional_output_paths(base: &Path) -> (PathBuf, PathBuf) {
    let parent = base.parent().unwrap_or_else(|| Path::new(""));
    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("blocklist_output");
    let extension = base.extension().and_then(|extension| extension.to_str());
    let inbound = match extension {
        Some(extension) => parent.join(format!("{stem}_inbound.{extension}")),
        None => parent.join(format!("{stem}_inbound")),
    };
    let outbound = match extension {
        Some(extension) => parent.join(format!("{stem}_outbound.{extension}")),
        None => parent.join(format!("{stem}_outbound")),
    };
    (inbound, outbound)
}

/// Return the fixed filenames used by the web server.
pub fn web_asset_output_paths(root_dir: &Path) -> (PathBuf, PathBuf) {
    (root_dir.join("inbound.txt"), root_dir.join("outbound.txt"))
}

/// Atomically replace both generated output files, cleaning temporary files after failures.
pub fn write_generated_outputs_atomic(
    inbound_path: &Path,
    outbound_path: &Path,
    outputs: &GeneratedBlocklistOutputs,
) -> Result<(), Box<dyn std::error::Error>> {
    let inbound_temp = temp_output_path(inbound_path);
    let outbound_temp = temp_output_path(outbound_path);
    if let Err(error) = write_atomic_temp(&inbound_temp, &outputs.inbound_output) {
        cleanup_temp_file(&inbound_temp);
        return Err(error);
    }
    if let Err(error) = write_atomic_temp(&outbound_temp, &outputs.outbound_output) {
        cleanup_temp_file(&inbound_temp);
        cleanup_temp_file(&outbound_temp);
        return Err(error);
    }
    if let Err(error) = fs::rename(&inbound_temp, inbound_path) {
        cleanup_temp_file(&inbound_temp);
        cleanup_temp_file(&outbound_temp);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&outbound_temp, outbound_path) {
        cleanup_temp_file(&outbound_temp);
        return Err(error.into());
    }
    Ok(())
}

/// Write only outputs whose blocklist payload or configured metadata differs.
///
/// A Blockmerge timestamp header is deliberately ignored during comparison, so
/// an unchanged list retains its previous update timestamp and modification
/// time.
pub fn write_generated_outputs_if_changed(
    inbound_path: &Path,
    outbound_path: &Path,
    outputs: &GeneratedBlocklistOutputs,
    timestamp_header: bool,
) -> Result<OutputWriteResult, Box<dyn std::error::Error>> {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let inbound_updated = write_output_if_changed(
        inbound_path,
        &outputs.inbound_output,
        timestamp_header,
        &timestamp,
    )?;
    let outbound_updated = write_output_if_changed(
        outbound_path,
        &outputs.outbound_output,
        timestamp_header,
        &timestamp,
    )?;
    Ok(OutputWriteResult {
        inbound_updated,
        outbound_updated,
    })
}

/// Generate and atomically write both directional blocklists.
pub fn generate_and_write_blocklists(
    client: &Client,
    config: &Config,
    inbound_path: &Path,
    outbound_path: &Path,
) -> Result<GeneratedBlocklistOutputs, Box<dyn std::error::Error>> {
    let outputs = generate_blocklist_outputs(client, config)?;
    write_generated_outputs_if_changed(
        inbound_path,
        outbound_path,
        &outputs,
        config.output.timestamp_header,
    )?;
    Ok(outputs)
}

/// Generate and write blocklists using fresh and eligible cached source bodies.
pub fn generate_and_write_blocklists_with_resilience(
    client: &Client,
    config: &Config,
    inbound_path: &Path,
    outbound_path: &Path,
    context: &mut RefreshContext,
) -> Result<GeneratedBlocklistOutputs, Box<dyn std::error::Error>> {
    let outputs = generate_blocklist_outputs_with_resilience(client, config, context)?;
    write_generated_outputs_if_changed(
        inbound_path,
        outbound_path,
        &outputs,
        config.output.timestamp_header,
    )?;
    Ok(outputs)
}

/// Refresh the directional assets served by the web binary.
pub fn refresh_web_assets(
    client: &Client,
    config: &Config,
    root_dir: &Path,
) -> Result<GeneratedBlocklistOutputs, Box<dyn std::error::Error>> {
    let (inbound_path, outbound_path) = web_asset_output_paths(root_dir);
    generate_and_write_blocklists(client, config, &inbound_path, &outbound_path)
}

/// Refresh web assets using fresh and eligible cached source bodies.
pub fn refresh_web_assets_with_resilience(
    client: &Client,
    config: &Config,
    root_dir: &Path,
    context: &mut RefreshContext,
) -> Result<GeneratedBlocklistOutputs, Box<dyn std::error::Error>> {
    let (inbound_path, outbound_path) = web_asset_output_paths(root_dir);
    generate_and_write_blocklists_with_resilience(
        client,
        config,
        &inbound_path,
        &outbound_path,
        context,
    )
}

fn write_atomic_temp(path: &Path, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    fs::write(path, content)?;
    Ok(())
}

fn write_output_if_changed(
    path: &Path,
    payload: &str,
    timestamp_header: bool,
    timestamp: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    match existing_output_matches(path, payload, timestamp_header) {
        Ok(true) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return write_new_output(path, payload, timestamp_header, timestamp);
        }
        Err(error) => return Err(error.into()),
        Ok(false) => {}
    }

    write_new_output(path, payload, timestamp_header, timestamp)
}

/// Compare an existing output file with a generated payload without loading the
/// existing file into memory.
fn existing_output_matches(
    path: &Path,
    payload: &str,
    timestamp_header: bool,
) -> std::io::Result<bool> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(COMPARISON_BUFFER_SIZE, file);
    let mut prefix = [0; TIMESTAMP_HEADER_PREFIX.len()];
    let prefix_length = read_prefix(&mut reader, &mut prefix)?;
    let header_state = if prefix_length == prefix.len()
        && prefix.as_slice() == TIMESTAMP_HEADER_PREFIX.as_bytes()
    {
        if consume_timestamp_header(&mut reader)? {
            TimestampHeaderState::Present
        } else {
            TimestampHeaderState::Malformed
        }
    } else {
        TimestampHeaderState::Absent
    };
    if header_state == TimestampHeaderState::Malformed {
        return Ok(false);
    }
    let has_timestamp_header = header_state == TimestampHeaderState::Present;

    if has_timestamp_header != timestamp_header {
        return Ok(false);
    }

    let mut payload_offset = 0;
    if !has_timestamp_header
        && !compare_chunk(
            &prefix[..prefix_length],
            payload.as_bytes(),
            &mut payload_offset,
        )
    {
        return Ok(false);
    }

    let mut buffer = [0; COMPARISON_BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(payload_offset == payload.len());
        }
        if !compare_chunk(&buffer[..read], payload.as_bytes(), &mut payload_offset) {
            return Ok(false);
        }
    }
}

fn read_prefix(reader: &mut BufReader<File>, prefix: &mut [u8]) -> std::io::Result<usize> {
    let mut prefix_length = 0;
    while prefix_length < prefix.len() {
        let read = reader.read(&mut prefix[prefix_length..])?;
        if read == 0 {
            break;
        }
        prefix_length += read;
    }
    Ok(prefix_length)
}

/// Consume the remainder of a recognized timestamp line without allocating for
/// the line. Returns false for an unterminated header.
fn consume_timestamp_header(reader: &mut BufReader<File>) -> std::io::Result<bool> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(false);
        }
        if let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            reader.consume(newline + 1);
            return Ok(true);
        }
        let consumed = buffer.len();
        reader.consume(consumed);
    }
}

fn compare_chunk(chunk: &[u8], payload: &[u8], payload_offset: &mut usize) -> bool {
    let Some(end) = payload_offset.checked_add(chunk.len()) else {
        return false;
    };
    let Some(payload_chunk) = payload.get(*payload_offset..end) else {
        return false;
    };
    if chunk != payload_chunk {
        return false;
    }
    *payload_offset += chunk.len();
    true
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TimestampHeaderState {
    Absent,
    Present,
    Malformed,
}

fn write_new_output(
    path: &Path,
    payload: &str,
    timestamp_header: bool,
    timestamp: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let temporary_path = temp_output_path(path);
    if let Err(error) = write_output_temp(&temporary_path, payload, timestamp_header, timestamp) {
        cleanup_temp_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        cleanup_temp_file(&temporary_path);
        return Err(error.into());
    }
    Ok(true)
}

fn write_output_temp(
    path: &Path,
    payload: &str,
    timestamp_header: bool,
    timestamp: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut writer = BufWriter::new(File::create(path)?);
    if timestamp_header {
        writer.write_all(TIMESTAMP_HEADER_PREFIX.as_bytes())?;
        writer.write_all(timestamp.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    writer.write_all(payload.as_bytes())?;
    writer.flush()?;
    Ok(())
}

fn temp_output_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("blockmerge-output")
    ))
}

fn cleanup_temp_file(path: &Path) {
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ScheduleConfig, WebConfig};
    use crate::generation::GeneratedBlocklistOutputs;
    use crate::source::{Direction, ListType, SourceConfig};
    use static_web_server::settings::file as sws_file;
    use tempfile::tempdir;

    fn inline_source(name: &str, direction: Direction, entries: &[&str]) -> SourceConfig {
        SourceConfig {
            name: name.to_string(),
            url: None,
            list_type: ListType::Blocklist,
            comment_char: "#".to_string(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: Some(entries.iter().map(ToString::to_string).collect()),
            rate_limited: false,
            enabled: true,
            direction,
        }
    }

    #[test]
    fn derives_directional_paths() {
        let (inbound, outbound) = directional_output_paths(Path::new("/tmp/blocklist.txt"));

        assert_eq!(inbound, PathBuf::from("/tmp/blocklist_inbound.txt"));
        assert_eq!(outbound, PathBuf::from("/tmp/blocklist_outbound.txt"));
        assert_eq!(
            web_asset_output_paths(Path::new("/tmp/assets")),
            (
                PathBuf::from("/tmp/assets/inbound.txt"),
                PathBuf::from("/tmp/assets/outbound.txt")
            )
        );
    }

    #[test]
    fn atomically_writes_both_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let inbound = directory.path().join("inbound.txt");
        let outbound = directory.path().join("outbound.txt");
        let outputs = GeneratedBlocklistOutputs {
            inbound_output: "192.0.2.0/24\n".to_string(),
            outbound_output: "2001:db8::/32\n".to_string(),
            inbound_entries: 1,
            outbound_entries: 1,
            successful_sources: Vec::new(),
            source_outcomes: Vec::new(),
        };

        write_generated_outputs_atomic(&inbound, &outbound, &outputs).unwrap();

        assert_eq!(fs::read_to_string(inbound).unwrap(), outputs.inbound_output);
        assert_eq!(
            fs::read_to_string(outbound).unwrap(),
            outputs.outbound_output
        );
    }

    #[test]
    fn generates_and_writes_directional_inline_sources() {
        let config = Config {
            blocklists: vec![
                inline_source("inbound", Direction::Inbound, &["192.0.2.0/24"]),
                inline_source("outbound", Direction::Outbound, &["198.51.100.0/24"]),
            ],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let directory = tempfile::tempdir().unwrap();
        let inbound = directory.path().join("inbound.txt");
        let outbound = directory.path().join("outbound.txt");

        let outputs =
            generate_and_write_blocklists(&Client::new(), &config, &inbound, &outbound).unwrap();

        assert_eq!(outputs.inbound_entries, 1);
        assert_eq!(outputs.outbound_entries, 1);
        let inbound_contents = fs::read_to_string(inbound).unwrap();
        assert!(inbound_contents.starts_with(TIMESTAMP_HEADER_PREFIX));
        assert!(inbound_contents.ends_with("192.0.2.0/24\n"));
        assert!(
            fs::read_to_string(outbound)
                .unwrap()
                .ends_with("198.51.100.0/24\n")
        );
    }

    #[test]
    fn timestamped_outputs_are_not_rewritten_when_payloads_match() {
        let directory = tempfile::tempdir().unwrap();
        let inbound = directory.path().join("inbound.txt");
        let outbound = directory.path().join("outbound.txt");
        let outputs = GeneratedBlocklistOutputs {
            inbound_output: "192.0.2.0/24\n".to_string(),
            outbound_output: "2001:db8::/32\n".to_string(),
            inbound_entries: 1,
            outbound_entries: 1,
            successful_sources: Vec::new(),
            source_outcomes: Vec::new(),
        };

        assert_eq!(
            write_generated_outputs_if_changed(&inbound, &outbound, &outputs, true).unwrap(),
            OutputWriteResult {
                inbound_updated: true,
                outbound_updated: true,
            }
        );
        let original_inbound = fs::read_to_string(&inbound).unwrap();
        assert!(original_inbound.starts_with(TIMESTAMP_HEADER_PREFIX));
        let timestamp = original_inbound
            .trim_end()
            .strip_prefix(TIMESTAMP_HEADER_PREFIX)
            .unwrap()
            .split('\n')
            .next()
            .unwrap();
        assert!(chrono::DateTime::parse_from_rfc3339(timestamp).is_ok());

        assert_eq!(
            write_generated_outputs_if_changed(&inbound, &outbound, &outputs, true).unwrap(),
            OutputWriteResult {
                inbound_updated: false,
                outbound_updated: false,
            }
        );
        assert_eq!(fs::read_to_string(&inbound).unwrap(), original_inbound);

        let changed_outputs = GeneratedBlocklistOutputs {
            outbound_output: "2001:db8:1::/48\n".to_string(),
            ..outputs
        };
        assert_eq!(
            write_generated_outputs_if_changed(&inbound, &outbound, &changed_outputs, true)
                .unwrap(),
            OutputWriteResult {
                inbound_updated: false,
                outbound_updated: true,
            }
        );
    }

    #[test]
    fn compares_payloads_across_multiple_streaming_chunks() {
        let directory = tempfile::tempdir().unwrap();
        let inbound = directory.path().join("inbound.txt");
        let outbound = directory.path().join("outbound.txt");
        let inbound_payload = format!("{}\n", "1".repeat(COMPARISON_BUFFER_SIZE * 2));
        let outputs = GeneratedBlocklistOutputs {
            inbound_output: inbound_payload.clone(),
            outbound_output: "2001:db8::/32\n".to_string(),
            inbound_entries: 1,
            outbound_entries: 1,
            successful_sources: Vec::new(),
            source_outcomes: Vec::new(),
        };

        write_generated_outputs_if_changed(&inbound, &outbound, &outputs, true).unwrap();
        assert_eq!(
            write_generated_outputs_if_changed(&inbound, &outbound, &outputs, true).unwrap(),
            OutputWriteResult {
                inbound_updated: false,
                outbound_updated: false,
            }
        );

        let mut changed_payload = inbound_payload;
        changed_payload.replace_range(COMPARISON_BUFFER_SIZE..COMPARISON_BUFFER_SIZE + 1, "2");
        let changed_outputs = GeneratedBlocklistOutputs {
            inbound_output: changed_payload,
            ..outputs
        };
        assert_eq!(
            write_generated_outputs_if_changed(&inbound, &outbound, &changed_outputs, true)
                .unwrap(),
            OutputWriteResult {
                inbound_updated: true,
                outbound_updated: false,
            }
        );
    }

    #[test]
    fn rewrites_an_unterminated_timestamp_header() {
        let directory = tempfile::tempdir().unwrap();
        let inbound = directory.path().join("inbound.txt");
        let outbound = directory.path().join("outbound.txt");
        fs::write(&inbound, format!("{TIMESTAMP_HEADER_PREFIX}unterminated")).unwrap();
        let outputs = GeneratedBlocklistOutputs {
            inbound_output: "192.0.2.0/24\n".to_string(),
            outbound_output: "2001:db8::/32\n".to_string(),
            inbound_entries: 1,
            outbound_entries: 1,
            successful_sources: Vec::new(),
            source_outcomes: Vec::new(),
        };

        let result =
            write_generated_outputs_if_changed(&inbound, &outbound, &outputs, true).unwrap();
        assert!(result.inbound_updated);
        assert!(
            fs::read_to_string(inbound)
                .unwrap()
                .ends_with(&outputs.inbound_output)
        );
    }

    #[test]
    fn disabling_timestamp_headers_rewrites_existing_outputs_without_them() {
        let directory = tempfile::tempdir().unwrap();
        let inbound = directory.path().join("inbound.txt");
        let outbound = directory.path().join("outbound.txt");
        let outputs = GeneratedBlocklistOutputs {
            inbound_output: "192.0.2.0/24\n".to_string(),
            outbound_output: "2001:db8::/32\n".to_string(),
            inbound_entries: 1,
            outbound_entries: 1,
            successful_sources: Vec::new(),
            source_outcomes: Vec::new(),
        };

        write_generated_outputs_if_changed(&inbound, &outbound, &outputs, true).unwrap();
        assert_eq!(
            write_generated_outputs_if_changed(&inbound, &outbound, &outputs, false).unwrap(),
            OutputWriteResult {
                inbound_updated: true,
                outbound_updated: true,
            }
        );
        assert_eq!(fs::read_to_string(inbound).unwrap(), outputs.inbound_output);
        assert_eq!(
            fs::read_to_string(outbound).unwrap(),
            outputs.outbound_output
        );
    }

    #[test]
    fn test_directional_output_paths_include_direction_suffixes() {
        let (inbound, outbound) = directional_output_paths(Path::new("/tmp/blocklist_output.txt"));

        assert_eq!(inbound, PathBuf::from("/tmp/blocklist_output_inbound.txt"));
        assert_eq!(
            outbound,
            PathBuf::from("/tmp/blocklist_output_outbound.txt")
        );
    }

    #[test]
    fn test_web_asset_output_paths_are_stable() {
        let (inbound, outbound) = web_asset_output_paths(Path::new("/tmp/web-assets"));

        assert_eq!(inbound, PathBuf::from("/tmp/web-assets/inbound.txt"));
        assert_eq!(outbound, PathBuf::from("/tmp/web-assets/outbound.txt"));
    }

    #[test]
    fn test_generate_and_write_blocklists_writes_directional_outputs() {
        let config = Config {
            blocklists: vec![
                crate::test_support::inline_source(
                    "inbound",
                    ListType::Blocklist,
                    vec!["8.8.8.0/24"],
                ),
                {
                    let mut source = crate::test_support::inline_source(
                        "outbound",
                        ListType::Blocklist,
                        vec!["9.9.9.0/24"],
                    );
                    source.direction = Direction::Outbound;
                    source
                },
            ],
            allowlists: vec![crate::test_support::inline_source(
                "private-ranges",
                ListType::Allowlist,
                vec!["10.0.0.0/8"],
            )],
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();
        let temp_dir = tempdir().unwrap();
        let inbound_path = temp_dir.path().join("inbound.txt");
        let outbound_path = temp_dir.path().join("outbound.txt");

        let outputs =
            generate_and_write_blocklists(&client, &config, &inbound_path, &outbound_path).unwrap();

        assert_eq!(outputs.inbound_entries, 1);
        assert_eq!(outputs.outbound_entries, 1);
        assert!(
            fs::read_to_string(inbound_path)
                .unwrap()
                .ends_with("8.8.8.0/24\n")
        );
        assert!(
            fs::read_to_string(outbound_path)
                .unwrap()
                .ends_with("9.9.9.0/24\n")
        );
    }

    #[test]
    fn test_write_generated_outputs_atomic_keeps_existing_files_when_second_write_fails() {
        let temp_dir = tempdir().unwrap();
        let inbound_path = temp_dir.path().join("inbound.txt");
        fs::write(&inbound_path, "existing inbound\n").unwrap();
        let outbound_parent = temp_dir.path().join("not-a-directory");
        fs::write(&outbound_parent, "file").unwrap();
        let outbound_path = outbound_parent.join("outbound.txt");

        let outputs = GeneratedBlocklistOutputs {
            inbound_output: "new inbound\n".to_string(),
            outbound_output: "new outbound\n".to_string(),
            inbound_entries: 1,
            outbound_entries: 1,
            successful_sources: Vec::new(),
            source_outcomes: Vec::new(),
        };

        let err =
            write_generated_outputs_atomic(&inbound_path, &outbound_path, &outputs).unwrap_err();

        assert!(!err.to_string().is_empty());
        assert_eq!(
            fs::read_to_string(inbound_path).unwrap(),
            "existing inbound\n"
        );
        assert!(!temp_dir.path().join(".inbound.txt.tmp").exists());
    }

    #[test]
    fn test_refresh_web_assets_smoke_test_with_inline_sources() {
        let config = Config {
            blocklists: vec![
                crate::test_support::inline_source("inbound", ListType::Blocklist, vec!["8.8.8.8"]),
                {
                    let mut source = crate::test_support::inline_source(
                        "outbound",
                        ListType::Blocklist,
                        vec!["2001:4860::8888"],
                    );
                    source.direction = Direction::Outbound;
                    source
                },
            ],
            allowlists: Vec::new(),
            geoip: None,
            web: Some(WebConfig {
                general: Some(sws_file::General {
                    host: Some("127.0.0.1".to_string()),
                    port: Some(8080),
                    root: Some(PathBuf::from("web-assets")),
                    log_level: None,
                    log_with_ansi: None,
                    cache_control_headers: None,
                    compression_static: None,
                    page404: None,
                    page50x: None,
                    security_headers: None,
                    cors_allow_origins: None,
                    cors_allow_headers: None,
                    cors_expose_headers: None,
                    index_files: None,
                    directory_listing: Some(false),
                    directory_listing_order: None,
                    directory_listing_format: None,
                    fd: None,
                    threads_multiplier: None,
                    max_blocking_threads: None,
                    grace_period: None,
                    log_remote_address: None,
                    log_x_real_ip: None,
                    log_forwarded_for: None,
                    trusted_proxies: None,
                    redirect_trailing_slash: None,
                    ignore_hidden_files: None,
                    disable_symlinks: None,
                    use_relative_root: None,
                    health: None,
                    accept_markdown: None,
                    text_charset: None,
                    maintenance_mode: None,
                    maintenance_mode_status: None,
                    maintenance_mode_file: None,
                }),
                advanced: None,
            }),
            output: Default::default(),
            schedule: Some(ScheduleConfig {
                interval: Some("15m".to_string()),
                cron: None,
                run_on_startup: true,
            }),
            resilience: Default::default(),
        };
        let client = Client::new();
        let temp_dir = tempdir().unwrap();

        let outputs = refresh_web_assets(&client, &config, temp_dir.path()).unwrap();

        assert_eq!(outputs.inbound_entries, 1);
        assert_eq!(outputs.outbound_entries, 1);
        assert!(temp_dir.path().join("inbound.txt").exists());
        assert!(temp_dir.path().join("outbound.txt").exists());
    }
}
