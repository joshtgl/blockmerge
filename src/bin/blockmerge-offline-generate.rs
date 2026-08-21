use std::fs;
use std::path::{Path, PathBuf};

use blockmerge::{
    config::{Config, load_config},
    offline::{DownloadManifestEntry, load_manifest, sha256_hex},
    output::{directional_output_paths, format_blocklist_output},
    ranges::IpRangeAccumulator,
    source::{Direction, ListType},
};
use clap::Parser;

/// Generate blocklist output from previously downloaded offline blocklists.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file used to parse the offline blocklists
    #[arg(
        long,
        default_value = "blockmerge.toml",
        env = "BLOCKMERGE_CONFIG_FILE"
    )]
    config: String,

    /// Directory containing downloaded blocklists and manifest.json
    #[arg(long, short = 'i')]
    input_dir: PathBuf,

    /// Path where the merged blocklist output should be written
    #[arg(long, short = 'o', default_value = "blocklist_output.txt")]
    output: PathBuf,

    /// Process a single offline list file instead of every entry in manifest.json
    #[arg(long)]
    list_file: Option<PathBuf>,

    /// Include manifest entries whose config source is currently disabled
    #[arg(long)]
    include_disabled: bool,
}

#[derive(Debug)]
struct OfflineInput {
    name: String,
    path: PathBuf,
    expected_sha256: Option<String>,
}

#[derive(Debug)]
struct ParsedSourceEntries {
    direction: Direction,
    list_type: ListType,
    entries: IpRangeAccumulator,
}

fn source_name_from_file(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(ToOwned::to_owned)
}

fn matching_manifest_entry<'a>(
    manifest: &'a [DownloadManifestEntry],
    input_dir: &Path,
    list_file: &Path,
) -> Option<&'a DownloadManifestEntry> {
    manifest.iter().find(|entry| {
        let manifest_path = input_dir.join(&entry.file);
        Path::new(&entry.file) == list_file || manifest_path == list_file
    })
}

fn resolve_single_list_file(
    input_dir: &Path,
    manifest: &[DownloadManifestEntry],
    list_file: &Path,
) -> Result<OfflineInput, Box<dyn std::error::Error>> {
    let source_path = if list_file.exists() {
        list_file.to_path_buf()
    } else {
        input_dir.join(list_file)
    };

    if let Some(entry) = matching_manifest_entry(manifest, input_dir, &source_path).or_else(|| {
        list_file.file_name().and_then(|file_name| {
            matching_manifest_entry(manifest, input_dir, Path::new(file_name))
        })
    }) {
        return Ok(OfflineInput {
            name: entry.name.clone(),
            path: source_path,
            expected_sha256: Some(entry.sha256.clone()),
        });
    }

    let Some(name) = source_name_from_file(&source_path) else {
        return Err(format!(
            "could not infer config source name from {}",
            source_path.display()
        )
        .into());
    };

    Ok(OfflineInput {
        name,
        path: source_path,
        expected_sha256: None,
    })
}

fn manifest_input(input_dir: &Path, entry: DownloadManifestEntry) -> OfflineInput {
    OfflineInput {
        name: entry.name,
        path: input_dir.join(entry.file),
        expected_sha256: Some(entry.sha256),
    }
}

fn read_source_entries(
    config: &Config,
    input: &OfflineInput,
    include_disabled: bool,
) -> Result<Vec<ParsedSourceEntries>, Box<dyn std::error::Error>> {
    if let Some(source) = config.source_by_name(&input.name) {
        if !source.enabled && !include_disabled {
            println!("Skipping disabled source '{}'", input.name);
            return Ok(Vec::new());
        }
        println!("Reading '{}' from {}...", input.name, input.path.display());
        let body = read_verified_body(input)?;
        let mut entries = IpRangeAccumulator::new();
        let entry_count = source.parse_into(&body, &mut entries);
        println!("  Found {entry_count} entries");
        return Ok(vec![ParsedSourceEntries {
            direction: source.direction,
            list_type: source.list_type,
            entries,
        }]);
    }

    if let Some(geoip) = config.geoip_by_name(&input.name) {
        if !geoip.enabled && !include_disabled {
            println!("Skipping disabled source '{}'", input.name);
            return Ok(Vec::new());
        }
        println!("Reading '{}' from {}...", input.name, input.path.display());
        let entries = geoip.parse_database(&read_verified_bytes(input)?)?;
        println!(
            "  Selected {} GeoIP records ({} inbound and {} outbound entries)",
            entries.selected_records,
            entries.inbound.len(),
            entries.outbound.len()
        );
        return Ok(vec![
            ParsedSourceEntries {
                direction: Direction::Inbound,
                list_type: ListType::Blocklist,
                entries: entries.inbound,
            },
            ParsedSourceEntries {
                direction: Direction::Outbound,
                list_type: ListType::Blocklist,
                entries: entries.outbound,
            },
        ]);
    }

    eprintln!("Skipping '{}': source is not present in config", input.name);
    Ok(Vec::new())
}

fn read_verified_bytes(input: &OfflineInput) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let body = fs::read(&input.path)?;
    if let Some(expected_sha256) = input.expected_sha256.as_deref()
        && sha256_hex(&body) != expected_sha256
    {
        return Err(format!(
            "checksum mismatch for '{}': {} no longer matches manifest.json",
            input.name,
            input.path.display()
        )
        .into());
    }
    Ok(body)
}

fn read_verified_body(input: &OfflineInput) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(read_verified_bytes(input)?)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load_config(&args.config)?;

    let manifest_path = args.input_dir.join("manifest.json");
    let manifest = load_manifest(&manifest_path)?;
    let inputs = if let Some(list_file) = &args.list_file {
        vec![resolve_single_list_file(
            &args.input_dir,
            &manifest.sources,
            list_file,
        )?]
    } else {
        manifest
            .sources
            .into_iter()
            .map(|entry| manifest_input(&args.input_dir, entry))
            .collect()
    };

    let mut inbound_blocklist_entries = IpRangeAccumulator::new();
    let mut outbound_blocklist_entries = IpRangeAccumulator::new();
    let mut inbound_allowlist_entries = IpRangeAccumulator::new();
    let mut outbound_allowlist_entries = IpRangeAccumulator::new();
    let mut processed_sources = 0;
    let mut parsed_entries = 0;

    for input in inputs {
        for ParsedSourceEntries {
            direction,
            list_type,
            entries,
        } in read_source_entries(&config, &input, args.include_disabled)?
        {
            parsed_entries += entries.len();
            match (list_type, direction) {
                (ListType::Blocklist, Direction::Inbound) => {
                    inbound_blocklist_entries.append(entries)
                }
                (ListType::Blocklist, Direction::Outbound) => {
                    outbound_blocklist_entries.append(entries)
                }
                (ListType::Blocklist, Direction::Both) => {
                    inbound_blocklist_entries.append(entries.clone());
                    outbound_blocklist_entries.append(entries);
                }
                (ListType::Allowlist, Direction::Inbound) => {
                    inbound_allowlist_entries.append(entries)
                }
                (ListType::Allowlist, Direction::Outbound) => {
                    outbound_allowlist_entries.append(entries)
                }
                (ListType::Allowlist, Direction::Both) => {
                    inbound_allowlist_entries.append(entries.clone());
                    outbound_allowlist_entries.append(entries);
                }
            }
            processed_sources += 1;
        }
    }

    let inbound_allowlist = inbound_allowlist_entries.finalize();
    let outbound_allowlist = outbound_allowlist_entries.finalize();
    let inbound_blocklist = inbound_blocklist_entries
        .finalize()
        .subtract(&inbound_allowlist);
    let outbound_blocklist = outbound_blocklist_entries
        .finalize()
        .subtract(&outbound_allowlist);
    let (inbound_output, inbound_final_entries) = format_blocklist_output(&inbound_blocklist);
    let (outbound_output, outbound_final_entries) = format_blocklist_output(&outbound_blocklist);
    let (inbound_path, outbound_path) = directional_output_paths(&args.output);
    fs::write(&inbound_path, inbound_output)?;
    fs::write(&outbound_path, outbound_output)?;

    println!(
        "Processed {} sources and {} parsed entries",
        processed_sources, parsed_entries
    );
    println!(
        "Inbound output written to {} ({} total entries)",
        inbound_path.display(),
        inbound_final_entries
    );
    println!(
        "Outbound output written to {} ({} total entries)",
        outbound_path.display(),
        outbound_final_entries
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{OfflineInput, read_verified_body};

    #[test]
    fn rejects_a_manifest_checksum_mismatch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alpha.txt");
        std::fs::write(&path, "192.0.2.0/24\n").unwrap();
        let input = OfflineInput {
            name: "alpha".to_string(),
            path,
            expected_sha256: Some("0".repeat(64)),
        };

        assert!(
            read_verified_body(&input)
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch")
        );
    }
}
