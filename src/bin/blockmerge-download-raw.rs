use std::fs;
use std::path::{Path, PathBuf};

use blockmerge::{
    config::load_config,
    geoip::GeoIpConfig,
    offline::{DownloadManifest, DownloadManifestEntry, load_manifest, sha256_hex},
    source::SourceConfig,
};
use chrono::Utc;
use clap::Parser;
use reqwest::blocking::Client;

/// Download configured blocklist files for offline testing.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file (default: blockmerge.toml)
    #[arg(
        long,
        default_value = "blockmerge.toml",
        env = "BLOCKMERGE_CONFIG_FILE"
    )]
    config: String,

    /// Directory where downloaded blocklists should be written
    #[arg(long, short = 'o')]
    output_dir: PathBuf,

    /// Download disabled sources as well as enabled sources
    #[arg(long)]
    include_disabled: bool,

    /// Download only the named source from the config
    #[arg(long)]
    list_name: Option<String>,
}

fn fixture_filename(source_name: &str) -> String {
    let mut file_name = String::new();

    for ch in source_name.chars() {
        if ch.is_ascii_alphanumeric() {
            file_name.push(ch.to_ascii_lowercase());
        } else if !file_name.ends_with('-') {
            file_name.push('-');
        }
    }

    let file_name = file_name.trim_matches('-');
    if file_name.is_empty() {
        "blocklist.txt".to_string()
    } else {
        format!("{file_name}.txt")
    }
}

fn download_source(
    client: &Client,
    output_dir: &Path,
    name: &str,
    source: &SourceConfig,
) -> Result<DownloadManifestEntry, Box<dyn std::error::Error>> {
    let body = if let Some(entries) = source.net_list.as_ref() {
        println!("Writing inline source '{name}' to fixture file...");
        entries.join("\n").into_bytes()
    } else {
        let Some(url) = source.url.as_deref() else {
            return Err(format!("source '{name}' is missing both url and net_list").into());
        };

        println!("Downloading '{name}' from {}...", url);
        let response = client.get(url).send()?;

        if !response.status().is_success() {
            return Err(format!("{} returned HTTP {}", url, response.status()).into());
        }

        response.bytes()?.to_vec()
    };

    let file = fixture_filename(name);
    fs::write(output_dir.join(&file), &body)?;

    println!("  Wrote {} bytes to {}", body.len(), file);

    Ok(DownloadManifestEntry {
        name: name.to_string(),
        url: source.url.clone(),
        file,
        sha256: sha256_hex(&body),
        downloaded_at: Utc::now().to_rfc3339(),
    })
}

fn geoip_fixture_filename(source_name: &str) -> String {
    fixture_filename(source_name)
        .trim_end_matches(".txt")
        .to_string()
        + ".zip"
}

fn download_geoip(
    client: &Client,
    output_dir: &Path,
    geoip: &GeoIpConfig,
) -> Result<DownloadManifestEntry, Box<dyn std::error::Error>> {
    let body = geoip.fetch_database(client)?;
    let file = geoip_fixture_filename(&geoip.name);
    fs::write(output_dir.join(&file), &body)?;
    println!("  Wrote {} bytes to {}", body.len(), file);
    Ok(DownloadManifestEntry {
        name: geoip.name.clone(),
        url: Some(geoip.download_url()?.to_string()),
        file,
        sha256: sha256_hex(&body),
        downloaded_at: Utc::now().to_rfc3339(),
    })
}

fn load_existing_manifest(
    manifest_path: &Path,
) -> Result<DownloadManifest, Box<dyn std::error::Error>> {
    load_manifest(manifest_path)
}

fn merge_manifest_entries(
    mut existing_entries: Vec<DownloadManifestEntry>,
    new_entries: Vec<DownloadManifestEntry>,
) -> Vec<DownloadManifestEntry> {
    for new_entry in new_entries {
        if let Some(existing_entry) = existing_entries
            .iter_mut()
            .find(|existing_entry| existing_entry.name == new_entry.name)
        {
            *existing_entry = new_entry;
        } else {
            existing_entries.push(new_entry);
        }
    }

    existing_entries.sort_by(|left, right| left.name.cmp(&right.name));
    existing_entries
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load_config(&args.config)?;
    fs::create_dir_all(&args.output_dir)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut entries = Vec::new();
    let mut failures = Vec::new();
    let selected_geoip = args
        .list_name
        .as_deref()
        .and_then(|name| config.geoip_by_name(name));
    let sources: Vec<_> = if let Some(list_name) = args.list_name.as_ref() {
        if let Some(source) = config.source_by_name(list_name) {
            if !source.enabled && !args.include_disabled {
                return Err(format!(
                    "source '{list_name}' is disabled in {}. Re-run with --include-disabled to download it",
                    args.config
                )
                .into());
            }
            vec![source]
        } else if let Some(geoip) = selected_geoip {
            if !geoip.enabled && !args.include_disabled {
                return Err(format!(
                    "source '{list_name}' is disabled in {}. Re-run with --include-disabled to download it",
                    args.config
                )
                .into());
            }
            Vec::new()
        } else {
            return Err(format!("source '{list_name}' was not found in {}", args.config).into());
        }
    } else {
        let mut sources: Vec<_> = config.sources().collect();
        sources.sort_by(|left, right| left.name.cmp(&right.name));
        sources
    };

    for source in sources {
        if !source.enabled && !args.include_disabled {
            println!("Skipping disabled source '{}'", source.name);
            continue;
        }

        match download_source(&client, &args.output_dir, &source.name, source) {
            Ok(entry) => entries.push(entry),
            Err(err) => {
                eprintln!("  Error downloading {}: {err}", source.name);
                failures.push(source.name.clone());
            }
        }
    }

    let geoip = if args.list_name.is_some() {
        selected_geoip
    } else {
        config.geoip.as_ref()
    };
    if let Some(geoip) = geoip {
        if !geoip.enabled && !args.include_disabled {
            println!("Skipping disabled source '{}'", geoip.name);
        } else {
            match download_geoip(&client, &args.output_dir, geoip) {
                Ok(entry) => entries.push(entry),
                Err(err) => {
                    eprintln!("  Error downloading {}: {err}", geoip.name);
                    failures.push(geoip.name.clone());
                }
            }
        }
    }

    let manifest_path = args.output_dir.join("manifest.json");
    let manifest_entries = if args.list_name.is_some() && manifest_path.exists() {
        merge_manifest_entries(load_existing_manifest(&manifest_path)?.sources, entries)
    } else {
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        entries
    };
    let manifest = serde_json::to_string_pretty(&DownloadManifest::new(manifest_entries.clone())?)?;
    fs::write(&manifest_path, manifest)?;
    println!(
        "Wrote manifest for {} downloaded sources to {}",
        manifest_entries.len(),
        manifest_path.display()
    );

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} downloads failed: {}",
            failures.len(),
            failures.join(", ")
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use blockmerge::offline::sha256_hex;

    use super::{DownloadManifestEntry, merge_manifest_entries};

    fn entry(name: &str, file: &str) -> DownloadManifestEntry {
        DownloadManifestEntry {
            name: name.to_string(),
            url: Some(format!("https://example.com/{name}.txt")),
            file: file.to_string(),
            sha256: sha256_hex(name.as_bytes()),
            downloaded_at: "2026-08-15T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn merge_manifest_entries_replaces_matching_entry() {
        let existing = vec![entry("alpha", "alpha-old.txt"), entry("beta", "beta.txt")];
        let merged = merge_manifest_entries(existing, vec![entry("alpha", "alpha-new.txt")]);

        assert_eq!(
            merged,
            vec![entry("alpha", "alpha-new.txt"), entry("beta", "beta.txt")]
        );
    }

    #[test]
    fn merge_manifest_entries_appends_new_entry_and_sorts() {
        let existing = vec![entry("gamma", "gamma.txt")];
        let merged = merge_manifest_entries(existing, vec![entry("alpha", "alpha.txt")]);

        assert_eq!(
            merged,
            vec![entry("alpha", "alpha.txt"), entry("gamma", "gamma.txt")]
        );
    }
}
