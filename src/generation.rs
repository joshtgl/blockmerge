//! Retrieve configured sources and generate directional blocklists.

use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use tempfile::NamedTempFile;

use crate::config::{Config, ResiliencePolicy};
use crate::geoip::{GeoIpConfig, GeoIpEntries};
use crate::offline::sha256_hex;
use crate::ranges::{DirectionalBlocklists, IpRangeAccumulator};
use crate::source::{Direction, ListType};
use crate::state::{CachedSource, StateFile};

/// Rendered blocklist contents, entry counts, and successfully retrieved sources.
pub struct GeneratedBlocklistOutputs {
    pub inbound_output: String,
    pub outbound_output: String,
    pub inbound_entries: usize,
    pub outbound_entries: usize,
    pub successful_sources: Vec<String>,
    pub source_outcomes: Vec<SourceRefreshOutcome>,
}

/// Merged directional blocklists and the source names retrieved successfully.
pub struct RetrievedBlocklists {
    pub blocklists: DirectionalBlocklists,
    pub successful_sources: Vec<String>,
    pub source_outcomes: Vec<SourceRefreshOutcome>,
}

/// How a source contributed to a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRefreshOutcome {
    Inline { name: String },
    Fresh { name: String },
    Stale { name: String, failures: u32 },
    Unavailable { name: String },
    Expired { name: String, failures: u32 },
    Cached { name: String },
}

/// Mutable state and cache used while retrieving resilient sources.
pub struct RefreshContext {
    pub policy: ResiliencePolicy,
    pub state: StateFile,
    pub cache_dir: PathBuf,
}

impl RefreshContext {
    pub fn new(policy: ResiliencePolicy, state: StateFile, cache_dir: PathBuf) -> Self {
        Self {
            policy,
            state,
            cache_dir,
        }
    }
}

#[derive(Default)]
struct RangeAccumulators {
    inbound_blocklist: IpRangeAccumulator,
    outbound_blocklist: IpRangeAccumulator,
    inbound_allowlist: IpRangeAccumulator,
    outbound_allowlist: IpRangeAccumulator,
}

impl RangeAccumulators {
    fn add(&mut self, list_type: ListType, direction: Direction, entry: ipnet::IpNet) {
        match (list_type, direction) {
            (ListType::Blocklist, Direction::Inbound) => self.inbound_blocklist.add(entry),
            (ListType::Blocklist, Direction::Outbound) => self.outbound_blocklist.add(entry),
            (ListType::Blocklist, Direction::Both) => {
                self.inbound_blocklist.add(entry);
                self.outbound_blocklist.add(entry);
            }
            (ListType::Allowlist, Direction::Inbound) => self.inbound_allowlist.add(entry),
            (ListType::Allowlist, Direction::Outbound) => self.outbound_allowlist.add(entry),
            (ListType::Allowlist, Direction::Both) => {
                self.inbound_allowlist.add(entry);
                self.outbound_allowlist.add(entry);
            }
        }
    }

    fn finalize(self) -> DirectionalBlocklists {
        let inbound_allowlist = self.inbound_allowlist.finalize();
        let outbound_allowlist = self.outbound_allowlist.finalize();
        DirectionalBlocklists {
            inbound: self
                .inbound_blocklist
                .finalize()
                .subtract(&inbound_allowlist),
            outbound: self
                .outbound_blocklist
                .finalize()
                .subtract(&outbound_allowlist),
        }
    }
}

fn parse_source_body(
    source: &crate::source::SourceConfig,
    body: &str,
    ranges: &mut RangeAccumulators,
) -> usize {
    source.visit_entries(body, |entry| {
        ranges.add(source.list_type, source.direction, entry)
    })
}

fn fetch_source(
    client: &Client,
    source: &crate::source::SourceConfig,
    ranges: &mut RangeAccumulators,
) -> Result<usize, Box<dyn std::error::Error>> {
    source.fetch_and_visit(client, |entry| {
        ranges.add(source.list_type, source.direction, entry)
    })
}

/// Retrieve, route, and merge all enabled sources.
pub fn retrieve_blocklists(
    client: &Client,
    config: &Config,
) -> Result<RetrievedBlocklists, Box<dyn std::error::Error>> {
    let mut ranges = RangeAccumulators::default();
    let mut total_entries = 0;
    let mut inbound_entries = 0;
    let mut outbound_entries = 0;
    let mut allowlist_entries = 0;
    let mut successful_sources = Vec::new();
    let enabled_sources: Vec<_> = config.sources().filter(|source| source.enabled).collect();

    println!(
        "Found {} list sources ({} enabled)",
        config.source_count(),
        enabled_sources.len()
    );
    for source in enabled_sources {
        println!("Processing '{}'...", source.name);
        if source.rate_limited {
            println!("  Note: This source is rate limited. Please be respectful.");
        }
        match source.fetch_and_visit(client, |entry| {
            total_entries += 1;
            match (source.list_type, source.direction) {
                (ListType::Blocklist, Direction::Inbound) => inbound_entries += 1,
                (ListType::Blocklist, Direction::Outbound) => outbound_entries += 1,
                (ListType::Blocklist, Direction::Both) => {
                    inbound_entries += 1;
                    outbound_entries += 1;
                }
                (ListType::Allowlist, _) => allowlist_entries += 1,
            }
            ranges.add(source.list_type, source.direction, entry);
        }) {
            Ok(_) => {
                successful_sources.push(source.name.clone());
            }
            Err(error) => eprintln!("  Error fetching {}: {}", source.name, error),
        }
    }

    if let Some(geoip) = config.geoip.as_ref().filter(|geoip| geoip.enabled) {
        println!("Processing GeoIP source '{}'...", geoip.name);
        match geoip
            .fetch_database(client)
            .and_then(|body| geoip.parse_database(&body))
        {
            Ok(GeoIpEntries {
                inbound,
                outbound,
                selected_records,
                ..
            }) => {
                println!(
                    "  Selected {selected_records} GeoIP records ({} inbound and {} outbound entries)",
                    inbound.len(),
                    outbound.len()
                );
                total_entries += inbound.len() + outbound.len();
                inbound_entries += inbound.len();
                outbound_entries += outbound.len();
                ranges.inbound_blocklist.append(inbound);
                ranges.outbound_blocklist.append(outbound);
                successful_sources.push(geoip.name.clone());
            }
            Err(error) => eprintln!("  Error fetching GeoIP source '{}': {error}", geoip.name),
        }
    }

    println!("Simplifying and deduplicating entries...");
    println!("Total entries processed: {}", total_entries);
    println!("Inbound entries processed: {}", inbound_entries);
    println!("Outbound entries processed: {}", outbound_entries);
    println!("Allowlist entries processed: {}", allowlist_entries);
    let blocklists = ranges.finalize();
    println!(
        "Inbound unique IPv4 networks: {}",
        blocklists.inbound.ipv4_networks().count()
    );
    println!(
        "Inbound unique IPv6 networks: {}",
        blocklists.inbound.ipv6_networks().count()
    );
    println!(
        "Outbound unique IPv4 networks: {}",
        blocklists.outbound.ipv4_networks().count()
    );
    println!(
        "Outbound unique IPv6 networks: {}",
        blocklists.outbound.ipv6_networks().count()
    );

    Ok(RetrievedBlocklists {
        blocklists,
        successful_sources,
        source_outcomes: Vec::new(),
    })
}

/// Retrieve all enabled sources, retaining eligible cached bodies after failures.
pub fn retrieve_blocklists_with_resilience(
    client: &Client,
    config: &Config,
    context: &mut RefreshContext,
) -> Result<RetrievedBlocklists, Box<dyn std::error::Error>> {
    prune_inactive_sources(config, context);

    let mut ranges = RangeAccumulators::default();
    let mut successful_sources = Vec::new();
    let mut source_outcomes = Vec::new();

    for source in config.sources().filter(|source| source.enabled) {
        println!("Processing '{}'...", source.name);
        if source.net_list.is_some() {
            fetch_source(client, source, &mut ranges)?;
            source_outcomes.push(SourceRefreshOutcome::Inline {
                name: source.name.clone(),
            });
        } else if !context.policy.enabled {
            match fetch_source(client, source, &mut ranges) {
                Ok(_) => {
                    successful_sources.push(source.name.clone());
                    source_outcomes.push(SourceRefreshOutcome::Fresh {
                        name: source.name.clone(),
                    });
                }
                Err(error) => {
                    eprintln!("  Error fetching {}: {}", source.name, error);
                    source_outcomes.push(SourceRefreshOutcome::Unavailable {
                        name: source.name.clone(),
                    });
                }
            }
        } else {
            match source.fetch_body(client) {
                Ok(body) => {
                    let cached_source = write_cached_body(&context.cache_dir, &source.name, &body)?;
                    context.state.mark_success(
                        &source.name,
                        Utc::now().to_rfc3339(),
                        cached_source,
                    );
                    let entry_count = parse_source_body(source, &body, &mut ranges);
                    println!("  Found {entry_count} entries");
                    successful_sources.push(source.name.clone());
                    source_outcomes.push(SourceRefreshOutcome::Fresh {
                        name: source.name.clone(),
                    });
                }
                Err(error) => {
                    eprintln!("  Error fetching {}: {}", source.name, error);
                    let failures = context
                        .state
                        .mark_failure(&source.name, Utc::now().to_rfc3339());
                    let cache_dir = context.cache_dir.clone();
                    match read_eligible_cached_body(&cache_dir, &source.name, failures, context) {
                        Ok(Some(body)) => {
                            let entry_count = parse_source_body(source, &body, &mut ranges);
                            println!(
                                "  Using cached source after {failures} failure(s); found {} entries",
                                entry_count
                            );
                            source_outcomes.push(SourceRefreshOutcome::Stale {
                                name: source.name.clone(),
                                failures,
                            });
                        }
                        Ok(None) => {
                            eprintln!(
                                "  No eligible cached source remains for '{}' after {failures} failure(s); omitting it",
                                source.name
                            );
                            source_outcomes.push(SourceRefreshOutcome::Expired {
                                name: source.name.clone(),
                                failures,
                            });
                        }
                        Err(cache_error) => {
                            eprintln!(
                                "  Cached source '{}' is unavailable: {cache_error}",
                                source.name
                            );
                            source_outcomes.push(SourceRefreshOutcome::Unavailable {
                                name: source.name.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    add_geoip_with_resilience(
        client,
        config.geoip.as_ref().filter(|geoip| geoip.enabled),
        context,
        &mut ranges.inbound_blocklist,
        &mut ranges.outbound_blocklist,
        &mut successful_sources,
        &mut source_outcomes,
    );

    Ok(RetrievedBlocklists {
        blocklists: ranges.finalize(),
        successful_sources,
        source_outcomes,
    })
}

fn add_geoip_with_resilience(
    client: &Client,
    geoip: Option<&GeoIpConfig>,
    context: &mut RefreshContext,
    inbound: &mut IpRangeAccumulator,
    outbound: &mut IpRangeAccumulator,
    successful_sources: &mut Vec<String>,
    outcomes: &mut Vec<SourceRefreshOutcome>,
) {
    let Some(geoip) = geoip else {
        return;
    };
    println!("Processing GeoIP source '{}'...", geoip.name);
    let entries = match geoip_refresh_due(geoip, context) {
        Ok(true) => match geoip.fetch_database(client).and_then(|body| {
            let entries = geoip.parse_database(&body)?;
            let cached = write_cached_bytes(&context.cache_dir, &geoip.name, &body)?;
            context
                .state
                .mark_success(&geoip.name, Utc::now().to_rfc3339(), cached);
            Ok(entries)
        }) {
            Ok(entries) => {
                successful_sources.push(geoip.name.clone());
                outcomes.push(SourceRefreshOutcome::Fresh {
                    name: geoip.name.clone(),
                });
                Some(entries)
            }
            Err(error) => {
                eprintln!("  Error refreshing GeoIP source '{}': {error}", geoip.name);
                context
                    .state
                    .mark_failure(&geoip.name, Utc::now().to_rfc3339());
                match read_persistent_cached_body(&geoip.name, context) {
                    Ok(Some(body)) => match geoip.parse_database(&body) {
                        Ok(entries) => {
                            outcomes.push(SourceRefreshOutcome::Cached {
                                name: geoip.name.clone(),
                            });
                            Some(entries)
                        }
                        Err(cache_error) => {
                            eprintln!(
                                "  Cached GeoIP source '{}' is invalid: {cache_error}",
                                geoip.name
                            );
                            outcomes.push(SourceRefreshOutcome::Unavailable {
                                name: geoip.name.clone(),
                            });
                            None
                        }
                    },
                    Ok(None) => {
                        outcomes.push(SourceRefreshOutcome::Unavailable {
                            name: geoip.name.clone(),
                        });
                        None
                    }
                    Err(cache_error) => {
                        eprintln!(
                            "  Cached GeoIP source '{}' is unavailable: {cache_error}",
                            geoip.name
                        );
                        outcomes.push(SourceRefreshOutcome::Unavailable {
                            name: geoip.name.clone(),
                        });
                        None
                    }
                }
            }
        },
        Ok(false) => match read_persistent_cached_body(&geoip.name, context) {
            Ok(Some(body)) => match geoip.parse_database(&body) {
                Ok(entries) => {
                    outcomes.push(SourceRefreshOutcome::Cached {
                        name: geoip.name.clone(),
                    });
                    Some(entries)
                }
                Err(error) => {
                    eprintln!("  Cached GeoIP source '{}' is invalid: {error}", geoip.name);
                    outcomes.push(SourceRefreshOutcome::Unavailable {
                        name: geoip.name.clone(),
                    });
                    None
                }
            },
            Ok(None) => {
                outcomes.push(SourceRefreshOutcome::Unavailable {
                    name: geoip.name.clone(),
                });
                None
            }
            Err(error) => {
                eprintln!(
                    "  Cached GeoIP source '{}' is unavailable: {error}",
                    geoip.name
                );
                outcomes.push(SourceRefreshOutcome::Unavailable {
                    name: geoip.name.clone(),
                });
                None
            }
        },
        Err(error) => {
            eprintln!(
                "  GeoIP refresh scheduling error for '{}': {error}",
                geoip.name
            );
            outcomes.push(SourceRefreshOutcome::Unavailable {
                name: geoip.name.clone(),
            });
            None
        }
    };

    if let Some(GeoIpEntries {
        inbound: geoip_inbound,
        outbound: geoip_outbound,
        selected_records,
        ..
    }) = entries
    {
        println!(
            "  Selected {selected_records} GeoIP records ({} inbound and {} outbound entries)",
            geoip_inbound.len(),
            geoip_outbound.len()
        );
        inbound.append(geoip_inbound);
        outbound.append(geoip_outbound);
    }
}

fn geoip_refresh_due(
    geoip: &GeoIpConfig,
    context: &RefreshContext,
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(status) = context.state.source(&geoip.name) else {
        return Ok(true);
    };
    let Some(last_attempt) = status
        .last_attempt_at
        .as_deref()
        .or(status.last_success_at.as_deref())
    else {
        return Ok(true);
    };
    let last_attempt = DateTime::parse_from_rfc3339(last_attempt)?.with_timezone(&Utc);
    let elapsed = Utc::now().signed_duration_since(last_attempt);
    let policy = geoip.policy()?;
    Ok(elapsed
        .to_std()
        .map(|age| age >= policy.refresh_interval)
        .unwrap_or(false))
}

fn prune_inactive_sources(config: &Config, context: &mut RefreshContext) {
    let mut active: std::collections::HashSet<_> = config
        .sources()
        .filter(|source| source.enabled)
        .map(|source| source.name.as_str())
        .collect();
    if let Some(geoip) = config.geoip.as_ref().filter(|geoip| geoip.enabled) {
        active.insert(geoip.name.as_str());
    }
    let inactive: Vec<_> = context
        .state
        .sources
        .keys()
        .filter(|name| !active.contains(name.as_str()))
        .cloned()
        .collect();
    for name in inactive {
        if let Some(cache) = context.state.remove_source(&name) {
            remove_cached_body(&context.cache_dir, &cache);
        }
    }
}

fn write_cached_body(
    cache_dir: &Path,
    source_name: &str,
    body: &str,
) -> Result<CachedSource, Box<dyn std::error::Error>> {
    write_cached_bytes(cache_dir, source_name, body.as_bytes())
}

fn write_cached_bytes(
    cache_dir: &Path,
    source_name: &str,
    body: &[u8],
) -> Result<CachedSource, Box<dyn std::error::Error>> {
    fs::create_dir_all(cache_dir)?;
    let cache_file = format!("{}.body", sha256_hex(source_name.as_bytes()));
    let mut temporary = NamedTempFile::new_in(cache_dir)?;
    temporary.write_all(body)?;
    temporary
        .persist(cache_dir.join(&cache_file))
        .map_err(|error| error.error)?;
    Ok(CachedSource {
        cache_file,
        sha256: sha256_hex(body),
    })
}

fn read_persistent_cached_body(
    source_name: &str,
    context: &mut RefreshContext,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let Some(status) = context.state.source(source_name).cloned() else {
        return Ok(None);
    };
    let Some(cached_source) = status.cached_source else {
        return Ok(None);
    };
    let path = checked_cache_path(&context.cache_dir, &cached_source.cache_file)?;
    let body = fs::read(path)?;
    if sha256_hex(&body) != cached_source.sha256 {
        expire_source_cache(&context.cache_dir.clone(), source_name, context);
        return Err("cached source checksum mismatch".into());
    }
    Ok(Some(body))
}

fn read_eligible_cached_body(
    cache_dir: &Path,
    source_name: &str,
    failures: u32,
    context: &mut RefreshContext,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(status) = context.state.source(source_name).cloned() else {
        return Ok(None);
    };
    let Some(cached_source) = status.cached_source else {
        return Ok(None);
    };
    let Some(last_success_at) = status.last_success_at else {
        expire_source_cache(cache_dir, source_name, context);
        return Ok(None);
    };
    let last_success_at = DateTime::parse_from_rfc3339(&last_success_at)?.with_timezone(&Utc);
    let age = Utc::now().signed_duration_since(last_success_at);
    let within_age = age
        .to_std()
        .map(|age| age <= context.policy.max_stale_age)
        .unwrap_or(true);
    if !within_age || failures >= context.policy.max_consecutive_failures {
        eprintln!(
            "  Cached source '{}' expired (age: {:?}, failures: {})",
            source_name, age, failures
        );
        expire_source_cache(cache_dir, source_name, context);
        return Ok(None);
    }

    let path = checked_cache_path(cache_dir, &cached_source.cache_file)?;
    let body = fs::read_to_string(path)?;
    if sha256_hex(body.as_bytes()) != cached_source.sha256 {
        expire_source_cache(cache_dir, source_name, context);
        return Err("cached source checksum mismatch".into());
    }
    println!(
        "  Using cached source '{}' (age: {:?}, failures: {})",
        source_name, age, failures
    );
    Ok(Some(body))
}

fn expire_source_cache(cache_dir: &Path, source_name: &str, context: &mut RefreshContext) {
    if let Some(cache) = context.state.expire_cache(source_name) {
        remove_cached_body(cache_dir, &cache);
    }
}

fn checked_cache_path(
    cache_dir: &Path,
    cache_file: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = Path::new(cache_file);
    if !path.is_relative()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err("invalid cached source path in refresh state".into());
    }
    Ok(cache_dir.join(path))
}

fn remove_cached_body(cache_dir: &Path, cached_source: &CachedSource) {
    if let Ok(path) = checked_cache_path(cache_dir, &cached_source.cache_file) {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use ipnet::{Ipv4Net, Ipv6Net};
    use mockito::Server;
    use std::io::{Cursor, Write};

    use super::*;
    use crate::config::{ResilienceConfig, ResiliencePolicy};
    use crate::geoip::{
        CountryRule, CustomGeoIpConfig, CustomGeoIpFormat, GeoIpConfig, GeoIpService,
    };
    use crate::source::SourceConfig;
    use crate::test_support::test_source;

    fn inline_source(
        name: &str,
        list_type: ListType,
        direction: Direction,
        entries: &[&str],
    ) -> SourceConfig {
        SourceConfig {
            name: name.to_string(),
            url: None,
            list_type,
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

    fn remote_source(name: &str, url: String) -> SourceConfig {
        SourceConfig {
            name: name.to_string(),
            url: Some(url),
            list_type: ListType::Blocklist,
            comment_char: "#".to_string(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        }
    }

    fn resilient_config(source: SourceConfig) -> Config {
        Config {
            blocklists: vec![source],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: ResilienceConfig::default(),
        }
    }

    fn geoip_config(url: String) -> GeoIpConfig {
        GeoIpConfig {
            name: "iplocate-country".to_string(),
            enabled: true,
            refresh_interval: "24h".to_string(),
            service: GeoIpService::Custom,
            api_key_env: None,
            api_key: None,
            custom: Some(CustomGeoIpConfig {
                download_url: url,
                format: CustomGeoIpFormat::ZipCsv,
                network_column: "network".to_string(),
                country_code_column: "country_code".to_string(),
                api_key_query_parameter: None,
            }),
            country_rules: vec![CountryRule {
                country_codes: vec!["US".to_string()],
                direction: Direction::Inbound,
            }],
        }
    }

    fn geoip_zip() -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "ip-to-country.csv",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer
            .write_all(b"network,country,country_code,continent_code\n192.0.2.0/24,Example,US,NA\n")
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn geoip_country_ranges_merge_and_allowlists_remain_exceptions() {
        let mut server = mockito::Server::new();
        let response = server
            .mock("GET", "/country.zip")
            .with_status(200)
            .with_body(geoip_zip())
            .create();
        let config = Config {
            blocklists: Vec::new(),
            allowlists: vec![inline_source(
                "exception",
                ListType::Allowlist,
                Direction::Inbound,
                &["192.0.2.0/25"],
            )],
            geoip: Some(geoip_config(format!("{}/country.zip", server.url()))),
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: ResilienceConfig::default(),
        };
        let directory = tempfile::tempdir().unwrap();
        let mut context = RefreshContext::new(
            ResiliencePolicy {
                enabled: true,
                max_stale_age: std::time::Duration::from_secs(1),
                max_consecutive_failures: 1,
            },
            StateFile::default(),
            directory.path().to_path_buf(),
        );

        let result = retrieve_blocklists_with_resilience(&Client::new(), &config, &mut context)
            .unwrap()
            .blocklists;

        assert_eq!(
            result.inbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["192.0.2.128/25".parse().unwrap()]
        );
        assert!(
            result
                .outbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        response.assert();
    }

    #[test]
    fn geoip_cache_is_reused_without_age_expiry_before_next_attempt() {
        let config = Config {
            blocklists: Vec::new(),
            allowlists: Vec::new(),
            geoip: Some(geoip_config("http://127.0.0.1/unreachable.zip".to_string())),
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: ResilienceConfig::default(),
        };
        let directory = tempfile::tempdir().unwrap();
        let cached =
            write_cached_bytes(directory.path(), "iplocate-country", &geoip_zip()).unwrap();
        let mut state = StateFile::default();
        state.mark_success(
            "iplocate-country",
            "2000-01-01T00:00:00Z".to_string(),
            cached,
        );
        state
            .sources
            .get_mut("iplocate-country")
            .unwrap()
            .last_attempt_at = Some(Utc::now().to_rfc3339());
        let mut context = RefreshContext::new(
            ResilienceConfig::default().policy().unwrap(),
            state,
            directory.path().to_path_buf(),
        );

        let retrieved =
            retrieve_blocklists_with_resilience(&Client::new(), &config, &mut context).unwrap();
        assert_eq!(
            retrieved
                .blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>(),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
        assert_eq!(
            retrieved.source_outcomes,
            vec![SourceRefreshOutcome::Cached {
                name: "iplocate-country".to_string(),
            }]
        );
    }

    #[test]
    fn uses_a_recent_cached_body_after_fetch_failure() {
        let mut server = mockito::Server::new();
        let failed = server.mock("GET", "/source.txt").with_status(500).create();
        let directory = tempfile::tempdir().unwrap();
        let mut state = StateFile::default();
        let cached = write_cached_body(directory.path(), "alpha", "192.0.2.0/24\n").unwrap();
        state.mark_success("alpha", Utc::now().to_rfc3339(), cached);
        let mut context = RefreshContext::new(
            ResiliencePolicy {
                enabled: true,
                max_stale_age: std::time::Duration::from_secs(24 * 60 * 60),
                max_consecutive_failures: 4,
            },
            state,
            directory.path().to_path_buf(),
        );

        let retrieved = retrieve_blocklists_with_resilience(
            &Client::new(),
            &resilient_config(remote_source(
                "alpha",
                format!("{}/source.txt", server.url()),
            )),
            &mut context,
        )
        .unwrap();

        assert_eq!(
            retrieved
                .blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>(),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
        assert_eq!(
            retrieved.source_outcomes,
            vec![SourceRefreshOutcome::Stale {
                name: "alpha".to_string(),
                failures: 1,
            }]
        );
        failed.assert();
    }

    #[test]
    fn expires_cache_after_retry_limit() {
        let mut server = mockito::Server::new();
        let failed = server.mock("GET", "/source.txt").with_status(500).create();
        let directory = tempfile::tempdir().unwrap();
        let mut state = StateFile::default();
        let cached = write_cached_body(directory.path(), "alpha", "192.0.2.0/24\n").unwrap();
        let cached_path = directory.path().join(&cached.cache_file);
        state.mark_success("alpha", Utc::now().to_rfc3339(), cached);
        let mut context = RefreshContext::new(
            ResiliencePolicy {
                enabled: true,
                max_stale_age: std::time::Duration::from_secs(24 * 60 * 60),
                max_consecutive_failures: 1,
            },
            state,
            directory.path().to_path_buf(),
        );

        let retrieved = retrieve_blocklists_with_resilience(
            &Client::new(),
            &resilient_config(remote_source(
                "alpha",
                format!("{}/source.txt", server.url()),
            )),
            &mut context,
        )
        .unwrap();

        assert!(
            retrieved
                .blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert_eq!(
            retrieved.source_outcomes,
            vec![SourceRefreshOutcome::Expired {
                name: "alpha".to_string(),
                failures: 1,
            }]
        );
        assert!(!cached_path.exists());
        failed.assert();
    }

    #[test]
    fn expires_cache_after_maximum_age() {
        let directory = tempfile::tempdir().unwrap();
        let cached = write_cached_body(directory.path(), "alpha", "192.0.2.0/24\n").unwrap();
        let mut state = StateFile::default();
        state.mark_success(
            "alpha",
            (Utc::now() - ChronoDuration::hours(25)).to_rfc3339(),
            cached,
        );
        let cached_path = directory.path().join(
            state
                .source("alpha")
                .unwrap()
                .cached_source
                .as_ref()
                .unwrap()
                .cache_file
                .clone(),
        );
        let mut context = RefreshContext::new(
            ResiliencePolicy {
                enabled: true,
                max_stale_age: std::time::Duration::from_secs(24 * 60 * 60),
                max_consecutive_failures: 4,
            },
            state,
            directory.path().to_path_buf(),
        );
        let mut server = mockito::Server::new();
        let _failed = server.mock("GET", "/source.txt").with_status(500).create();

        let retrieved = retrieve_blocklists_with_resilience(
            &Client::new(),
            &resilient_config(remote_source(
                "alpha",
                format!("{}/source.txt", server.url()),
            )),
            &mut context,
        )
        .unwrap();

        assert!(matches!(
            retrieved.source_outcomes.as_slice(),
            [SourceRefreshOutcome::Expired { .. }]
        ));
        assert!(!cached_path.exists());
    }

    #[test]
    fn rejects_corrupted_cached_bodies() {
        let directory = tempfile::tempdir().unwrap();
        let cached = write_cached_body(directory.path(), "alpha", "192.0.2.0/24\n").unwrap();
        let cached_path = directory.path().join(&cached.cache_file);
        std::fs::write(&cached_path, "corrupted\n").unwrap();
        let mut state = StateFile::default();
        state.mark_success("alpha", Utc::now().to_rfc3339(), cached);
        let mut context = RefreshContext::new(
            ResiliencePolicy {
                enabled: true,
                max_stale_age: std::time::Duration::from_secs(24 * 60 * 60),
                max_consecutive_failures: 4,
            },
            state,
            directory.path().to_path_buf(),
        );
        let mut server = mockito::Server::new();
        let _failed = server.mock("GET", "/source.txt").with_status(500).create();

        let retrieved = retrieve_blocklists_with_resilience(
            &Client::new(),
            &resilient_config(remote_source(
                "alpha",
                format!("{}/source.txt", server.url()),
            )),
            &mut context,
        )
        .unwrap();

        assert!(matches!(
            retrieved.source_outcomes.as_slice(),
            [SourceRefreshOutcome::Unavailable { .. }]
        ));
        assert!(!cached_path.exists());
        assert!(
            context
                .state
                .source("alpha")
                .unwrap()
                .cached_source
                .is_none()
        );
    }

    #[test]
    fn inline_sources_bypass_the_cache() {
        let directory = tempfile::tempdir().unwrap();
        let cache_dir = directory.path().join("cache");
        let mut context = RefreshContext::new(
            ResiliencePolicy {
                enabled: true,
                max_stale_age: std::time::Duration::from_secs(24 * 60 * 60),
                max_consecutive_failures: 4,
            },
            StateFile::default(),
            cache_dir.clone(),
        );
        let config = resilient_config(inline_source(
            "inline",
            ListType::Blocklist,
            Direction::Inbound,
            &["192.0.2.0/24"],
        ));

        let retrieved =
            retrieve_blocklists_with_resilience(&Client::new(), &config, &mut context).unwrap();

        assert!(matches!(
            retrieved.source_outcomes.as_slice(),
            [SourceRefreshOutcome::Inline { .. }]
        ));
        assert!(!cache_dir.exists());
    }

    #[test]
    fn routes_both_direction_sources_and_applies_directional_allowlists() {
        let config = Config {
            blocklists: vec![
                inline_source(
                    "both",
                    ListType::Blocklist,
                    Direction::Both,
                    &["192.0.2.0/24"],
                ),
                inline_source(
                    "outbound",
                    ListType::Blocklist,
                    Direction::Outbound,
                    &["198.51.100.0/24"],
                ),
            ],
            allowlists: vec![inline_source(
                "inbound-allow",
                ListType::Allowlist,
                Direction::Inbound,
                &["192.0.2.0/25"],
            )],
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };

        let blocklists = retrieve_blocklists(&Client::new(), &config)
            .unwrap()
            .blocklists;

        assert_eq!(
            blocklists.inbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["192.0.2.128/25".parse().unwrap()]
        );
        assert_eq!(
            blocklists.outbound.ipv4_networks().collect::<Vec<_>>(),
            vec![
                "192.0.2.0/24".parse().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn ignores_disabled_sources() {
        let mut disabled = inline_source(
            "disabled",
            ListType::Blocklist,
            Direction::Inbound,
            &["192.0.2.0/24"],
        );
        disabled.enabled = false;
        let config = Config {
            blocklists: vec![disabled],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };

        let blocklists = retrieve_blocklists(&Client::new(), &config)
            .unwrap()
            .blocklists;

        assert!(
            blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
    }

    #[test]
    fn test_retrieve_blocklists_fetches_and_merges_mocked_blocklists() {
        let mut server = Server::new();
        let blocklist_one = server
            .mock("GET", "/blocklist-one.txt")
            .with_status(200)
            .with_body("# comment\n8.8.8.0/25\n8.8.8.128/25\n2001:db8::/32\n")
            .create();
        let blocklist_two = server
            .mock("GET", "/blocklist-two.txt")
            .with_status(200)
            .with_body("1.1.1.1\n2001:4860:4860::8888\nnot-an-ip\n")
            .create();

        let config = Config {
            blocklists: vec![
                test_source(format!("{}/blocklist-one.txt", server.url())),
                test_source(format!("{}/blocklist-two.txt", server.url())),
            ],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        let expected_v4: Vec<Ipv4Net> =
            vec!["1.1.1.1/32".parse().unwrap(), "8.8.8.0/24".parse().unwrap()];
        let expected_v6: Vec<Ipv6Net> = vec![
            "2001:db8::/32".parse().unwrap(),
            "2001:4860:4860::8888/128".parse().unwrap(),
        ];
        assert_eq!(
            result.inbound.ipv4_networks().collect::<Vec<_>>(),
            expected_v4
        );
        assert_eq!(
            result.inbound.ipv6_networks().collect::<Vec<_>>(),
            expected_v6
        );
        assert!(
            result
                .outbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .outbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        blocklist_one.assert();
        blocklist_two.assert();
    }

    #[test]
    fn test_retrieve_blocklists_applies_inline_allowlist_source() {
        let config = Config {
            blocklists: vec![crate::test_support::inline_source(
                "blocklist",
                ListType::Blocklist,
                vec!["8.8.8.0/24", "10.0.0.0/8"],
            )],
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

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        assert_eq!(
            result.inbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["8.8.8.0/24".parse().unwrap()]
        );
        assert!(
            result
                .inbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
    }

    #[test]
    fn test_retrieve_blocklists_skips_disabled_sources() {
        let mut disabled_source = test_source("http://127.0.0.1/disabled.txt".to_string());
        disabled_source.enabled = false;

        let config = Config {
            blocklists: vec![disabled_source],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        assert!(
            result
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .inbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .outbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .outbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
    }

    #[test]
    fn test_retrieve_blocklists_continues_after_mocked_fetch_error() {
        let mut server = Server::new();
        let failing_blocklist = server.mock("GET", "/failing.txt").with_status(500).create();
        let successful_blocklist = server
            .mock("GET", "/successful.txt")
            .with_status(200)
            .with_body("9.9.9.0/24\n")
            .create();

        let config = Config {
            blocklists: vec![
                test_source(format!("{}/failing.txt", server.url())),
                test_source(format!("{}/successful.txt", server.url())),
            ],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap();

        assert_eq!(
            result
                .blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>(),
            vec!["9.9.9.0/24".parse().unwrap()]
        );
        assert!(
            result
                .blocklists
                .inbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .blocklists
                .outbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .blocklists
                .outbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert_eq!(
            result.successful_sources,
            vec![format!("{}/successful.txt", server.url())]
        );
        failing_blocklist.assert();
        successful_blocklist.assert();
    }

    #[test]
    fn test_retrieve_blocklists_applies_inline_private_range_allowlist() {
        let mut server = Server::new();
        let blocklist = server
            .mock("GET", "/zero-dot.txt")
            .with_status(200)
            .with_body("0.0.0.0/8\n0.1.2.3\n8.8.8.0/24\n")
            .create();

        let config = Config {
            blocklists: vec![test_source(format!("{}/zero-dot.txt", server.url()))],
            allowlists: vec![crate::test_support::inline_source(
                "private-ranges",
                ListType::Allowlist,
                vec!["0.0.0.0/8"],
            )],
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        assert_eq!(
            result.inbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["8.8.8.0/24".parse().unwrap()]
        );
        assert!(
            result
                .inbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .outbound
                .ipv4_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert!(
            result
                .outbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        blocklist.assert();
    }

    #[test]
    fn test_retrieve_blocklists_splits_entries_by_direction() {
        let mut server = Server::new();
        let inbound_blocklist = server
            .mock("GET", "/inbound.txt")
            .with_status(200)
            .with_body("8.8.8.0/24\n")
            .create();
        let outbound_blocklist = server
            .mock("GET", "/outbound.txt")
            .with_status(200)
            .with_body("9.9.9.0/24\n")
            .create();

        let inbound_source = test_source(format!("{}/inbound.txt", server.url()));
        let mut outbound_source = test_source(format!("{}/outbound.txt", server.url()));
        outbound_source.direction = Direction::Outbound;
        let config = Config {
            blocklists: vec![inbound_source, outbound_source],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        assert_eq!(
            result.inbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["8.8.8.0/24".parse().unwrap()]
        );
        assert!(
            result
                .inbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert_eq!(
            result.outbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["9.9.9.0/24".parse().unwrap()]
        );
        assert!(
            result
                .outbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        inbound_blocklist.assert();
        outbound_blocklist.assert();
    }

    #[test]
    fn test_retrieve_blocklists_adds_both_direction_to_both_lists() {
        let mut server = Server::new();
        let both_blocklist = server
            .mock("GET", "/both.txt")
            .with_status(200)
            .with_body("4.4.4.0/24\n")
            .create();

        let mut both_source = test_source(format!("{}/both.txt", server.url()));
        both_source.direction = Direction::Both;
        let config = Config {
            blocklists: vec![both_source],
            allowlists: Vec::new(),
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        assert_eq!(
            result.inbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["4.4.4.0/24".parse().unwrap()]
        );
        assert!(
            result
                .inbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        assert_eq!(
            result.outbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["4.4.4.0/24".parse().unwrap()]
        );
        assert!(
            result
                .outbound
                .ipv6_networks()
                .collect::<Vec<_>>()
                .is_empty()
        );
        both_blocklist.assert();
    }

    #[test]
    fn test_retrieve_blocklists_applies_directional_allowlists() {
        let mut server = Server::new();
        let inbound_blocklist = server
            .mock("GET", "/inbound-blocklist.txt")
            .with_status(200)
            .with_body("8.8.8.0/24\n")
            .create();
        let outbound_blocklist = server
            .mock("GET", "/outbound-blocklist.txt")
            .with_status(200)
            .with_body("8.8.8.0/24\n")
            .create();
        let inbound_allowlist = server
            .mock("GET", "/inbound-allowlist.txt")
            .with_status(200)
            .with_body("8.8.8.0/25\n")
            .create();

        let inbound_blocklist_source =
            test_source(format!("{}/inbound-blocklist.txt", server.url()));
        let mut outbound_source = test_source(format!("{}/outbound-blocklist.txt", server.url()));
        outbound_source.direction = Direction::Outbound;
        let mut allowlist_source = test_source(format!("{}/inbound-allowlist.txt", server.url()));
        allowlist_source.list_type = ListType::Allowlist;
        let config = Config {
            blocklists: vec![inbound_blocklist_source, outbound_source],
            allowlists: vec![allowlist_source],
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        assert_eq!(
            result.inbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["8.8.8.128/25".parse().unwrap()]
        );
        assert_eq!(
            result.outbound.ipv4_networks().collect::<Vec<_>>(),
            vec!["8.8.8.0/24".parse().unwrap()]
        );
        inbound_blocklist.assert();
        outbound_blocklist.assert();
        inbound_allowlist.assert();
    }

    #[test]
    fn test_retrieve_blocklists_applies_both_direction_allowlists_to_both_outputs() {
        let mut server = Server::new();
        let blocklist = server
            .mock("GET", "/blocklist.txt")
            .with_status(200)
            .with_body("4.4.4.0/24\n")
            .create();
        let allowlist = server
            .mock("GET", "/allowlist.txt")
            .with_status(200)
            .with_body("4.4.4.0/25\n")
            .create();

        let mut blocklist_source = test_source(format!("{}/blocklist.txt", server.url()));
        blocklist_source.direction = Direction::Both;
        let mut allowlist_source = test_source(format!("{}/allowlist.txt", server.url()));
        allowlist_source.list_type = ListType::Allowlist;
        allowlist_source.direction = Direction::Both;
        let config = Config {
            blocklists: vec![blocklist_source],
            allowlists: vec![allowlist_source],
            geoip: None,
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: Default::default(),
        };
        let client = Client::new();

        let result = retrieve_blocklists(&client, &config).unwrap().blocklists;

        let expected: Vec<Ipv4Net> = vec!["4.4.4.128/25".parse().unwrap()];
        assert_eq!(result.inbound.ipv4_networks().collect::<Vec<_>>(), expected);
        assert_eq!(
            result.outbound.ipv4_networks().collect::<Vec<_>>(),
            expected
        );
        blocklist.assert();
        allowlist.assert();
    }
}
