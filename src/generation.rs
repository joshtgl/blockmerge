//! Retrieve configured sources and generate directional blocklists.

use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{
    ETAG, HeaderMap, HeaderName, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::config::{Config, ResiliencePolicy};
use crate::geoip::{GeoIpConfig, GeoIpEntries};
use crate::offline::sha256_hex;
use crate::ranges::{DirectionalBlocklists, IpRangeAccumulator};
use crate::source::{Direction, ListType};
use crate::state::{CachedSource, HttpValidators, StateFile};

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
    NotModified { name: String },
    Stale { name: String, failures: u32 },
    Unavailable { name: String },
    Expired { name: String, failures: u32 },
    Cached { name: String },
}

enum CachedHttpResponse {
    Modified {
        response: Response,
        validators: Option<HttpValidators>,
    },
    NotModified {
        body: Vec<u8>,
        cached_source: CachedSource,
    },
}

enum CachedTextResponse {
    Modified {
        body: String,
        validators: Option<HttpValidators>,
    },
    NotModified {
        body: String,
        cached_source: CachedSource,
    },
}

enum HttpResponse {
    Modified {
        response: Response,
        validators: Option<HttpValidators>,
    },
    NotModified {
        validators: Option<HttpValidators>,
    },
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

fn response_header(headers: &HeaderMap, name: HeaderName, source_name: &str) -> Option<String> {
    let value = headers.get(&name)?;
    match value.to_str() {
        Ok(value) => Some(value.to_string()),
        Err(_) => {
            eprintln!(
                "  Ignoring non-text {} response header for '{}'",
                name.as_str(),
                source_name
            );
            None
        }
    }
}

fn response_validators(
    headers: &HeaderMap,
    resource_key: &str,
    source_name: &str,
) -> Option<HttpValidators> {
    let etag = response_header(headers, ETAG, source_name);
    let last_modified = response_header(headers, LAST_MODIFIED, source_name);
    if etag.is_none() && last_modified.is_none() {
        None
    } else {
        Some(HttpValidators {
            resource_key: resource_key.to_string(),
            etag,
            last_modified,
        })
    }
}

fn send_http_request(
    client: &Client,
    source_name: &str,
    url: Url,
    stored_validators: Option<&HttpValidators>,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let resource_key = sha256_hex(url.as_str().as_bytes());
    let mut request = client.get(url);
    let mut sent_conditional = false;

    if let Some(validators) = stored_validators.filter(|value| value.resource_key == resource_key) {
        for (name, value) in [
            (IF_NONE_MATCH, validators.etag.as_deref()),
            (IF_MODIFIED_SINCE, validators.last_modified.as_deref()),
        ] {
            let Some(value) = value else {
                continue;
            };
            match HeaderValue::try_from(value) {
                Ok(value) => {
                    request = request.header(name, value);
                    sent_conditional = true;
                }
                Err(_) => eprintln!(
                    "  Ignoring invalid stored {} header for '{}'",
                    name.as_str(),
                    source_name
                ),
            }
        }
    }

    let response = request.send()?;
    let validators = response_validators(response.headers(), &resource_key, source_name);
    if response.status() == StatusCode::NOT_MODIFIED {
        if !sent_conditional {
            return Err(format!(
                "source '{}' returned HTTP 304 without a conditional request",
                source_name
            )
            .into());
        }
        return Ok(HttpResponse::NotModified { validators });
    }
    if !response.status().is_success() {
        return Err(format!(
            "HTTP {}: {}",
            response.status(),
            response
                .status()
                .canonical_reason()
                .unwrap_or("Unknown error")
        )
        .into());
    }
    Ok(HttpResponse::Modified {
        response,
        validators,
    })
}

fn merge_revalidated_validators(
    stored: &HttpValidators,
    returned: Option<HttpValidators>,
) -> HttpValidators {
    let Some(returned) = returned else {
        return stored.clone();
    };
    HttpValidators {
        resource_key: returned.resource_key,
        etag: returned.etag.or_else(|| stored.etag.clone()),
        last_modified: returned
            .last_modified
            .or_else(|| stored.last_modified.clone()),
    }
}

fn fetch_cached_http_response(
    client: &Client,
    source_name: &str,
    url: Url,
    conditional_enabled: bool,
    context: &mut RefreshContext,
) -> Result<CachedHttpResponse, Box<dyn std::error::Error>> {
    let existing_cache = context
        .state
        .source(source_name)
        .and_then(|status| status.cached_source.clone());
    let stored_validators = conditional_enabled
        .then_some(existing_cache.as_ref())
        .flatten()
        .and_then(|cached| cached.http_validators.as_ref());

    match send_http_request(client, source_name, url.clone(), stored_validators)? {
        HttpResponse::Modified {
            response,
            validators,
        } => Ok(CachedHttpResponse::Modified {
            response,
            validators,
        }),
        HttpResponse::NotModified { validators } => {
            let Some(mut cached_source) = existing_cache else {
                return Err(format!(
                    "source '{}' returned HTTP 304 without a cached body",
                    source_name
                )
                .into());
            };
            match read_persistent_cached_body(source_name, context) {
                Ok(Some(body)) => {
                    let stored = cached_source
                        .http_validators
                        .as_ref()
                        .ok_or("conditional response is missing stored validators")?;
                    cached_source.http_validators =
                        Some(merge_revalidated_validators(stored, validators));
                    Ok(CachedHttpResponse::NotModified {
                        body,
                        cached_source,
                    })
                }
                Ok(None) | Err(_) => {
                    eprintln!(
                        "  Cached source '{}' cannot satisfy HTTP 304; retrying unconditionally",
                        source_name
                    );
                    expire_source_cache(&context.cache_dir.clone(), source_name, context);
                    match send_http_request(client, source_name, url, None)? {
                        HttpResponse::Modified {
                            response,
                            validators,
                        } => Ok(CachedHttpResponse::Modified {
                            response,
                            validators,
                        }),
                        HttpResponse::NotModified { .. } => Err(format!(
                            "source '{}' returned HTTP 304 to an unconditional retry",
                            source_name
                        )
                        .into()),
                    }
                }
            }
        }
    }
}

fn fetch_cached_text_response(
    client: &Client,
    source_name: &str,
    url: Url,
    context: &mut RefreshContext,
) -> Result<CachedTextResponse, Box<dyn std::error::Error>> {
    match fetch_cached_http_response(client, source_name, url.clone(), true, context)? {
        CachedHttpResponse::Modified {
            response,
            validators,
        } => Ok(CachedTextResponse::Modified {
            body: response.text()?,
            validators,
        }),
        CachedHttpResponse::NotModified {
            body,
            cached_source,
        } => match String::from_utf8(body) {
            Ok(body) => Ok(CachedTextResponse::NotModified {
                body,
                cached_source,
            }),
            Err(_) => {
                eprintln!(
                    "  Cached source '{}' is not valid UTF-8; retrying unconditionally",
                    source_name
                );
                expire_source_cache(&context.cache_dir.clone(), source_name, context);
                match fetch_cached_http_response(client, source_name, url, false, context)? {
                    CachedHttpResponse::Modified {
                        response,
                        validators,
                    } => Ok(CachedTextResponse::Modified {
                        body: response.text()?,
                        validators,
                    }),
                    CachedHttpResponse::NotModified { .. } => Err(format!(
                        "source '{}' returned HTTP 304 to an unconditional retry",
                        source_name
                    )
                    .into()),
                }
            }
        },
    }
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
            let fetched = (|| {
                let source_url = source.url.as_deref().ok_or("source is missing url")?;
                println!("  Fetching from {}...", source_url);
                let url = Url::parse(source_url)?;
                fetch_cached_text_response(client, &source.name, url, context)
            })();
            match fetched {
                Ok(CachedTextResponse::Modified { body, validators }) => {
                    let cached_source = retain_or_write_cached_bytes(
                        &context.cache_dir,
                        &source.name,
                        body.as_bytes(),
                        validators,
                        context.state.source(&source.name),
                    )?;
                    let entry_count = parse_source_body(source, &body, &mut ranges);
                    println!("  Found {entry_count} entries");
                    context.state.mark_success(
                        &source.name,
                        Utc::now().to_rfc3339(),
                        cached_source,
                    );
                    successful_sources.push(source.name.clone());
                    source_outcomes.push(SourceRefreshOutcome::Fresh {
                        name: source.name.clone(),
                    });
                }
                Ok(CachedTextResponse::NotModified {
                    body,
                    cached_source,
                }) => {
                    let entry_count = parse_source_body(source, &body, &mut ranges);
                    println!("  Source unchanged; found {entry_count} cached entries");
                    context.state.mark_success(
                        &source.name,
                        Utc::now().to_rfc3339(),
                        cached_source,
                    );
                    successful_sources.push(source.name.clone());
                    source_outcomes.push(SourceRefreshOutcome::NotModified {
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
        Ok(true) => {
            println!(
                "  Fetching {:?} country database for '{}'...",
                geoip.service, geoip.name
            );
            let refreshed = geoip.database_request_url().and_then(|url| {
                fetch_cached_http_response(
                    client,
                    &geoip.name,
                    url,
                    context.policy.enabled,
                    context,
                )
            });
            match refreshed {
                Ok(CachedHttpResponse::Modified {
                    response,
                    validators,
                }) => response
                    .bytes()
                    .map_err(Into::into)
                    .and_then(|body| {
                        let entries = geoip.parse_database(&body)?;
                        let cached = retain_or_write_cached_bytes(
                            &context.cache_dir,
                            &geoip.name,
                            &body,
                            validators,
                            context.state.source(&geoip.name),
                        )?;
                        context
                            .state
                            .mark_success(&geoip.name, Utc::now().to_rfc3339(), cached);
                        Ok(entries)
                    })
                    .inspect(|_| {
                        successful_sources.push(geoip.name.clone());
                        outcomes.push(SourceRefreshOutcome::Fresh {
                            name: geoip.name.clone(),
                        });
                    }),
                Ok(CachedHttpResponse::NotModified {
                    body,
                    cached_source,
                }) => geoip.parse_database(&body).inspect(|_| {
                    context
                        .state
                        .mark_success(&geoip.name, Utc::now().to_rfc3339(), cached_source);
                    successful_sources.push(geoip.name.clone());
                    outcomes.push(SourceRefreshOutcome::NotModified {
                        name: geoip.name.clone(),
                    });
                }),
                Err(error) => Err(error),
            }
            .map(Some)
            .unwrap_or_else(|error| {
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
            })
        }
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

#[cfg(test)]
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
        http_validators: None,
    })
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn retain_or_write_cached_bytes(
    cache_dir: &Path,
    source_name: &str,
    body: &[u8],
    http_validators: Option<HttpValidators>,
    existing_status: Option<&crate::state::BlocklistStatus>,
) -> Result<CachedSource, Box<dyn std::error::Error>> {
    let sha256 = sha256_hex(body);
    if let Some(existing) = existing_status.and_then(|status| status.cached_source.as_ref())
        && existing.sha256 == sha256
        && checked_cache_path(cache_dir, &existing.cache_file)
            .ok()
            .and_then(|path| sha256_file(&path).ok())
            .is_some_and(|cached_sha256| cached_sha256 == sha256)
    {
        let mut retained = existing.clone();
        retained.http_validators = http_validators;
        return Ok(retained);
    }

    let mut cached = write_cached_bytes(cache_dir, source_name, body)?;
    cached.http_validators = http_validators;
    Ok(cached)
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
    use mockito::{Matcher, Server};
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

    fn cached_with_validators(
        cache_dir: &Path,
        source_name: &str,
        body: &[u8],
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> CachedSource {
        let mut cached = write_cached_bytes(cache_dir, source_name, body).unwrap();
        cached.http_validators = Some(HttpValidators {
            resource_key: sha256_hex(url.as_bytes()),
            etag: etag.map(ToString::to_string),
            last_modified: last_modified.map(ToString::to_string),
        });
        cached
    }

    #[test]
    fn last_modified_validator_is_sent_without_an_etag() {
        let mut server = Server::new();
        let url = format!("{}/source.txt", server.url());
        let unchanged = server
            .mock("GET", "/source.txt")
            .match_header("if-none-match", Matcher::Missing)
            .match_header("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT")
            .with_status(304)
            .create();
        let validators = HttpValidators {
            resource_key: sha256_hex(url.as_bytes()),
            etag: None,
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
        };

        let response = send_http_request(
            &Client::new(),
            "alpha",
            Url::parse(&url).unwrap(),
            Some(&validators),
        )
        .unwrap();

        assert!(matches!(response, HttpResponse::NotModified { .. }));
        unchanged.assert();
    }

    #[test]
    fn malformed_stored_validator_is_ignored() {
        let mut server = Server::new();
        let url = format!("{}/source.txt", server.url());
        let fresh = server
            .mock("GET", "/source.txt")
            .match_header("if-none-match", Matcher::Missing)
            .with_status(200)
            .with_body("192.0.2.0/24\n")
            .create();
        let validators = HttpValidators {
            resource_key: sha256_hex(url.as_bytes()),
            etag: Some("invalid\nvalue".to_string()),
            last_modified: None,
        };

        let response = send_http_request(
            &Client::new(),
            "alpha",
            Url::parse(&url).unwrap(),
            Some(&validators),
        )
        .unwrap();

        assert!(matches!(response, HttpResponse::Modified { .. }));
        fresh.assert();
    }

    #[test]
    fn unsolicited_not_modified_response_is_rejected() {
        let mut server = Server::new();
        let url = format!("{}/source.txt", server.url());
        let unsolicited = server
            .mock("GET", "/source.txt")
            .match_header("if-none-match", Matcher::Missing)
            .match_header("if-modified-since", Matcher::Missing)
            .with_status(304)
            .create();

        let error = send_http_request(&Client::new(), "alpha", Url::parse(&url).unwrap(), None)
            .err()
            .unwrap();

        assert!(error.to_string().contains("without a conditional request"));
        unsolicited.assert();
    }

    #[test]
    fn normal_source_revalidates_with_etag_and_last_modified() {
        let mut server = Server::new();
        let url = format!("{}/source.txt", server.url());
        let first = server
            .mock("GET", "/source.txt")
            .match_header("if-none-match", Matcher::Missing)
            .match_header("if-modified-since", Matcher::Missing)
            .with_status(200)
            .with_header("etag", "\"v1\"")
            .with_header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")
            .with_body("192.0.2.0/24\n")
            .create();
        let directory = tempfile::tempdir().unwrap();
        let mut context = RefreshContext::new(
            ResilienceConfig::default().policy().unwrap(),
            StateFile::default(),
            directory.path().to_path_buf(),
        );
        let config = resilient_config(remote_source("alpha", url));

        let initial =
            retrieve_blocklists_with_resilience(&Client::new(), &config, &mut context).unwrap();
        assert_eq!(
            initial.source_outcomes,
            vec![SourceRefreshOutcome::Fresh {
                name: "alpha".to_string()
            }]
        );
        first.assert();
        first.remove();

        let previous_status = context.state.sources.get_mut("alpha").unwrap();
        previous_status.last_success_at = Some("2000-01-01T00:00:00Z".to_string());
        previous_status.last_attempt_at = Some("2000-01-01T00:00:00Z".to_string());
        previous_status.consecutive_failures = 2;
        let unchanged = server
            .mock("GET", "/source.txt")
            .match_header("if-none-match", "\"v1\"")
            .match_header("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT")
            .with_status(304)
            .with_header("etag", "\"v2\"")
            .create();

        let revalidated =
            retrieve_blocklists_with_resilience(&Client::new(), &config, &mut context).unwrap();

        assert_eq!(
            revalidated.source_outcomes,
            vec![SourceRefreshOutcome::NotModified {
                name: "alpha".to_string()
            }]
        );
        assert_eq!(
            revalidated
                .blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>(),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
        let status = context.state.source("alpha").unwrap();
        assert_eq!(status.consecutive_failures, 0);
        assert_ne!(
            status.last_success_at.as_deref(),
            Some("2000-01-01T00:00:00Z")
        );
        let validators = status
            .cached_source
            .as_ref()
            .unwrap()
            .http_validators
            .as_ref()
            .unwrap();
        assert_eq!(validators.etag.as_deref(), Some("\"v2\""));
        assert_eq!(
            validators.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
        unchanged.assert();
    }

    #[test]
    fn corrupt_cache_after_304_is_retried_unconditionally() {
        let mut server = Server::new();
        let url = format!("{}/source.txt", server.url());
        let directory = tempfile::tempdir().unwrap();
        let cached = cached_with_validators(
            directory.path(),
            "alpha",
            b"192.0.2.0/24\n",
            &url,
            Some("\"v1\""),
            None,
        );
        std::fs::write(directory.path().join(&cached.cache_file), "corrupt\n").unwrap();
        let mut state = StateFile::default();
        state.mark_success("alpha", Utc::now().to_rfc3339(), cached);
        let mut context = RefreshContext::new(
            ResilienceConfig::default().policy().unwrap(),
            state,
            directory.path().to_path_buf(),
        );
        let not_modified = server
            .mock("GET", "/source.txt")
            .match_header("if-none-match", "\"v1\"")
            .with_status(304)
            .create();
        let replacement = server
            .mock("GET", "/source.txt")
            .match_header("if-none-match", Matcher::Missing)
            .with_status(200)
            .with_header("etag", "\"v2\"")
            .with_body("198.51.100.0/24\n")
            .create();

        let retrieved = retrieve_blocklists_with_resilience(
            &Client::new(),
            &resilient_config(remote_source("alpha", url)),
            &mut context,
        )
        .unwrap();

        assert_eq!(
            retrieved.source_outcomes,
            vec![SourceRefreshOutcome::Fresh {
                name: "alpha".to_string()
            }]
        );
        assert_eq!(
            retrieved
                .blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>(),
            vec!["198.51.100.0/24".parse().unwrap()]
        );
        not_modified.assert();
        replacement.assert();
    }

    #[test]
    fn changed_resource_identity_does_not_send_old_validators() {
        let mut server = Server::new();
        let old_url = format!("{}/old.txt", server.url());
        let new_url = format!("{}/new.txt", server.url());
        let directory = tempfile::tempdir().unwrap();
        let cached = cached_with_validators(
            directory.path(),
            "alpha",
            b"192.0.2.0/24\n",
            &old_url,
            Some("\"old\""),
            None,
        );
        let mut state = StateFile::default();
        state.mark_success("alpha", Utc::now().to_rfc3339(), cached);
        let mut context = RefreshContext::new(
            ResilienceConfig::default().policy().unwrap(),
            state,
            directory.path().to_path_buf(),
        );
        let fresh = server
            .mock("GET", "/new.txt")
            .match_header("if-none-match", Matcher::Missing)
            .with_status(200)
            .with_body("198.51.100.0/24\n")
            .create();

        let retrieved = retrieve_blocklists_with_resilience(
            &Client::new(),
            &resilient_config(remote_source("alpha", new_url)),
            &mut context,
        )
        .unwrap();

        assert!(matches!(
            retrieved.source_outcomes.as_slice(),
            [SourceRefreshOutcome::Fresh { .. }]
        ));
        assert!(
            context
                .state
                .source("alpha")
                .unwrap()
                .cached_source
                .as_ref()
                .unwrap()
                .http_validators
                .is_none()
        );
        fresh.assert();
    }

    #[test]
    fn due_geoip_source_uses_conditional_request() {
        let mut server = Server::new();
        let url = format!("{}/country.zip", server.url());
        let directory = tempfile::tempdir().unwrap();
        let cached = cached_with_validators(
            directory.path(),
            "iplocate-country",
            &geoip_zip(),
            &url,
            Some("\"geo-v1\""),
            None,
        );
        let mut state = StateFile::default();
        state.mark_success(
            "iplocate-country",
            "2000-01-01T00:00:00Z".to_string(),
            cached,
        );
        let mut context = RefreshContext::new(
            ResilienceConfig::default().policy().unwrap(),
            state,
            directory.path().to_path_buf(),
        );
        let unchanged = server
            .mock("GET", "/country.zip")
            .match_header("if-none-match", "\"geo-v1\"")
            .with_status(304)
            .create();
        let config = Config {
            blocklists: Vec::new(),
            allowlists: Vec::new(),
            geoip: Some(geoip_config(url)),
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: ResilienceConfig::default(),
        };

        let retrieved =
            retrieve_blocklists_with_resilience(&Client::new(), &config, &mut context).unwrap();

        assert_eq!(
            retrieved.source_outcomes,
            vec![SourceRefreshOutcome::NotModified {
                name: "iplocate-country".to_string()
            }]
        );
        assert_eq!(
            retrieved
                .blocklists
                .inbound
                .ipv4_networks()
                .collect::<Vec<_>>(),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
        unchanged.assert();
    }

    #[test]
    fn resilience_disabled_suppresses_geoip_conditionals() {
        let mut server = Server::new();
        let url = format!("{}/country.zip", server.url());
        let directory = tempfile::tempdir().unwrap();
        let cached = cached_with_validators(
            directory.path(),
            "iplocate-country",
            &geoip_zip(),
            &url,
            Some("\"geo-v1\""),
            None,
        );
        let mut state = StateFile::default();
        state.mark_success(
            "iplocate-country",
            "2000-01-01T00:00:00Z".to_string(),
            cached,
        );
        let mut context = RefreshContext::new(
            ResiliencePolicy {
                enabled: false,
                max_stale_age: std::time::Duration::from_secs(1),
                max_consecutive_failures: 1,
            },
            state,
            directory.path().to_path_buf(),
        );
        let fresh = server
            .mock("GET", "/country.zip")
            .match_header("if-none-match", Matcher::Missing)
            .with_status(200)
            .with_body(geoip_zip())
            .create();
        let config = Config {
            blocklists: Vec::new(),
            allowlists: Vec::new(),
            geoip: Some(geoip_config(url)),
            web: None,
            output: Default::default(),
            schedule: None,
            resilience: ResilienceConfig::default(),
        };

        let retrieved =
            retrieve_blocklists_with_resilience(&Client::new(), &config, &mut context).unwrap();

        assert!(matches!(
            retrieved.source_outcomes.as_slice(),
            [SourceRefreshOutcome::Fresh { .. }]
        ));
        fresh.assert();
    }

    #[test]
    fn identical_body_retains_existing_cache_file() {
        let directory = tempfile::tempdir().unwrap();
        let body = b"192.0.2.0/24\n";
        let legacy_path = directory.path().join("legacy.body");
        std::fs::write(&legacy_path, body).unwrap();
        let status = crate::state::BlocklistStatus {
            last_success_at: Some(Utc::now().to_rfc3339()),
            last_attempt_at: None,
            consecutive_failures: 0,
            cached_source: Some(CachedSource {
                cache_file: "legacy.body".to_string(),
                sha256: sha256_hex(body),
                http_validators: None,
            }),
        };
        let validators = HttpValidators {
            resource_key: "resource".to_string(),
            etag: Some("\"v2\"".to_string()),
            last_modified: None,
        };

        let retained = retain_or_write_cached_bytes(
            directory.path(),
            "alpha",
            body,
            Some(validators.clone()),
            Some(&status),
        )
        .unwrap();

        assert_eq!(retained.cache_file, "legacy.body");
        assert_eq!(retained.http_validators, Some(validators));
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
