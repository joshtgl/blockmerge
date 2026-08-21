//! IPLocate IP-to-country CSV retrieval and filtering.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::time::Duration;

use ipnet::IpNet;
use reqwest::{Url, blocking::Client};
use serde::Deserialize;
use zip::ZipArchive;

use crate::ranges::IpRangeAccumulator;
use crate::source::Direction;

const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const IPLOCATE_DOWNLOAD_URL: &str =
    "https://www.iplocate.io/download/ip-to-country.csv?variant=daily";

/// Supported GeoIP download services.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GeoIpService {
    Iplocate,
    Custom,
}

/// Compression and encoding used by a custom GeoIP CSV service.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CustomGeoIpFormat {
    ZipCsv,
    Csv,
}

/// Settings for a custom service whose records can be mapped to country blocks.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomGeoIpConfig {
    pub download_url: String,
    pub format: CustomGeoIpFormat,
    #[serde(default = "default_network_column")]
    pub network_column: String,
    #[serde(default = "default_country_code_column")]
    pub country_code_column: String,
    #[serde(default)]
    pub api_key_query_parameter: Option<String>,
}

/// Configuration for a supported IP-to-country service.
#[derive(Debug, Clone, Deserialize)]
pub struct GeoIpConfig {
    #[serde(default = "default_geoip_name")]
    pub name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: String,
    pub service: GeoIpService,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub custom: Option<CustomGeoIpConfig>,
    #[serde(default)]
    pub country_rules: Vec<CountryRule>,
}

#[derive(Debug, Clone)]
struct GeoIpDownloadSpec {
    url: Url,
    format: CustomGeoIpFormat,
    network_column: String,
    country_code_column: String,
    api_key_query_parameter: Option<String>,
}

/// Country codes to add to a directional blocklist.
#[derive(Debug, Clone, Deserialize)]
pub struct CountryRule {
    pub country_codes: Vec<String>,
    #[serde(default)]
    pub direction: Direction,
}

/// Parsed policy used to schedule GeoIP retrieval.
#[derive(Debug, Clone)]
pub struct GeoIpPolicy {
    pub refresh_interval: Duration,
}

/// Directional networks selected from a GeoIP database.
#[derive(Debug, Default)]
pub struct GeoIpEntries {
    pub inbound: IpRangeAccumulator,
    pub outbound: IpRangeAccumulator,
    /// CSV records retained because their country code matches a configured rule.
    pub selected_records: usize,
    /// CSV records excluded because their country code has no configured rule.
    pub excluded_records: usize,
}

fn default_geoip_name() -> String {
    "geoip".to_string()
}

fn default_enabled() -> bool {
    true
}

fn default_refresh_interval() -> String {
    "24h".to_string()
}

fn default_network_column() -> String {
    "network".to_string()
}

fn default_country_code_column() -> String {
    "country_code".to_string()
}

impl GeoIpConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.name.trim().is_empty() {
            return Err("geoip name must not be empty".into());
        }
        if self.enabled && self.country_rules.is_empty() {
            return Err("enabled geoip configuration requires at least one country rule".into());
        }
        self.policy()?;
        for rule in &self.country_rules {
            if rule.country_codes.is_empty() {
                return Err("geoip country rule must include at least one country code".into());
            }
            for code in &rule.country_codes {
                if !is_country_code(code) {
                    return Err(format!(
                        "invalid geoip country code '{code}'; use two uppercase letters"
                    )
                    .into());
                }
            }
        }
        self.download_spec()?;
        Ok(())
    }

    pub fn policy(&self) -> Result<GeoIpPolicy, Box<dyn std::error::Error>> {
        let refresh_interval = crate::schedule::parse_interval_duration(&self.refresh_interval)?;
        if refresh_interval < MIN_REFRESH_INTERVAL {
            return Err("geoip refresh_interval must be at least 24h".into());
        }
        Ok(GeoIpPolicy { refresh_interval })
    }

    fn api_key(&self) -> Option<String> {
        self.api_key_env
            .as_deref()
            .and_then(|name| std::env::var(name).ok())
            .filter(|key| !key.is_empty())
            .or_else(|| self.api_key.clone().filter(|key| !key.is_empty()))
    }

    fn download_spec(&self) -> Result<GeoIpDownloadSpec, Box<dyn std::error::Error>> {
        match self.service {
            GeoIpService::Iplocate => {
                if self.custom.is_some() {
                    return Err(
                        "geoip custom settings are only valid when service = 'custom'".into(),
                    );
                }
                if self.api_key().is_none() {
                    return Err("geoip service 'iplocate' requires api_key_env or api_key".into());
                }
                Ok(GeoIpDownloadSpec {
                    url: Url::parse(IPLOCATE_DOWNLOAD_URL)?,
                    format: CustomGeoIpFormat::ZipCsv,
                    network_column: default_network_column(),
                    country_code_column: default_country_code_column(),
                    api_key_query_parameter: Some("apikey".to_string()),
                })
            }
            GeoIpService::Custom => {
                let custom = self
                    .custom
                    .as_ref()
                    .ok_or("geoip service 'custom' requires a [geoip.custom] section")?;
                let url = Url::parse(&custom.download_url)?;
                match (&custom.api_key_query_parameter, self.api_key()) {
                    (Some(_), None) => {
                        return Err(
                            "geoip custom api_key_query_parameter requires api_key_env or api_key"
                                .into(),
                        );
                    }
                    (None, Some(_)) => {
                        return Err(
                            "geoip credentials require custom api_key_query_parameter".into()
                        );
                    }
                    _ => {}
                }
                if let Some(parameter) = custom.api_key_query_parameter.as_deref() {
                    if parameter.is_empty() {
                        return Err("geoip custom api_key_query_parameter must not be empty".into());
                    }
                    if url.query_pairs().any(|(key, _)| key == parameter) {
                        return Err("geoip custom download_url must not include the API key query parameter".into());
                    }
                }
                if custom.network_column.is_empty() || custom.country_code_column.is_empty() {
                    return Err("geoip custom CSV column names must not be empty".into());
                }
                Ok(GeoIpDownloadSpec {
                    url,
                    format: custom.format,
                    network_column: custom.network_column.clone(),
                    country_code_column: custom.country_code_column.clone(),
                    api_key_query_parameter: custom.api_key_query_parameter.clone(),
                })
            }
        }
    }

    /// Return the credential-free source URL recorded in offline manifests.
    pub fn download_url(&self) -> Result<Url, Box<dyn std::error::Error>> {
        Ok(self.download_spec()?.url)
    }

    /// Return the effective database URL used for an HTTP request.
    pub(crate) fn database_request_url(&self) -> Result<Url, Box<dyn std::error::Error>> {
        let spec = self.download_spec()?;
        let mut url = spec.url;
        if let Some(parameter) = spec.api_key_query_parameter {
            let api_key = self.api_key().ok_or("missing GeoIP API key")?;
            url.query_pairs_mut().append_pair(&parameter, &api_key);
        }
        Ok(url)
    }

    /// Download the configured database without logging its credential-bearing URL.
    pub fn fetch_database(&self, client: &Client) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let url = self.database_request_url()?;
        println!(
            "  Fetching {:?} country database for '{}'...",
            self.service, self.name
        );
        let response = client
            .get(url)
            .send()
            .map_err(|_| "failed to request GeoIP country database")?;
        if !response.status().is_success() {
            return Err(format!("GeoIP service returned HTTP {}", response.status()).into());
        }
        Ok(response
            .bytes()
            .map_err(|_| "failed to read GeoIP country database")?
            .to_vec())
    }

    pub fn parse_database(&self, body: &[u8]) -> Result<GeoIpEntries, Box<dyn std::error::Error>> {
        let directions = self.country_directions();
        let mut matched = HashSet::new();
        let spec = self.download_spec()?;
        let csv_body = match spec.format {
            CustomGeoIpFormat::Csv => body.to_vec(),
            CustomGeoIpFormat::ZipCsv => read_zip_csv(body)?,
        };

        let mut reader = csv::ReaderBuilder::new()
            .trim(csv::Trim::All)
            .from_reader(csv_body.as_slice());
        let headers = reader.headers()?.clone();
        let network_index = headers
            .iter()
            .position(|header| header == spec.network_column)
            .ok_or_else(|| format!("GeoIP CSV is missing the '{}' header", spec.network_column))?;
        let country_index = headers
            .iter()
            .position(|header| header == spec.country_code_column)
            .ok_or_else(|| {
                format!(
                    "GeoIP CSV is missing the '{}' header",
                    spec.country_code_column
                )
            })?;

        let mut entries = GeoIpEntries::default();
        for record in reader.records() {
            let record = record?;
            let country = record
                .get(country_index)
                .ok_or("GeoIP CSV row is missing country code")?;
            let Some(direction) = directions.get(country) else {
                entries.excluded_records += 1;
                continue;
            };
            let network = record
                .get(network_index)
                .ok_or("GeoIP CSV row is missing network")?
                .parse::<IpNet>()?;
            matched.insert(country.to_string());
            entries.selected_records += 1;
            match direction {
                Direction::Inbound => entries.inbound.add(network),
                Direction::Outbound => entries.outbound.add(network),
                Direction::Both => {
                    entries.inbound.add(network);
                    entries.outbound.add(network);
                }
            }
        }

        let missing: Vec<_> = directions
            .keys()
            .filter(|country| !matched.contains(*country))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "GeoIP database has no networks for configured countries: {}",
                missing.join(", ")
            )
            .into());
        }
        Ok(entries)
    }

    fn country_directions(&self) -> HashMap<String, Direction> {
        let mut directions = HashMap::new();
        for rule in &self.country_rules {
            for country in &rule.country_codes {
                directions
                    .entry(country.clone())
                    .and_modify(|existing| *existing = merge_directions(*existing, rule.direction))
                    .or_insert(rule.direction);
            }
        }
        directions
    }
}

fn read_zip_csv(body: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut archive = ZipArchive::new(Cursor::new(body))?;
    let csv_index = (0..archive.len())
        .find(|index| {
            archive
                .by_index(*index)
                .is_ok_and(|file| file.name().ends_with(".csv"))
        })
        .ok_or("GeoIP ZIP does not contain a CSV file")?;
    let mut csv_file = archive.by_index(csv_index)?;
    let mut csv_body = Vec::new();
    csv_file.read_to_end(&mut csv_body)?;
    Ok(csv_body)
}

fn is_country_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn merge_directions(left: Direction, right: Direction) -> Direction {
    if left == right { left } else { Direction::Both }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn config() -> GeoIpConfig {
        GeoIpConfig {
            name: "geoip".to_string(),
            enabled: true,
            refresh_interval: "24h".to_string(),
            service: GeoIpService::Custom,
            api_key_env: None,
            api_key: None,
            custom: Some(CustomGeoIpConfig {
                download_url: "https://example.com/ip-to-country.csv".to_string(),
                format: CustomGeoIpFormat::ZipCsv,
                network_column: "network".to_string(),
                country_code_column: "country_code".to_string(),
                api_key_query_parameter: None,
            }),
            country_rules: vec![CountryRule {
                country_codes: vec!["US".to_string()],
                direction: Direction::Both,
            }],
        }
    }

    fn zip_csv(csv: &str) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "ip-to-country.csv",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(csv.as_bytes()).unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn parses_selected_ipv4_and_ipv6_networks() {
        let entries = config().parse_database(&zip_csv(
            "network,country,country_code,continent_code\n192.0.2.0/24,Example,US,NA\n2001:db8::/32,Example,US,NA\n198.51.100.0/24,Else,CA,NA\n",
        )).unwrap();
        assert_eq!(entries.inbound.len(), 2);
        assert_eq!(entries.outbound.len(), 2);
        assert_eq!(entries.selected_records, 2);
        assert_eq!(entries.excluded_records, 1);
    }

    #[test]
    fn rejects_short_refresh_interval() {
        let mut config = config();
        config.refresh_interval = "23h".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn iplocate_owns_its_download_contract() {
        let mut config = config();
        config.service = GeoIpService::Iplocate;
        config.custom = None;
        config.api_key = Some("test-key".to_string());

        let spec = config.download_spec().unwrap();
        assert_eq!(spec.url.as_str(), IPLOCATE_DOWNLOAD_URL);
        assert_eq!(spec.format, CustomGeoIpFormat::ZipCsv);
        assert_eq!(spec.api_key_query_parameter.as_deref(), Some("apikey"));
    }

    #[test]
    fn custom_plain_csv_uses_configured_columns() {
        let mut config = config();
        let custom = config.custom.as_mut().unwrap();
        custom.format = CustomGeoIpFormat::Csv;
        custom.network_column = "cidr".to_string();
        custom.country_code_column = "country".to_string();

        let entries = config
            .parse_database(b"cidr,country\n192.0.2.0/24,US\n198.51.100.0/24,CA\n")
            .unwrap();
        assert_eq!(entries.selected_records, 1);
        assert_eq!(
            entries
                .inbound
                .finalize()
                .ipv4_networks()
                .collect::<Vec<_>>(),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn custom_api_key_parameter_requires_a_credential() {
        let mut config = config();
        config.custom.as_mut().unwrap().api_key_query_parameter = Some("token".to_string());
        assert!(config.validate().is_err());
    }
}
