//! Configuration model and loading.

use std::collections::HashSet;
use std::fs;
use std::time::Duration;

use serde::Deserialize;
use static_web_server::settings::file as sws_file;

use crate::geoip::GeoIpConfig;
use crate::source::SourceConfig;

/// Top-level configuration containing all list sources.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub blocklists: Vec<SourceConfig>,
    #[serde(default)]
    pub allowlists: Vec<SourceConfig>,
    #[serde(default)]
    pub geoip: Option<GeoIpConfig>,
    #[serde(default)]
    pub web: Option<WebConfig>,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub schedule: Option<ScheduleConfig>,
    #[serde(default)]
    pub resilience: ResilienceConfig,
}

/// Static Web Server settings used by the web binary.
pub type WebConfig = sws_file::Settings;

/// Settings controlling generated blocklist files.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OutputConfig {
    /// Prefix generated files with a Blockmerge timestamp comment.
    #[serde(default = "default_timestamp_header")]
    pub timestamp_header: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            timestamp_header: default_timestamp_header(),
        }
    }
}

fn default_timestamp_header() -> bool {
    true
}

/// Refresh schedule configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ScheduleConfig {
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub cron: Option<String>,
    #[serde(default = "default_run_on_startup")]
    pub run_on_startup: bool,
}

fn default_run_on_startup() -> bool {
    true
}

/// Policy controlling cached fallback after source retrieval failures.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ResilienceConfig {
    #[serde(default = "default_resilience_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_stale_age")]
    pub max_stale_age: String,
    #[serde(default = "default_max_consecutive_failures")]
    pub max_consecutive_failures: u32,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            enabled: default_resilience_enabled(),
            max_stale_age: default_max_stale_age(),
            max_consecutive_failures: default_max_consecutive_failures(),
        }
    }
}

/// Parsed resilience settings used at refresh time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResiliencePolicy {
    pub enabled: bool,
    pub max_stale_age: Duration,
    pub max_consecutive_failures: u32,
}

fn default_resilience_enabled() -> bool {
    true
}

fn default_max_stale_age() -> String {
    "24h".to_string()
}

fn default_max_consecutive_failures() -> u32 {
    4
}

impl ResilienceConfig {
    /// Validate and parse the configured resilience settings.
    pub fn policy(&self) -> Result<ResiliencePolicy, Box<dyn std::error::Error>> {
        let max_stale_age = crate::schedule::parse_interval_duration(&self.max_stale_age)?;
        if max_stale_age.is_zero() {
            return Err("resilience max_stale_age must be greater than zero".into());
        }
        if self.max_consecutive_failures == 0 {
            return Err("resilience max_consecutive_failures must be greater than zero".into());
        }
        Ok(ResiliencePolicy {
            enabled: self.enabled,
            max_stale_age,
            max_consecutive_failures: self.max_consecutive_failures,
        })
    }
}

impl Config {
    /// Iterate over blocklist and allowlist sources.
    pub fn sources(&self) -> impl Iterator<Item = &SourceConfig> {
        self.blocklists.iter().chain(self.allowlists.iter())
    }

    /// Return the configured source with `name`.
    pub fn source_by_name(&self, name: &str) -> Option<&SourceConfig> {
        self.sources().find(|source| source.name == name)
    }

    /// Return the configured GeoIP source with `name`.
    pub fn geoip_by_name(&self, name: &str) -> Option<&GeoIpConfig> {
        self.geoip.as_ref().filter(|geoip| geoip.name == name)
    }

    /// Return the total configured source count.
    pub fn source_count(&self) -> usize {
        self.blocklists.len() + self.allowlists.len() + usize::from(self.geoip_enabled())
    }

    pub fn geoip_enabled(&self) -> bool {
        self.geoip.as_ref().is_some_and(|geoip| geoip.enabled)
    }

    /// Return refresh scheduling settings when present.
    pub fn schedule_config(&self) -> Result<&ScheduleConfig, Box<dyn std::error::Error>> {
        self.schedule
            .as_ref()
            .ok_or_else(|| "missing required [schedule] config section".into())
    }

    /// Return validated source-fallback policy.
    pub fn resilience_policy(&self) -> Result<ResiliencePolicy, Box<dyn std::error::Error>> {
        self.resilience.policy()
    }
}

/// Load configuration from a TOML file.
pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&content)?;

    for source in &mut config.blocklists {
        source.list_type = crate::source::ListType::Blocklist;
    }
    for source in &mut config.allowlists {
        source.list_type = crate::source::ListType::Allowlist;
    }

    let mut names = HashSet::new();
    for source in config.sources() {
        if !names.insert(source.name.clone()) {
            return Err(format!("duplicate source name '{}'", source.name).into());
        }
    }
    if let Some(geoip) = config.geoip.as_ref() {
        geoip.validate()?;
        if !names.insert(geoip.name.clone()) {
            return Err(format!("duplicate source name '{}'", geoip.name).into());
        }
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::source::{Direction, ListType};

    #[test]
    fn loads_sources_with_their_containing_list_type() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("blockmerge.toml");
        fs::write(
            &path,
            r#"
[[blocklists]]
name = "blocked"
net_list = ["192.0.2.0/24"]

[[allowlists]]
name = "allowed"
net_list = ["198.51.100.0/24"]
"#,
        )
        .unwrap();

        let config = load_config(path.to_str().unwrap()).unwrap();

        assert_eq!(config.blocklists[0].list_type, ListType::Blocklist);
        assert_eq!(config.allowlists[0].list_type, ListType::Allowlist);
        assert_eq!(
            config.source_by_name("allowed").unwrap().direction,
            Direction::Inbound
        );
    }

    #[test]
    fn rejects_duplicate_source_names() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("blockmerge.toml");
        fs::write(
            &path,
            r#"
[[blocklists]]
name = "duplicate"
net_list = ["192.0.2.0/24"]

[[allowlists]]
name = "duplicate"
net_list = ["198.51.100.0/24"]
"#,
        )
        .unwrap();

        assert!(
            load_config(path.to_str().unwrap())
                .unwrap_err()
                .to_string()
                .contains("duplicate source name")
        );
    }

    #[test]
    fn loads_geoip_rules_and_rejects_a_short_refresh_interval() {
        let config: Config = toml::from_str(
            r#"
[geoip]
service = "custom"
refresh_interval = "24h"

[geoip.custom]
download_url = "https://example.com/ip-to-country.csv"
format = "csv"

[[geoip.country_rules]]
country_codes = ["US"]
direction = "both"
"#,
        )
        .unwrap();
        assert_eq!(config.geoip.as_ref().unwrap().name, "geoip");
        config.geoip.as_ref().unwrap().validate().unwrap();

        let invalid: Config = toml::from_str(
            r#"
[geoip]
service = "custom"
refresh_interval = "1h"

[geoip.custom]
download_url = "https://example.com/ip-to-country.csv"
format = "csv"

[[geoip.country_rules]]
country_codes = ["US"]
"#,
        )
        .unwrap();
        assert!(invalid.geoip.as_ref().unwrap().validate().is_err());
    }

    #[test]
    fn requires_a_geoip_download_url() {
        let error = toml::from_str::<Config>(
            r#"
[geoip]
service = "custom"

[geoip.custom]
format = "csv"

[[geoip.country_rules]]
country_codes = ["US"]
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("download_url"));
    }

    #[test]
    fn defaults_resilience_and_validates_overrides() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.resilience.enabled);
        assert!(config.output.timestamp_header);
        assert_eq!(
            config.resilience_policy().unwrap().max_consecutive_failures,
            4
        );

        let invalid: Config = toml::from_str(
            r#"
[resilience]
max_stale_age = "0s"
max_consecutive_failures = 0
"#,
        )
        .unwrap();
        assert!(invalid.resilience_policy().is_err());
    }

    #[test]
    fn allows_timestamp_headers_to_be_disabled() {
        let config: Config = toml::from_str(
            r#"
[output]
timestamp_header = false
"#,
        )
        .unwrap();

        assert!(!config.output.timestamp_header);
    }

    #[test]
    fn test_load_config_valid() {
        let toml_content = r#"
            [[blocklists]]
            name = "source1"
            url = "http://example.com/list1.txt"
            enabled = true

            [[allowlists]]
            name = "source2"
            url = "http://example.com/list2.txt"
            comment_char = "!"
            field_separator = "\t"
            extract_field = 2
            net_json = "prefixes/ipv4Prefix"
            net_list = ["10.0.0.0/8", "::1/128"]
            rate_limited = true
            enabled = false
        "#;
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_config.toml");
        fs::write(&temp_file, toml_content).unwrap();

        let config = load_config(temp_file.to_str().unwrap()).unwrap();
        assert_eq!(config.source_count(), 2);

        let source1 = config.source_by_name("source1").unwrap();
        assert_eq!(source1.name, "source1");
        assert_eq!(source1.url.as_deref(), Some("http://example.com/list1.txt"));
        assert_eq!(source1.enabled, true);
        assert_eq!(source1.direction, Direction::Inbound);
        assert_eq!(source1.list_type, ListType::Blocklist);

        let source2 = config.source_by_name("source2").unwrap();
        assert_eq!(source2.name, "source2");
        assert_eq!(source2.url.as_deref(), Some("http://example.com/list2.txt"));
        assert_eq!(source2.list_type, ListType::Allowlist);
        assert_eq!(source2.comment_char, "!");
        assert_eq!(source2.field_separator, Some("\t".to_string()));
        assert_eq!(source2.extract_field, Some(2));
        assert_eq!(source2.net_json.as_deref(), Some("prefixes/ipv4Prefix"));
        assert_eq!(
            source2.net_list.as_deref(),
            Some(&["10.0.0.0/8".to_string(), "::1/128".to_string()][..])
        );
        assert_eq!(source2.rate_limited, true);
        assert_eq!(source2.enabled, false);
        assert_eq!(source2.direction, Direction::Inbound);

        fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_load_config_missing_file() {
        let result = load_config("/tmp/nonexistent_config_12345.toml");
        assert!(result.is_err());
    }
}
