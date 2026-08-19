//! List-source configuration, parsing, and retrieval.

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Configuration for a single list source.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceConfig {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(skip, default)]
    pub list_type: ListType,
    #[serde(default = "default_comment_char")]
    pub comment_char: String,
    #[serde(default)]
    pub field_separator: Option<String>,
    #[serde(default)]
    pub extract_field: Option<usize>,
    #[serde(default)]
    pub prefix_field: Option<usize>,
    #[serde(default)]
    pub net_json: Option<String>,
    #[serde(default)]
    pub net_list: Option<Vec<String>>,
    #[serde(default)]
    pub rate_limited: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub direction: Direction,
}

pub(crate) fn default_comment_char() -> String {
    "#".to_string()
}

fn default_enabled() -> bool {
    true
}

/// Traffic direction to which a source applies.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    Inbound,
    Outbound,
    Both,
}

/// Whether a source adds blocked or allowed networks.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListType {
    #[default]
    Blocklist,
    Allowlist,
}

pub(crate) enum IpAddrNet {
    Addr(IpAddr),
    Net(IpNet),
}

impl SourceConfig {
    /// Parse a source body into IP networks.
    pub fn parse(&self, body: &str) -> Vec<IpNet> {
        if self.net_json.is_some() {
            self.parse_json(body)
        } else {
            self.parse_text(body)
        }
    }

    fn parse_text(&self, body: &str) -> Vec<IpNet> {
        let mut entries = Vec::new();
        let mut warning_count = 0;
        for (line_number, line) in body.lines().enumerate() {
            let mut line = line.trim();
            if !self.comment_char.is_empty() {
                line = line
                    .split_once(&self.comment_char)
                    .map(|(entry, _)| entry.trim())
                    .unwrap_or(line);
            }
            if line.is_empty() {
                continue;
            }
            match self.parse_line(line) {
                Ok(entry) => entries.push(entry),
                Err(err) => {
                    if warning_count < 10 {
                        eprintln!(
                            "  Warning parsing line {} '{}': {}",
                            line_number + 1,
                            line,
                            err
                        );
                        warning_count += 1;
                        if warning_count == 10 {
                            eprintln!("  Not printing remaining parse errors for this list.");
                        }
                    }
                }
            }
        }
        entries
    }

    fn parse_json(&self, body: &str) -> Vec<IpNet> {
        let mut entries = Vec::new();
        let mut warning_count = 0;
        let Some(path) = self.net_json.as_deref() else {
            return entries;
        };
        let json: Value = match serde_json::from_str(body) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("  Warning parsing JSON body: {}", err);
                return entries;
            }
        };
        let path_segments: Vec<&str> = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        for value in self.json_path_values(&json, &path_segments) {
            match value {
                Value::String(entry) => match self.parse_ip_or_net(entry) {
                    Ok(net) => entries.push(net),
                    Err(err) => Self::warn_json(
                        &mut warning_count,
                        format!(
                            "  Warning parsing JSON value '{}' at '{}': {}",
                            entry, path, err
                        ),
                    ),
                },
                other => Self::warn_json(
                    &mut warning_count,
                    format!(
                        "  Warning parsing JSON value at '{}': expected string, found {}",
                        path,
                        Self::json_value_type(other)
                    ),
                ),
            }
        }
        entries
    }

    fn warn_json(warning_count: &mut usize, message: String) {
        if *warning_count < 10 {
            eprintln!("{message}");
            *warning_count += 1;
            if *warning_count == 10 {
                eprintln!("  Not printing remaining parse errors for this list.");
            }
        }
    }

    pub(crate) fn parse_line(&self, line: &str) -> Result<IpNet, Box<dyn std::error::Error>> {
        let fields: Vec<&str> = self.field_separator.as_deref().map_or_else(
            || line.split_whitespace().collect(),
            |separator| line.split(separator).collect(),
        );
        match self.extract_ip(&fields)? {
            IpAddrNet::Net(net) => {
                if self.prefix_field.is_some() {
                    eprintln!(
                        "  Warning parsing line '{}': prefix_field is set, but extracted IP field is already a CIDR network",
                        line
                    );
                }
                Ok(net)
            }
            IpAddrNet::Addr(ip) => self.ip_to_net(
                ip,
                self.prefix_field
                    .map(|_| self.extract_prefix(&fields))
                    .transpose()?,
            ),
        }
    }

    pub(crate) fn extract_field_entry(
        &self,
        fields: &[&str],
        index: Option<usize>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(field_idx) = index {
            fields
                .get(field_idx)
                .map(|field| field.trim().to_string())
                .ok_or_else(|| {
                    format!(
                        "field index {} out of bounds for {} fields",
                        field_idx,
                        fields.len()
                    )
                    .into()
                })
        } else {
            Ok(fields.first().unwrap_or(&"").trim().to_string())
        }
    }

    pub(crate) fn extract_ip(
        &self,
        fields: &[&str],
    ) -> Result<IpAddrNet, Box<dyn std::error::Error>> {
        let entry = self.extract_field_entry(fields, self.extract_field)?;
        if let Ok(net) = entry.parse::<IpNet>() {
            Ok(IpAddrNet::Net(net))
        } else if let Ok(ip) = entry.parse::<IpAddr>() {
            Ok(IpAddrNet::Addr(ip))
        } else {
            Err(format!("failed to parse IP or CIDR from '{}'", entry).into())
        }
    }

    pub(crate) fn extract_prefix(
        &self,
        fields: &[&str],
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let entry = self.extract_field_entry(fields, self.prefix_field)?;
        entry
            .parse::<usize>()
            .map_err(|err| format!("failed to parse prefix from '{}': {}", entry, err).into())
    }

    fn parse_ip_or_net(&self, entry: &str) -> Result<IpNet, Box<dyn std::error::Error>> {
        if let Ok(net) = entry.parse::<IpNet>() {
            Ok(net)
        } else if let Ok(ip) = entry.parse::<IpAddr>() {
            self.ip_to_net(ip, None)
        } else {
            Err(format!("failed to parse IP or CIDR from '{}'", entry).into())
        }
    }

    fn ip_to_net(
        &self,
        ip: IpAddr,
        prefix: Option<usize>,
    ) -> Result<IpNet, Box<dyn std::error::Error>> {
        let prefix = prefix.unwrap_or(match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        });
        let prefix = u8::try_from(prefix)
            .map_err(|_| format!("prefix {} is out of range for u8", prefix))?;
        match ip {
            IpAddr::V4(v4) => Ok(IpNet::V4(Ipv4Net::new(v4, prefix)?)),
            IpAddr::V6(v6) => Ok(IpNet::V6(Ipv6Net::new(v6, prefix)?)),
        }
    }

    fn json_path_values<'a>(&self, value: &'a Value, path_segments: &[&str]) -> Vec<&'a Value> {
        if path_segments.is_empty() {
            return vec![value];
        }
        match value {
            Value::Array(items) => items
                .iter()
                .flat_map(|item| self.json_path_values(item, path_segments))
                .collect(),
            Value::Object(map) => map
                .get(path_segments[0])
                .map(|next| self.json_path_values(next, &path_segments[1..]))
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn json_value_type(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    pub(crate) fn fetch_list(
        &self,
        client: &Client,
    ) -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
        if let Some(entries) = self.net_list.as_deref() {
            let entries = self.inline_entries(entries);
            println!("  Found {} inline entries", entries.len());
            Ok(entries)
        } else {
            let body = self.fetch_body(client)?;
            let entries = self.parse(&body);
            println!("  Found {} entries", entries.len());
            Ok(entries)
        }
    }

    fn inline_entries(&self, entries: &[String]) -> Vec<IpNet> {
        let mut nets = Vec::new();
        let mut warning_count = 0;
        for (index, entry) in entries.iter().enumerate() {
            match self.parse_ip_or_net(entry) {
                Ok(net) => nets.push(net),
                Err(err) if warning_count < 10 => {
                    eprintln!(
                        "  Warning parsing net_list entry {} '{}': {}",
                        index + 1,
                        entry,
                        err
                    );
                    warning_count += 1;
                    if warning_count == 10 {
                        eprintln!("  Not printing remaining parse errors for this list.");
                    }
                }
                Err(_) => {}
            }
        }
        nets
    }

    /// Download an unparsed source body for resilient caching.
    pub(crate) fn fetch_body(&self, client: &Client) -> Result<String, Box<dyn std::error::Error>> {
        let Some(url) = self.url.as_deref() else {
            return Err("source is missing url".into());
        };
        println!("  Fetching from {}...", url);
        let response = client.get(url).send()?;
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
        Ok(response.text()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{net, test_source};

    fn source() -> SourceConfig {
        SourceConfig {
            name: "test".to_string(),
            url: None,
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
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

    fn network(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    #[test]
    fn parses_text_with_comments_and_whitespace() {
        let source = source();
        assert_eq!(
            source.parse("\n # ignore\n 192.0.2.1 # comment\n2001:db8::/32\n"),
            vec![network("192.0.2.1/32"), network("2001:db8::/32")]
        );
    }

    #[test]
    fn parses_selected_fields_and_prefixes() {
        let mut source = source();
        source.field_separator = Some(",".to_string());
        source.extract_field = Some(1);
        source.prefix_field = Some(2);

        assert_eq!(
            source.parse_line("ignored,192.0.2.7,24").unwrap(),
            network("192.0.2.7/24")
        );
        assert!(source.parse_line("ignored,not-an-address,24").is_err());
    }

    #[test]
    fn parses_json_paths_and_skips_non_strings() {
        let mut source = source();
        source.net_json = Some("prefixes/address".to_string());

        assert_eq!(
            source.parse(r#"{"prefixes":[{"address":"198.51.100.8"},{"address":7},{"address":"2001:db8::/32"}]}"#),
            vec![network("198.51.100.8/32"), network("2001:db8::/32")]
        );
    }

    #[test]
    fn parses_inline_sources_without_a_url() {
        let mut source = source();
        source.net_list = Some(vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()]);

        assert_eq!(
            source.fetch_list(&Client::new()).unwrap(),
            vec![network("10.0.0.0/8"), network("2001:db8::/32")]
        );
    }

    #[test]
    fn test_default_comment_char() {
        assert_eq!(default_comment_char(), "#");
    }

    #[test]
    fn test_extract_field_entry_index_out_of_bounds_returns_error() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: Some(2),
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };

        let result = config.extract_field_entry(&["192.168.1.1", "example"], config.extract_field);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_ip_parses_ip_address() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: Some(0),
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };

        let result = config.extract_ip(&["192.168.1.1"]).unwrap();
        assert!(
            matches!(result, IpAddrNet::Addr(IpAddr::V4(addr)) if addr.to_string() == "192.168.1.1")
        );
    }

    #[test]
    fn test_extract_ip_returns_error_for_invalid_ip() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: Some(0),
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };

        let result = config.extract_ip(&["not-an-ip"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_prefix_parses_prefix_field() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: Some(0),
            prefix_field: Some(1),
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };

        let result = config.extract_prefix(&["192.168.1.1", "24"]).unwrap();
        assert_eq!(result, 24);
    }

    #[test]
    fn test_extract_prefix_returns_error_for_invalid_prefix() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: Some(0),
            prefix_field: Some(1),
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };

        let result = config.extract_prefix(&["192.168.1.1", "abc"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_line_returns_ipnet_for_plain_ipv4() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: Some(0),
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };

        let result = config.parse_line("192.168.1.1").unwrap();
        assert_eq!(result, net("192.168.1.1/32"));
    }

    #[test]
    fn test_parse_line_uses_prefix_field_for_plain_ipv4() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: Some(",".to_string()),
            extract_field: Some(0),
            prefix_field: Some(1),
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };

        let result = config.parse_line("192.168.1.1,24").unwrap();
        assert_eq!(result, net("192.168.1.1/24"));
    }

    #[test]
    fn test_parse_empty() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        assert_eq!(config.parse(""), Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_comments() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
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
        };
        assert_eq!(config.parse("# comment"), Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_inline_comments() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
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
        };
        let result = config.parse("192.168.1.0/24 # inline comment\n10.0.0.1#compact");
        assert_eq!(result, vec![net("192.168.1.0/24"), net("10.0.0.1/32")]);
    }

    #[test]
    fn test_parse_indented_comment() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
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
        };
        assert_eq!(config.parse("   # indented comment"), Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_custom_comment_char() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: "!".to_string(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        assert_eq!(config.parse("! comment"), Vec::<IpNet>::new());
        // "#" is not a valid IP or CIDR, so it's not included
        assert_eq!(config.parse("# not comment"), Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_ipv4_cidr() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("192.168.1.0/24");
        assert_eq!(result, vec![net("192.168.1.0/24")]);
    }

    #[test]
    fn test_parse_ipv4_address() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("192.168.1.1");
        assert_eq!(result, vec![net("192.168.1.1/32")]);
    }

    #[test]
    fn test_parse_ipv6_cidr() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("2001:db8::/32");
        assert_eq!(result, vec![net("2001:db8::/32")]);
    }

    #[test]
    fn test_parse_ipv6_address() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("2001:db8::1");
        assert_eq!(result, vec![net("2001:db8::1/128")]);
    }

    #[test]
    fn test_parse_multiple_lines() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let input = "# comment\n\n192.168.1.0/24\n10.0.0.1\n";
        let result = config.parse(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], net("192.168.1.0/24"));
        assert_eq!(result[1], net("10.0.0.1/32"));
    }

    #[test]
    fn test_parse_invalid_entries() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let input = "not an ip\nalso not\n";
        let result = config.parse(input);
        // Neither "not" nor "also" are valid IPs/CIDRs, so nothing is returned
        assert_eq!(result, Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_uses_prefix_field_for_plain_ip() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: Some(",".to_string()),
            extract_field: Some(0),
            prefix_field: Some(1),
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("192.168.1.1,24");
        assert_eq!(result, vec![net("192.168.1.1/24")]);
    }

    #[test]
    fn test_parse_skips_invalid_prefix_and_continues() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: Some(",".to_string()),
            extract_field: Some(0),
            prefix_field: Some(1),
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("192.168.1.1,abc\n10.0.0.1,32");
        assert_eq!(result, vec![net("10.0.0.1/32")]);
    }

    #[test]
    fn test_parse_warns_and_uses_existing_cidr_when_prefix_field_is_set() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: Some(",".to_string()),
            extract_field: Some(0),
            prefix_field: Some(1),
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("192.168.1.0/24,32");
        assert_eq!(result, vec![net("192.168.1.0/24")]);
    }

    #[test]
    fn test_parse_skips_invalid_extract_field_and_continues() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: Some(",".to_string()),
            extract_field: Some(2),
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("192.168.1.1,example\nfoo,bar,baz\n10.0.0.1,example");
        assert_eq!(result, Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_with_field_separator() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: Some("\t".to_string()),
            extract_field: Some(2),
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let input = "192.168.1.0/24\texample.com\tdescription\n";
        let result = config.parse(input);
        // Extracts field 2 which is "description" (no IP), falls back to "description"
        assert_eq!(result, Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_mixed_content() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
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
        };
        let input = "# header\n192.168.1.0/24\n# another comment\n10.0.0.1\n";
        let result = config.parse(input);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], net("192.168.1.0/24"));
        assert_eq!(result[1], net("10.0.0.1/32"));
    }

    #[test]
    fn test_parse_ipv4_single_field() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("224.0.0.0");
        assert_eq!(result, vec![net("224.0.0.0/32")]);
    }

    #[test]
    fn test_parse_empty_lines_and_whitespace() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("  \n   \n1.2.3.4\n  \n");
        assert_eq!(result, vec![net("1.2.3.4/32")]);
    }

    #[test]
    fn test_parse_ipv6_no_brackets() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("fe80::1");
        assert_eq!(result, vec![net("fe80::1/128")]);
    }

    #[test]
    fn test_parse_ipv4_with_trailing_whitespace() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("  192.168.1.1  ");
        assert_eq!(result, vec![net("192.168.1.1/32")]);
    }

    #[test]
    fn test_parse_ignore_non_ip_lines() {
        let config = SourceConfig {
            name: "test".to_string(),
            url: Some("test".to_string()),
            list_type: ListType::Blocklist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: None,
            rate_limited: false,
            enabled: true,
            direction: Direction::Inbound,
        };
        let result = config.parse("\n\n# comment\n\nnot-an-ip\nalso-not\n\n");
        // Each non-IP line falls back to first word, but parse() only accepts valid IPs/CIDRs
        assert_eq!(result, Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_json_extracts_ipv4_prefixes() {
        let mut config = test_source("test".to_string());
        config.list_type = ListType::Allowlist;
        config.direction = Direction::Outbound;
        config.net_json = Some("prefixes/ipv4Prefix".to_string());

        let body = r#"{
            "prefixes": [
                {"ipv4Prefix": "8.8.4.0/24"},
                {"ipv6Prefix": "2001:4860::/32"},
                {"ipv4Prefix": "216.239.32.0/19"},
                {"ipv6Prefix": "2a00:1450::/32"}
            ]
        }"#;
        let result = config.parse(body);

        assert_eq!(result, vec![net("8.8.4.0/24"), net("216.239.32.0/19")]);
    }

    #[test]
    fn test_parse_json_extracts_ipv6_prefixes() {
        let mut config = test_source("test".to_string());
        config.net_json = Some("prefixes/ipv6Prefix".to_string());

        let body = r#"{
            "prefixes": [
                {"ipv4Prefix": "8.8.4.0/24"},
                {"ipv6Prefix": "2001:4860::/32"},
                {"ipv4Prefix": "216.239.32.0/19"},
                {"ipv6Prefix": "2a00:1450::/32"}
            ]
        }"#;
        let result = config.parse(body);

        assert_eq!(result, vec![net("2001:4860::/32"), net("2a00:1450::/32")]);
    }

    #[test]
    fn test_parse_json_normalizes_plain_ip_strings() {
        let mut config = test_source("test".to_string());
        config.net_json = Some("prefixes/ipv4Prefix".to_string());

        let result = config.parse(r#"{"prefixes":[{"ipv4Prefix":"8.8.8.8"}]}"#);

        assert_eq!(result, vec![net("8.8.8.8/32")]);
    }

    #[test]
    fn test_parse_json_missing_path_returns_no_entries() {
        let mut config = test_source("test".to_string());
        config.net_json = Some("prefixes/missing".to_string());

        let result = config.parse(r#"{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"}]}"#);

        assert_eq!(result, Vec::<IpNet>::new());
    }

    #[test]
    fn test_parse_json_skips_non_string_leaves() {
        let mut config = test_source("test".to_string());
        config.net_json = Some("prefixes/ipv4Prefix".to_string());

        let result = config.parse(
            r#"{"prefixes":[{"ipv4Prefix":123},{"ipv4Prefix":"8.8.8.0/24"},{"ipv4Prefix":false}]}"#,
        );

        assert_eq!(result, vec![net("8.8.8.0/24")]);
    }

    #[test]
    fn test_fetch_list_uses_inline_net_list_without_url() {
        let source = SourceConfig {
            name: "test".to_string(),
            url: None,
            list_type: ListType::Allowlist,
            comment_char: default_comment_char(),
            field_separator: None,
            extract_field: None,
            prefix_field: None,
            net_json: None,
            net_list: Some(vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()]),
            rate_limited: false,
            enabled: true,
            direction: Direction::Both,
        };

        let client = Client::new();
        let result = source.fetch_list(&client).unwrap();

        assert_eq!(result, vec![net("10.0.0.0/8"), net("2001:db8::/32")]);
    }
}
