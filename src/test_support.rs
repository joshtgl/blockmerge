use ipnet::IpNet;

use crate::source::{Direction, ListType, SourceConfig, default_comment_char};

pub(crate) fn test_source(url: String) -> SourceConfig {
    SourceConfig {
        name: url.clone(),
        url: Some(url),
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

pub(crate) fn inline_source(name: &str, list_type: ListType, net_list: Vec<&str>) -> SourceConfig {
    SourceConfig {
        name: name.to_string(),
        url: None,
        list_type,
        comment_char: default_comment_char(),
        field_separator: None,
        extract_field: None,
        prefix_field: None,
        net_json: None,
        net_list: Some(net_list.into_iter().map(ToOwned::to_owned).collect()),
        rate_limited: false,
        enabled: true,
        direction: Direction::Inbound,
    }
}

pub(crate) fn net(value: &str) -> IpNet {
    value.parse().unwrap()
}

pub(crate) fn runtime_config_toml(schedule_body: &str) -> String {
    format!(
        r#"
[web.general]
host = "0.0.0.0"
port = 8080
root = "web-assets"
directory-listing = true

[schedule]
{schedule_body}
"#
    )
}
