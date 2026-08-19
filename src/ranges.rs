//! IP-network range merging and allowlist subtraction.

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;

/// A collection of IPv4 and IPv6 networks.
pub struct IpRanges {
    pub(crate) iprange_v4: IpRange<Ipv4Net>,
    pub(crate) iprange_v6: IpRange<Ipv6Net>,
}

/// Final blocklists for each traffic direction.
pub struct DirectionalBlocklists {
    pub inbound: IpRanges,
    pub outbound: IpRanges,
}

impl IpRanges {
    pub fn new() -> Self {
        Self {
            iprange_v4: IpRange::new(),
            iprange_v6: IpRange::new(),
        }
    }

    pub fn add(&mut self, entry: IpNet) {
        match entry {
            IpNet::V4(network) => {
                self.iprange_v4.add(network);
            }
            IpNet::V6(network) => {
                self.iprange_v6.add(network);
            }
        }
    }

    pub fn add_all<I: IntoIterator<Item = IpNet>>(&mut self, entries: I) {
        for entry in entries {
            self.add(entry);
        }
    }

    pub fn simplify(&mut self) {
        self.iprange_v4.simplify();
        self.iprange_v6.simplify();
    }

    pub fn remove_allowlists(&mut self, allowlist: Option<&IpRanges>) {
        if let Some(allowlist) = allowlist {
            for network in &allowlist.iprange_v4 {
                self.iprange_v4.remove(network);
            }
            for network in &allowlist.iprange_v6 {
                self.iprange_v6.remove(network);
            }
        }
    }

    pub fn final_ipv4(&self) -> Vec<Ipv4Net> {
        let mut networks: Vec<_> = self.iprange_v4.iter().collect();
        networks.sort_unstable();
        networks
    }

    pub fn final_ipv6(&self) -> Vec<Ipv6Net> {
        let mut networks: Vec<_> = self.iprange_v6.iter().collect();
        networks.sort_unstable();
        networks
    }

    pub(crate) fn ipv4_count(&self) -> usize {
        self.iprange_v4.iter().count()
    }
    pub(crate) fn ipv6_count(&self) -> usize {
        self.iprange_v6.iter().count()
    }
}

impl Default for IpRanges {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn finalize(mut result: IpRanges, allowlist: Option<&IpRanges>) -> IpRanges {
    result.simplify();
    result.remove_allowlists(allowlist);
    result.simplify();
    result
}

/// Merge blocklist entries into simplified ranges.
pub fn merge_blocklist_entries<I: IntoIterator<Item = IpNet>>(entries: I) -> IpRanges {
    let mut ranges = IpRanges::new();
    ranges.add_all(entries);
    finalize(ranges, None)
}

/// Merge blocklist entries and subtract all allowlisted networks.
pub fn merge_blocklist_entries_with_allowlist<I, A>(entries: I, allowlist_entries: A) -> IpRanges
where
    I: IntoIterator<Item = IpNet>,
    A: IntoIterator<Item = IpNet>,
{
    let mut blocklist = IpRanges::new();
    let mut allowlist = IpRanges::new();
    blocklist.add_all(entries);
    allowlist.add_all(allowlist_entries);
    allowlist.simplify();
    finalize(blocklist, Some(&allowlist))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::net;

    fn network(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    #[test]
    fn merges_adjacent_networks() {
        let merged = merge_blocklist_entries([
            network("192.0.2.0/25"),
            network("192.0.2.128/25"),
            network("2001:db8::/33"),
            network("2001:db8:8000::/33"),
        ]);

        assert_eq!(merged.final_ipv4(), vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(merged.final_ipv6(), vec!["2001:db8::/32".parse().unwrap()]);
    }

    #[test]
    fn subtracts_allowlisted_subnets() {
        let merged = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24"), network("2001:db8::/32")],
            [network("192.0.2.0/25"), network("2001:db8::/33")],
        );

        assert_eq!(merged.final_ipv4(), vec!["192.0.2.128/25".parse().unwrap()]);
        assert_eq!(
            merged.final_ipv6(),
            vec!["2001:db8:8000::/33".parse().unwrap()]
        );
    }

    #[test]
    fn test_remove_allowlists_removes_allowlist_ranges() {
        let mut blocklist = IpRanges {
            iprange_v4: ["8.8.8.0/24".parse().unwrap(), "10.0.0.0/8".parse().unwrap()]
                .into_iter()
                .collect(),
            iprange_v6: [
                "2001:db8::/32".parse().unwrap(),
                "fc00::/7".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
        };
        let allowlist = IpRanges {
            iprange_v4: ["8.8.8.0/25".parse().unwrap()].into_iter().collect(),
            iprange_v6: ["2001:db8::/33".parse().unwrap()].into_iter().collect(),
        };

        blocklist.remove_allowlists(Some(&allowlist));

        let expected_v4: Vec<Ipv4Net> = vec![
            "8.8.8.128/25".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let expected_v6: Vec<Ipv6Net> = vec![
            "2001:db8:8000::/33".parse().unwrap(),
            "fc00::/7".parse().unwrap(),
        ];

        assert_eq!(blocklist.final_ipv4(), expected_v4);
        assert_eq!(blocklist.final_ipv6(), expected_v6);
    }

    #[test]
    fn test_remove_allowlists_with_no_allowlists_leaves_entries_unchanged() {
        let mut blocklist = IpRanges {
            iprange_v4: ["8.8.8.0/24".parse().unwrap(), "10.0.0.0/8".parse().unwrap()]
                .into_iter()
                .collect(),
            iprange_v6: [
                "2001:db8::/32".parse().unwrap(),
                "fc00::/7".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
        };

        blocklist.remove_allowlists(None);

        assert_eq!(
            blocklist.final_ipv4(),
            vec!["8.8.8.0/24".parse().unwrap(), "10.0.0.0/8".parse().unwrap()]
        );
        assert_eq!(
            blocklist.final_ipv6(),
            vec![
                "2001:db8::/32".parse().unwrap(),
                "fc00::/7".parse().unwrap()
            ]
        );
    }

    #[test]
    fn test_merge_blocklist_entries_with_allowlist_matches_offline_path() {
        let blocklist_entries = vec![net("8.8.8.0/24"), net("2001:db8::/32")];
        let allowlist_entries = vec![net("8.8.8.0/25"), net("2001:db8::/33")];

        let blocklist =
            merge_blocklist_entries_with_allowlist(blocklist_entries, allowlist_entries);

        assert_eq!(
            blocklist.final_ipv4(),
            vec!["8.8.8.128/25".parse().unwrap()]
        );
        assert_eq!(
            blocklist.final_ipv6(),
            vec!["2001:db8:8000::/33".parse().unwrap()]
        );
    }
}
