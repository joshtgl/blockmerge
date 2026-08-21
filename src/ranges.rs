//! Compact IP-network accumulation, merging, and allowlist subtraction.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Interval {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv6Interval {
    start: u128,
    end: u128,
}

/// Unsorted compact storage used while collecting IP networks.
#[derive(Debug, Clone, Default)]
pub struct IpRangeAccumulator {
    ipv4: Vec<Ipv4Interval>,
    ipv6: Vec<Ipv6Interval>,
}

/// A canonical collection of sorted, disjoint IP intervals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpRanges {
    ipv4: Vec<Ipv4Interval>,
    ipv6: Vec<Ipv6Interval>,
}

/// Final blocklists for each traffic direction.
pub struct DirectionalBlocklists {
    pub inbound: IpRanges,
    pub outbound: IpRanges,
}

impl IpRangeAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, entry: IpNet) {
        match entry {
            IpNet::V4(network) => self.ipv4.push(Ipv4Interval {
                start: u32::from(network.network()),
                end: u32::from(network.broadcast()),
            }),
            IpNet::V6(network) => self.ipv6.push(Ipv6Interval {
                start: u128::from(network.network()),
                end: ipv6_last_address(network),
            }),
        }
    }

    pub fn extend<I: IntoIterator<Item = IpNet>>(&mut self, entries: I) {
        for entry in entries {
            self.add(entry);
        }
    }

    /// Move another accumulator's buffers into this one without copying entries.
    pub fn append(&mut self, mut other: Self) {
        self.ipv4.append(&mut other.ipv4);
        self.ipv6.append(&mut other.ipv6);
    }

    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    pub fn finalize(mut self) -> IpRanges {
        merge_ipv4_intervals(&mut self.ipv4);
        merge_ipv6_intervals(&mut self.ipv6);
        IpRanges {
            ipv4: self.ipv4,
            ipv6: self.ipv6,
        }
    }
}

impl IpRanges {
    /// Iterate over the smallest exact IPv4 CIDR representation in numeric order.
    pub fn ipv4_networks(&self) -> impl Iterator<Item = Ipv4Net> + '_ {
        Ipv4CidrIterator::new(&self.ipv4)
    }

    /// Iterate over the smallest exact IPv6 CIDR representation in numeric order.
    pub fn ipv6_networks(&self) -> impl Iterator<Item = Ipv6Net> + '_ {
        Ipv6CidrIterator::new(&self.ipv6)
    }

    /// Subtract all allowlisted addresses while preserving canonical ordering.
    pub fn subtract(self, allowlist: &IpRanges) -> Self {
        Self {
            ipv4: subtract_ipv4_intervals(&self.ipv4, &allowlist.ipv4),
            ipv6: subtract_ipv6_intervals(&self.ipv6, &allowlist.ipv6),
        }
    }
}

fn ipv6_last_address(network: Ipv6Net) -> u128 {
    let start = u128::from(network.network());
    let host_bits = 128 - u32::from(network.prefix_len());
    if host_bits == 128 {
        u128::MAX
    } else {
        start | ((1_u128 << host_bits) - 1)
    }
}

fn merge_ipv4_intervals(intervals: &mut Vec<Ipv4Interval>) {
    intervals.sort_unstable_by_key(|range| (range.start, range.end));
    let mut write = 0;
    for read in 0..intervals.len() {
        let next = intervals[read];
        if write > 0 && next.start <= intervals[write - 1].end.saturating_add(1) {
            intervals[write - 1].end = intervals[write - 1].end.max(next.end);
        } else {
            intervals[write] = next;
            write += 1;
        }
    }
    intervals.truncate(write);
}

fn merge_ipv6_intervals(intervals: &mut Vec<Ipv6Interval>) {
    intervals.sort_unstable_by_key(|range| (range.start, range.end));
    let mut write = 0;
    for read in 0..intervals.len() {
        let next = intervals[read];
        if write > 0 && next.start <= intervals[write - 1].end.saturating_add(1) {
            intervals[write - 1].end = intervals[write - 1].end.max(next.end);
        } else {
            intervals[write] = next;
            write += 1;
        }
    }
    intervals.truncate(write);
}

fn subtract_ipv4_intervals(
    blocks: &[Ipv4Interval],
    allowlist: &[Ipv4Interval],
) -> Vec<Ipv4Interval> {
    let mut result = Vec::with_capacity(blocks.len());
    let mut allow_index = 0;
    for block in blocks {
        let mut cursor = Some(block.start);
        while allow_index < allowlist.len() && allowlist[allow_index].end < block.start {
            allow_index += 1;
        }
        let mut index = allow_index;
        while let Some(start) = cursor {
            let Some(allowed) = allowlist.get(index).copied() else {
                result.push(Ipv4Interval {
                    start,
                    end: block.end,
                });
                break;
            };
            if allowed.start > block.end {
                result.push(Ipv4Interval {
                    start,
                    end: block.end,
                });
                break;
            }
            if allowed.start > start {
                result.push(Ipv4Interval {
                    start,
                    end: allowed.start - 1,
                });
            }
            if allowed.end >= block.end {
                cursor = None;
            } else {
                cursor = Some(allowed.end.saturating_add(1).max(start));
                index += 1;
            }
        }
        allow_index = index;
    }
    result
}

fn subtract_ipv6_intervals(
    blocks: &[Ipv6Interval],
    allowlist: &[Ipv6Interval],
) -> Vec<Ipv6Interval> {
    let mut result = Vec::with_capacity(blocks.len());
    let mut allow_index = 0;
    for block in blocks {
        let mut cursor = Some(block.start);
        while allow_index < allowlist.len() && allowlist[allow_index].end < block.start {
            allow_index += 1;
        }
        let mut index = allow_index;
        while let Some(start) = cursor {
            let Some(allowed) = allowlist.get(index).copied() else {
                result.push(Ipv6Interval {
                    start,
                    end: block.end,
                });
                break;
            };
            if allowed.start > block.end {
                result.push(Ipv6Interval {
                    start,
                    end: block.end,
                });
                break;
            }
            if allowed.start > start {
                result.push(Ipv6Interval {
                    start,
                    end: allowed.start - 1,
                });
            }
            if allowed.end >= block.end {
                cursor = None;
            } else {
                cursor = Some(allowed.end.saturating_add(1).max(start));
                index += 1;
            }
        }
        allow_index = index;
    }
    result
}

struct Ipv4CidrIterator<'a> {
    intervals: &'a [Ipv4Interval],
    interval_index: usize,
    cursor: Option<u32>,
}

impl<'a> Ipv4CidrIterator<'a> {
    fn new(intervals: &'a [Ipv4Interval]) -> Self {
        Self {
            intervals,
            interval_index: 0,
            cursor: intervals.first().map(|range| range.start),
        }
    }
}

impl Iterator for Ipv4CidrIterator<'_> {
    type Item = Ipv4Net;

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.intervals.get(self.interval_index)?;
        let start = self.cursor?;
        let remaining = range.end - start;
        let span_bits = if remaining == u32::MAX {
            32
        } else {
            31 - (remaining + 1).leading_zeros()
        };
        let host_bits = start.trailing_zeros().min(span_bits);
        let prefix = (32 - host_bits) as u8;
        let network = Ipv4Net::new(Ipv4Addr::from(start), prefix)
            .expect("aligned IPv4 interval must produce a valid CIDR");
        if host_bits == 32 || start + ((1_u32 << host_bits) - 1) == range.end {
            self.interval_index += 1;
            self.cursor = self
                .intervals
                .get(self.interval_index)
                .map(|next| next.start);
        } else {
            self.cursor = Some(start + (1_u32 << host_bits));
        }
        Some(network)
    }
}

struct Ipv6CidrIterator<'a> {
    intervals: &'a [Ipv6Interval],
    interval_index: usize,
    cursor: Option<u128>,
}

impl<'a> Ipv6CidrIterator<'a> {
    fn new(intervals: &'a [Ipv6Interval]) -> Self {
        Self {
            intervals,
            interval_index: 0,
            cursor: intervals.first().map(|range| range.start),
        }
    }
}

impl Iterator for Ipv6CidrIterator<'_> {
    type Item = Ipv6Net;

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.intervals.get(self.interval_index)?;
        let start = self.cursor?;
        let remaining = range.end - start;
        let span_bits = if remaining == u128::MAX {
            128
        } else {
            127 - (remaining + 1).leading_zeros()
        };
        let host_bits = start.trailing_zeros().min(span_bits);
        let prefix = (128 - host_bits) as u8;
        let network = Ipv6Net::new(Ipv6Addr::from(start), prefix)
            .expect("aligned IPv6 interval must produce a valid CIDR");
        if host_bits == 128 || start + ((1_u128 << host_bits) - 1) == range.end {
            self.interval_index += 1;
            self.cursor = self
                .intervals
                .get(self.interval_index)
                .map(|next| next.start);
        } else {
            self.cursor = Some(start + (1_u128 << host_bits));
        }
        Some(network)
    }
}

/// Merge blocklist entries into simplified ranges.
pub fn merge_blocklist_entries<I: IntoIterator<Item = IpNet>>(entries: I) -> IpRanges {
    let mut ranges = IpRangeAccumulator::new();
    ranges.extend(entries);
    ranges.finalize()
}

/// Merge blocklist entries and subtract all allowlisted networks.
pub fn merge_blocklist_entries_with_allowlist<I, A>(entries: I, allowlist_entries: A) -> IpRanges
where
    I: IntoIterator<Item = IpNet>,
    A: IntoIterator<Item = IpNet>,
{
    let mut blocklist = IpRangeAccumulator::new();
    let mut allowlist = IpRangeAccumulator::new();
    blocklist.extend(entries);
    allowlist.extend(allowlist_entries);
    blocklist.finalize().subtract(&allowlist.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    fn network(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    fn ipv4(ranges: &IpRanges) -> Vec<Ipv4Net> {
        ranges.ipv4_networks().collect()
    }

    fn ipv6(ranges: &IpRanges) -> Vec<Ipv6Net> {
        ranges.ipv6_networks().collect()
    }

    fn ipv4_host(address: u32) -> IpNet {
        IpNet::V4(Ipv4Net::new(Ipv4Addr::from(address), 32).unwrap())
    }

    fn ipv6_host(address: u128) -> IpNet {
        IpNet::V6(Ipv6Net::new(Ipv6Addr::from(address), 128).unwrap())
    }

    #[test]
    fn empty_inputs_produce_empty_ranges() {
        let empty = merge_blocklist_entries(std::iter::empty::<IpNet>());
        assert!(empty.ipv4_networks().next().is_none());
        assert!(empty.ipv6_networks().next().is_none());

        let block = merge_blocklist_entries([network("192.0.2.0/24")]);
        let empty_allowlist = merge_blocklist_entries(std::iter::empty::<IpNet>());
        assert_eq!(
            ipv4(&block.clone().subtract(&empty_allowlist)),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
        assert!(empty.subtract(&block).ipv4_networks().next().is_none());
    }

    #[test]
    fn merges_duplicates_containment_overlap_and_adjacency() {
        let merged = merge_blocklist_entries([
            network("192.0.2.0/25"),
            network("192.0.2.0/25"),
            network("192.0.2.64/26"),
            network("192.0.2.128/26"),
            network("192.0.2.192/26"),
            network("2001:db8::/33"),
            network("2001:db8:8000::/33"),
        ]);

        assert_eq!(ipv4(&merged), vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(ipv6(&merged), vec!["2001:db8::/32".parse().unwrap()]);
    }

    #[test]
    fn union_sorts_reverse_order_input() {
        let merged = merge_blocklist_entries([
            network("2001:db8:2::/48"),
            network("2001:db8::/48"),
            network("192.0.2.192/26"),
            network("192.0.2.128/26"),
            network("192.0.2.0/25"),
        ]);

        assert_eq!(ipv4(&merged), vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(
            ipv6(&merged),
            vec![
                "2001:db8::/48".parse().unwrap(),
                "2001:db8:2::/48".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn accumulation_normalizes_host_bits_before_unioning() {
        let merged = merge_blocklist_entries([
            IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 193), 24).unwrap()),
            IpNet::V6(Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7), 64).unwrap()),
        ]);

        assert_eq!(ipv4(&merged), vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(ipv6(&merged), vec!["2001:db8::/64".parse().unwrap()]);
    }

    #[test]
    fn interval_union_handles_arbitrary_overlap_and_chained_adjacency() {
        let mut ipv4 = vec![
            Ipv4Interval { start: 30, end: 30 },
            Ipv4Interval { start: 10, end: 20 },
            Ipv4Interval { start: 1, end: 5 },
            Ipv4Interval { start: 4, end: 12 },
            Ipv4Interval { start: 21, end: 29 },
        ];
        merge_ipv4_intervals(&mut ipv4);
        assert_eq!(ipv4, vec![Ipv4Interval { start: 1, end: 30 }]);

        let mut ipv6 = vec![
            Ipv6Interval { start: 30, end: 30 },
            Ipv6Interval { start: 10, end: 20 },
            Ipv6Interval { start: 1, end: 5 },
            Ipv6Interval { start: 4, end: 12 },
            Ipv6Interval { start: 21, end: 29 },
        ];
        merge_ipv6_intervals(&mut ipv6);
        assert_eq!(ipv6, vec![Ipv6Interval { start: 1, end: 30 }]);
    }

    #[test]
    fn decomposes_unaligned_intervals_without_adding_addresses() {
        let merged = merge_blocklist_entries([
            network("192.0.2.1/32"),
            network("192.0.2.2/32"),
            network("192.0.2.3/32"),
            network("192.0.2.4/32"),
        ]);

        assert_eq!(
            ipv4(&merged),
            vec![
                "192.0.2.1/32".parse().unwrap(),
                "192.0.2.2/31".parse().unwrap(),
                "192.0.2.4/32".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn decomposes_unaligned_ipv6_intervals_without_adding_addresses() {
        let merged =
            merge_blocklist_entries([ipv6_host(1), ipv6_host(2), ipv6_host(3), ipv6_host(4)]);

        assert_eq!(
            ipv6(&merged),
            vec![
                "::1/128".parse().unwrap(),
                "::2/127".parse().unwrap(),
                "::4/128".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn handles_entire_address_spaces_and_maximum_addresses() {
        let merged = merge_blocklist_entries([
            network("0.0.0.0/0"),
            network("255.255.255.255/32"),
            network("::/0"),
            network("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
        ]);

        assert_eq!(ipv4(&merged), vec!["0.0.0.0/0".parse().unwrap()]);
        assert_eq!(ipv6(&merged), vec!["::/0".parse().unwrap()]);
    }

    #[test]
    fn interval_storage_has_compact_fixed_width_layouts() {
        assert_eq!(size_of::<Ipv4Interval>(), 8);
        assert_eq!(size_of::<Ipv6Interval>(), 32);
    }

    #[test]
    fn subtracts_allowlists_that_trim_split_and_span_blocks() {
        let merged = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24"), network("2001:db8::/32")],
            [network("192.0.2.64/26"), network("2001:db8::/33")],
        );

        assert_eq!(
            ipv4(&merged),
            vec![
                "192.0.2.0/26".parse().unwrap(),
                "192.0.2.128/25".parse().unwrap(),
            ]
        );
        assert_eq!(ipv6(&merged), vec!["2001:db8:8000::/33".parse().unwrap()]);
    }

    #[test]
    fn subtraction_trims_both_ends_and_applies_multiple_internal_allowlists() {
        let trim_start = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24")],
            [network("192.0.2.0/26")],
        );
        assert_eq!(
            ipv4(&trim_start),
            vec![
                "192.0.2.64/26".parse().unwrap(),
                "192.0.2.128/25".parse().unwrap(),
            ]
        );

        let trim_end = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24")],
            [network("192.0.2.192/26")],
        );
        assert_eq!(
            ipv4(&trim_end),
            vec![
                "192.0.2.0/25".parse().unwrap(),
                "192.0.2.128/26".parse().unwrap(),
            ]
        );

        let multiple = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24")],
            [network("192.0.2.32/27"), network("192.0.2.128/26")],
        );
        assert_eq!(
            ipv4(&multiple),
            vec![
                "192.0.2.0/27".parse().unwrap(),
                "192.0.2.64/26".parse().unwrap(),
                "192.0.2.192/26".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn one_allow_interval_can_overlap_multiple_disjoint_blocks() {
        let result = merge_blocklist_entries_with_allowlist(
            [network("192.0.0.0/24"), network("192.0.2.0/24")],
            [
                network("192.0.0.128/25"),
                network("192.0.1.0/24"),
                network("192.0.2.0/25"),
            ],
        );

        assert_eq!(
            ipv4(&result),
            vec![
                "192.0.0.0/25".parse().unwrap(),
                "192.0.2.128/25".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn subtraction_ignores_disjoint_allowlists_and_can_remove_everything() {
        let unchanged = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24")],
            [network("198.51.100.0/24")],
        );
        assert_eq!(ipv4(&unchanged), vec!["192.0.2.0/24".parse().unwrap()]);

        let empty = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24")],
            [network("0.0.0.0/0")],
        );
        assert!(empty.ipv4_networks().next().is_none());

        let allowlist_before = merge_blocklist_entries_with_allowlist(
            [network("192.0.2.0/24")],
            [network("192.0.1.0/24")],
        );
        assert_eq!(
            ipv4(&allowlist_before),
            vec!["192.0.2.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn subtraction_handles_the_maximum_address_without_overflow() {
        let result = merge_blocklist_entries_with_allowlist(
            [network("255.255.255.0/24")],
            [network("255.255.255.255/32")],
        );
        assert_eq!(
            ipv4(&result),
            vec![
                "255.255.255.0/25".parse().unwrap(),
                "255.255.255.128/26".parse().unwrap(),
                "255.255.255.192/27".parse().unwrap(),
                "255.255.255.224/28".parse().unwrap(),
                "255.255.255.240/29".parse().unwrap(),
                "255.255.255.248/30".parse().unwrap(),
                "255.255.255.252/31".parse().unwrap(),
                "255.255.255.254/32".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn ipv6_subtraction_handles_zero_and_maximum_without_overflow() {
        let without_max =
            merge_blocklist_entries_with_allowlist([network("::/0")], [ipv6_host(u128::MAX)]);
        let without_max_networks = ipv6(&without_max);
        assert_eq!(without_max_networks.len(), 128);
        assert!(
            without_max_networks
                .iter()
                .any(|network| network.contains(&Ipv6Addr::from(u128::MAX - 1)))
        );
        assert!(
            !without_max_networks
                .iter()
                .any(|network| network.contains(&Ipv6Addr::from(u128::MAX)))
        );

        let without_zero =
            merge_blocklist_entries_with_allowlist([network("::/0")], [ipv6_host(0)]);
        let without_zero_networks = ipv6(&without_zero);
        assert_eq!(without_zero_networks.len(), 128);
        assert!(
            !without_zero_networks
                .iter()
                .any(|network| network.contains(&Ipv6Addr::UNSPECIFIED))
        );
        assert!(
            without_zero_networks
                .iter()
                .any(|network| network.contains(&Ipv6Addr::from(1_u128)))
        );
        assert!(
            without_zero_networks
                .iter()
                .any(|network| network.contains(&Ipv6Addr::from(u128::MAX)))
        );
    }

    #[test]
    fn ipv4_merge_and_subtraction_exhaustively_match_a_per_address_oracle() {
        const ADDRESS_COUNT: usize = 8;
        let base = u32::from(Ipv4Addr::new(192, 0, 2, 0));

        for block_mask in 0..(1_u16 << ADDRESS_COUNT) {
            let mut blocks = IpRangeAccumulator::new();
            for index in 0..ADDRESS_COUNT {
                if block_mask & (1 << index) != 0 {
                    blocks.add(ipv4_host(base + index as u32));
                }
            }
            let blocks = blocks.finalize();

            for allow_mask in 0..(1_u16 << ADDRESS_COUNT) {
                let mut allowlist = IpRangeAccumulator::new();
                for index in 0..ADDRESS_COUNT {
                    if allow_mask & (1 << index) != 0 {
                        allowlist.add(ipv4_host(base + index as u32));
                    }
                }

                let result = blocks.clone().subtract(&allowlist.finalize());
                let networks: Vec<_> = result.ipv4_networks().collect();
                for index in 0..ADDRESS_COUNT {
                    let address = Ipv4Addr::from(base + index as u32);
                    let actual = networks.iter().any(|network| network.contains(&address));
                    let expected = block_mask & (1 << index) != 0 && allow_mask & (1 << index) == 0;
                    assert_eq!(
                        actual, expected,
                        "block mask {block_mask:#x}, allow mask {allow_mask:#x}, address {address}"
                    );
                }
            }
        }
    }

    #[test]
    fn ipv6_merge_and_subtraction_exhaustively_match_a_per_address_oracle() {
        const ADDRESS_COUNT: usize = 8;
        let base = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));

        for block_mask in 0..(1_u16 << ADDRESS_COUNT) {
            let mut blocks = IpRangeAccumulator::new();
            for index in 0..ADDRESS_COUNT {
                if block_mask & (1 << index) != 0 {
                    blocks.add(ipv6_host(base + index as u128));
                }
            }
            let blocks = blocks.finalize();

            for allow_mask in 0..(1_u16 << ADDRESS_COUNT) {
                let mut allowlist = IpRangeAccumulator::new();
                for index in 0..ADDRESS_COUNT {
                    if allow_mask & (1 << index) != 0 {
                        allowlist.add(ipv6_host(base + index as u128));
                    }
                }

                let result = blocks.clone().subtract(&allowlist.finalize());
                let networks: Vec<_> = result.ipv6_networks().collect();
                for index in 0..ADDRESS_COUNT {
                    let address = Ipv6Addr::from(base + index as u128);
                    let actual = networks.iter().any(|network| network.contains(&address));
                    let expected = block_mask & (1 << index) != 0 && allow_mask & (1 << index) == 0;
                    assert_eq!(
                        actual, expected,
                        "block mask {block_mask:#x}, allow mask {allow_mask:#x}, address {address}"
                    );
                }
            }
        }
    }

    #[test]
    fn accumulator_append_moves_both_address_families() {
        let mut left = IpRangeAccumulator::new();
        left.add(network("192.0.2.0/25"));
        let mut right = IpRangeAccumulator::new();
        right.add(network("192.0.2.128/25"));
        right.add(network("2001:db8::/32"));

        left.append(right);
        let merged = left.finalize();

        assert_eq!(ipv4(&merged), vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(ipv6(&merged), vec!["2001:db8::/32".parse().unwrap()]);
    }
}
