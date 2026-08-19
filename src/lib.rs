//! Blocklist retrieval, merging, and output generation.

pub mod config;
pub mod generation;
pub mod geoip;
pub mod offline;
pub mod output;
pub mod ranges;
pub mod schedule;
pub mod source;
pub mod state;
pub mod storage;

#[cfg(test)]
pub(crate) mod test_support;
