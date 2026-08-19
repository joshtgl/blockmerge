//! Versioned manifests for downloaded offline source snapshots.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current offline manifest format version.
pub const MANIFEST_VERSION: u32 = 1;

/// A verified snapshot of downloaded source files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DownloadManifest {
    pub version: u32,
    pub sources: Vec<DownloadManifestEntry>,
}

/// Metadata for one saved source body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DownloadManifestEntry {
    pub name: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub sha256: String,
    pub downloaded_at: String,
}

impl DownloadManifest {
    /// Build and validate a manifest in the current format.
    pub fn new(sources: Vec<DownloadManifestEntry>) -> Result<Self, Box<dyn std::error::Error>> {
        let manifest = Self {
            version: MANIFEST_VERSION,
            sources,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate manifest version and entry metadata before use.
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.version != MANIFEST_VERSION {
            return Err(format!(
                "unsupported offline manifest version {}; regenerate it with blockmerge-download-raw",
                self.version
            )
            .into());
        }

        let mut names = HashSet::new();
        for entry in &self.sources {
            if !names.insert(&entry.name) {
                return Err(format!("duplicate manifest source name '{}'", entry.name).into());
            }
            validate_entry(entry)?;
        }
        Ok(())
    }
}

/// Read a v1 manifest. Legacy array manifests are intentionally unsupported.
pub fn load_manifest(path: &Path) -> Result<DownloadManifest, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if value.is_array() {
        return Err(
            "legacy offline manifest arrays are unsupported; regenerate with blockmerge-download-raw"
                .into(),
        );
    }

    let manifest = serde_json::from_value::<DownloadManifest>(value)?;
    manifest.validate()?;
    Ok(manifest)
}

/// Return the lowercase hexadecimal SHA-256 checksum for a source body.
pub fn sha256_hex(body: &[u8]) -> String {
    format!("{:x}", Sha256::digest(body))
}

fn validate_entry(entry: &DownloadManifestEntry) -> Result<(), Box<dyn std::error::Error>> {
    let file = Path::new(&entry.file);
    if entry.file.is_empty()
        || !file.is_relative()
        || file
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(format!(
            "manifest file path '{}' must be a non-empty relative path without '.' or '..'",
            entry.file
        )
        .into());
    }
    if entry.sha256.len() != 64
        || !entry.sha256.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
    {
        return Err(format!("manifest source '{}' has an invalid SHA-256", entry.name).into());
    }
    DateTime::parse_from_rfc3339(&entry.downloaded_at).map_err(|error| {
        format!(
            "manifest source '{}' has an invalid downloaded_at timestamp: {}",
            entry.name, error
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn entry() -> DownloadManifestEntry {
        DownloadManifestEntry {
            name: "alpha".to_string(),
            file: "alpha.txt".to_string(),
            url: Some("https://example.com/alpha.txt".to_string()),
            sha256: sha256_hex(b"alpha"),
            downloaded_at: "2026-08-15T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn loads_a_valid_v1_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        let manifest = DownloadManifest::new(vec![entry()]).unwrap();
        fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();

        assert_eq!(load_manifest(&path).unwrap(), manifest);
    }

    #[test]
    fn rejects_legacy_manifest_arrays() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        fs::write(&path, "[]").unwrap();

        assert!(
            load_manifest(&path)
                .unwrap_err()
                .to_string()
                .contains("legacy offline manifest arrays")
        );
    }

    #[test]
    fn rejects_unsupported_manifest_versions() {
        let mut manifest = DownloadManifest::new(vec![entry()]).unwrap();
        manifest.version = 2;

        assert!(
            manifest
                .validate()
                .unwrap_err()
                .to_string()
                .contains("unsupported offline manifest version")
        );
    }

    #[test]
    fn rejects_parent_directory_paths() {
        let mut invalid_entry = entry();
        invalid_entry.file = "../alpha.txt".to_string();

        assert!(DownloadManifest::new(vec![invalid_entry]).is_err());
    }
}
