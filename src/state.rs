//! Persistent state for completed source updates.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

/// Current refresh-state format version.
pub const STATE_VERSION: u32 = 1;

/// Metadata used to validate a cached raw source body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedSource {
    pub cache_file: String,
    pub sha256: String,
}

/// Information about the last successful update for a list source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlocklistStatus {
    pub last_success_at: Option<String>,
    #[serde(default)]
    pub last_attempt_at: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub cached_source: Option<CachedSource>,
}

/// State file tracking last update times for each source.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StateFile {
    pub version: u32,
    #[serde(default)]
    pub sources: HashMap<String, BlocklistStatus>,
}

impl StateFile {
    /// Record a successfully cached source body.
    pub fn mark_success(
        &mut self,
        name: &str,
        last_success_at: String,
        cached_source: CachedSource,
    ) {
        let last_attempt_at = last_success_at.clone();
        self.sources.insert(
            name.to_string(),
            BlocklistStatus {
                last_success_at: Some(last_success_at),
                last_attempt_at: Some(last_attempt_at),
                consecutive_failures: 0,
                cached_source: Some(cached_source),
            },
        );
    }

    /// Increment and return a source's consecutive failure count.
    pub fn mark_failure(&mut self, name: &str, last_attempt_at: String) -> u32 {
        let status = self.sources.entry(name.to_string()).or_default();
        status.last_attempt_at = Some(last_attempt_at);
        status.consecutive_failures = status.consecutive_failures.saturating_add(1);
        status.consecutive_failures
    }

    /// Return current metadata for a source.
    pub fn source(&self, name: &str) -> Option<&BlocklistStatus> {
        self.sources.get(name)
    }

    /// Remove state for a source and return its cache metadata when present.
    pub fn remove_source(&mut self, name: &str) -> Option<CachedSource> {
        self.sources
            .remove(name)
            .and_then(|status| status.cached_source)
    }

    /// Remove cache metadata while retaining failure history.
    pub fn expire_cache(&mut self, name: &str) -> Option<CachedSource> {
        self.sources
            .get_mut(name)
            .and_then(|status| status.cached_source.take())
    }
}

/// Load the state file, returning an empty state when it does not exist.
pub fn load_state(path: impl AsRef<Path>) -> Result<StateFile, Box<dyn std::error::Error>> {
    let path = path.as_ref();
    if path.exists() {
        let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
        if value.get("version").is_none() {
            return Ok(StateFile::default());
        }
        let state: StateFile = serde_json::from_value(value)?;
        if state.version != STATE_VERSION {
            return Err(format!("unsupported refresh state version {}", state.version).into());
        }
        Ok(state)
    } else {
        Ok(StateFile::default())
    }
}

/// Save state as pretty-printed JSON.
pub fn save_state(
    path: impl AsRef<Path>,
    state: &StateFile,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let path = path.as_ref();
    let mut state = StateFile {
        version: STATE_VERSION,
        sources: state.sources.clone(),
    };
    state.version = STATE_VERSION;
    let content = serde_json::to_string_pretty(&state)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(content.as_bytes())?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_file_is_empty() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing.json");

        assert!(load_state(&path).unwrap().sources.is_empty());
    }

    #[test]
    fn ignores_legacy_timestamp_only_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        fs::write(
            &path,
            r#"{"alpha":{"last_updated":"2026-01-01T00:00:00Z"}}"#,
        )
        .unwrap();

        assert!(load_state(&path).unwrap().sources.is_empty());
    }

    #[test]
    fn saves_and_loads_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let mut state = StateFile::default();
        state.sources.insert(
            "alpha".to_string(),
            BlocklistStatus {
                last_success_at: Some("2026-01-01T00:00:00Z".to_string()),
                last_attempt_at: None,
                consecutive_failures: 0,
                cached_source: None,
            },
        );

        save_state(&path, &state).unwrap();

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&path).unwrap()).unwrap()
                ["version"],
            STATE_VERSION
        );

        assert_eq!(
            load_state(&path)
                .unwrap()
                .sources
                .get("alpha")
                .unwrap()
                .last_success_at
                .as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn tracks_successes_and_failures() {
        let mut state = StateFile::default();
        assert_eq!(
            state.mark_failure("failed", "2026-01-01T00:00:00Z".to_string()),
            1
        );
        state.mark_success(
            "successful",
            "2026-01-01T00:00:00Z".to_string(),
            CachedSource {
                cache_file: "successful.body".to_string(),
                sha256: "0".repeat(64),
            },
        );

        assert_eq!(state.sources["failed"].consecutive_failures, 1);
        assert_eq!(state.sources["successful"].consecutive_failures, 0);
    }

    #[test]
    fn test_load_state_nonexistent() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("nonexistent_state.json");
        let state = load_state(temp_file.to_str().unwrap()).unwrap();
        assert!(state.sources.is_empty());
    }

    #[test]
    fn test_save_and_load_state() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_state.json");
        let path = temp_file.to_str().unwrap();

        let mut state = StateFile::default();
        state.sources.insert(
            "source1".to_string(),
            BlocklistStatus {
                last_success_at: Some("2026-01-01T00:00:00Z".to_string()),
                last_attempt_at: None,
                consecutive_failures: 0,
                cached_source: None,
            },
        );

        save_state(path, &state).unwrap();
        let loaded = load_state(path).unwrap();
        assert_eq!(loaded.sources.len(), 1);
        let status = loaded.sources.get("source1").unwrap();
        assert_eq!(
            status.last_success_at.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );

        fs::remove_file(temp_file).unwrap();
    }
}
