//! Resolution of persistent refresh state and cache locations.

use std::path::PathBuf;

use etcetera::{AppStrategy, AppStrategyArgs, app_strategy};

/// Filesystem locations used by resilient refreshes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePaths {
    pub state_file: PathBuf,
    pub cache_dir: PathBuf,
}

/// Resolve explicit paths or use native per-user application directories.
pub fn resolve_storage_paths(
    state_file: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
) -> Result<StoragePaths, Box<dyn std::error::Error>> {
    let defaults = default_storage_paths()?;
    Ok(StoragePaths {
        state_file: state_file.unwrap_or(defaults.state_file),
        cache_dir: cache_dir.unwrap_or(defaults.cache_dir),
    })
}

fn default_storage_paths() -> Result<StoragePaths, Box<dyn std::error::Error>> {
    let args = AppStrategyArgs {
        top_level_domain: "org".to_string(),
        author: "Blockmerge".to_string(),
        app_name: "blockmerge".to_string(),
    };
    match app_strategy::choose_native_strategy(args) {
        Ok(strategy) => Ok(StoragePaths {
            state_file: strategy
                .state_dir()
                .unwrap_or_else(|| strategy.data_dir())
                .join("state.json"),
            cache_dir: strategy.cache_dir().join("sources"),
        }),
        Err(_) => {
            let root = std::env::current_dir()?.join(".blockmerge");
            Ok(StoragePaths {
                state_file: root.join("state.json"),
                cache_dir: root.join("cache"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::resolve_storage_paths;

    #[test]
    fn explicit_paths_override_platform_defaults() {
        let resolved = resolve_storage_paths(
            Some(PathBuf::from("/tmp/state.json")),
            Some(PathBuf::from("/tmp/cache")),
        )
        .unwrap();

        assert_eq!(resolved.state_file, PathBuf::from("/tmp/state.json"));
        assert_eq!(resolved.cache_dir, PathBuf::from("/tmp/cache"));
    }
}
