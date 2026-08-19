use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blockmerge::{
    config::{Config, WebConfig, load_config},
    generation::RefreshContext,
    output::{
        generate_blocklist_outputs_with_resilience, web_asset_output_paths,
        write_generated_outputs_if_changed,
    },
    schedule::{register_schedule, validate_web_runtime_config},
    state::{load_state, save_state},
    storage::resolve_storage_paths,
};
use clap::Parser;
use static_web_server::{Server, Settings, logger};
use tokio::sync::Mutex;
use tokio_cron_scheduler::JobScheduler;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file (default: blockmerge.toml)
    #[arg(
        long,
        default_value = "blockmerge.toml",
        env = "BLOCKMERGE_CONFIG_FILE"
    )]
    config: String,

    /// Path to the JSON refresh state file
    #[arg(long, env = "BLOCKMERGE_STATE_FILE")]
    state_file: Option<PathBuf>,

    /// Directory where cached source bodies are stored
    #[arg(long, env = "BLOCKMERGE_CACHE_DIR")]
    cache_dir: Option<PathBuf>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Loading configuration from {}...", args.config);
    let config = load_config(&args.config)?;
    validate_web_runtime_config(&config)?;

    let schedule = config.schedule_config()?.clone();
    let storage = resolve_storage_paths(args.state_file, args.cache_dir)?;
    let state = load_state(&storage.state_file)?;
    let refresh_context = Arc::new(Mutex::new(RefreshContext::new(
        config.resilience_policy()?,
        state,
        storage.cache_dir,
    )));
    let state_file = Arc::new(storage.state_file);
    let settings = build_server_settings(config.web.as_ref())?;
    let web_root = settings.general.root.clone();
    let web_host = settings.general.host.clone();
    let web_port = settings.general.port;
    std::fs::create_dir_all(&web_root)?;
    logger::init(&settings.general.log_level, settings.general.log_with_ansi)?;
    let server = Server::new(settings)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let shared_config = Arc::new(config);
    let shared_client = Arc::new(client);
    let shared_root = Arc::new(web_root.clone());

    if schedule.run_on_startup {
        run_refresh(
            shared_client.as_ref(),
            shared_config.as_ref(),
            shared_root.as_ref(),
            refresh_context.as_ref(),
            state_file.as_ref(),
        )
        .await?;
    }

    let scheduler = JobScheduler::new().await?;
    register_schedule(&scheduler, schedule, move || {
        let client = Arc::clone(&shared_client);
        let config = Arc::clone(&shared_config);
        let root_dir = Arc::clone(&shared_root);
        let refresh_context = Arc::clone(&refresh_context);
        let state_file = Arc::clone(&state_file);
        async move {
            if let Err(error) =
                run_refresh(&client, &config, &root_dir, &refresh_context, &state_file).await
            {
                eprintln!("Scheduled refresh failed: {error}");
            }
        }
    })
    .await?;
    scheduler.start().await?;

    println!(
        "Serving blocklists from {} on http://{}:{}",
        web_root.display(),
        web_host,
        web_port
    );

    let server_result = std::thread::spawn(move || server.run_standalone(None))
        .join()
        .map_err(|_| "static web server thread panicked")?;

    server_result.map_err(|err| err.to_string().into())
}

async fn run_refresh(
    client: &reqwest::blocking::Client,
    config: &Config,
    root_dir: &Path,
    refresh_context: &Mutex<RefreshContext>,
    state_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut refresh_context = refresh_context.lock().await;
    let outputs = tokio::task::block_in_place(|| {
        generate_blocklist_outputs_with_resilience(client, config, &mut refresh_context)
    })?;
    save_state(state_file, &refresh_context.state)?;
    let (inbound_path, outbound_path) = web_asset_output_paths(root_dir);
    let written = write_generated_outputs_if_changed(
        &inbound_path,
        &outbound_path,
        &outputs,
        config.output.timestamp_header,
    )?;
    println!(
        "Refreshed web assets in {} (inbound: {} {}, outbound: {} {})",
        root_dir.display(),
        outputs.inbound_entries,
        if written.inbound_updated {
            "updated"
        } else {
            "unchanged"
        },
        outputs.outbound_entries,
        if written.outbound_updated {
            "updated"
        } else {
            "unchanged"
        }
    );
    Ok(())
}

fn build_server_settings(web: Option<&WebConfig>) -> Result<Settings, Box<dyn std::error::Error>> {
    match web {
        Some(web) => {
            let mut temp_config = tempfile::Builder::new()
                .prefix("blockmerge-web-")
                .suffix(".toml")
                .tempfile()?;
            write!(temp_config, "{}", toml::to_string_pretty(web)?)?;
            let temp_config_arg = temp_config.path().to_string_lossy().into_owned();
            Settings::get_unparsed(
                false,
                &["blockmerge-web", "--config-file", temp_config_arg.as_str()],
            )
            .map_err(Into::into)
        }
        None => Settings::get_unparsed(false, &["blockmerge-web"]).map_err(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::build_server_settings;

    #[test]
    fn fallback_settings_do_not_parse_blockmerge_arguments() {
        assert!(build_server_settings(None).is_ok());
    }
}
