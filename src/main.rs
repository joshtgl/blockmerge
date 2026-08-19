use std::path::PathBuf;
use std::sync::Arc;

use blockmerge::{
    config::load_config,
    generation::RefreshContext,
    output::{generate_blocklist_outputs_with_resilience, write_generated_outputs_if_changed},
    schedule::{register_schedule, validate_runtime_config},
    state::{load_state, save_state},
    storage::resolve_storage_paths,
};
use clap::Parser;
use tokio::sync::Mutex;
use tokio_cron_scheduler::JobScheduler;

/// Blocklist merger application.
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

    /// Run continuously using the configured [schedule]
    #[arg(long)]
    daemon: bool,

    /// Path to the generated inbound blocklist
    #[arg(
        long,
        default_value = "blocklist_output_inbound.txt",
        env = "BLOCKMERGE_INBOUND_OUTPUT"
    )]
    inbound_output: PathBuf,

    /// Path to the generated outbound blocklist
    #[arg(
        long,
        default_value = "blocklist_output_outbound.txt",
        env = "BLOCKMERGE_OUTBOUND_OUTPUT"
    )]
    outbound_output: PathBuf,

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
    if args.daemon {
        run_daemon(args).await
    } else {
        run_once(args)
    }
}

fn run_once(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading configuration from {}...", args.config);
    let config = load_config(&args.config)?;
    let storage = resolve_storage_paths(args.state_file, args.cache_dir)?;
    let state = load_state(&storage.state_file)?;
    let mut refresh = RefreshContext::new(config.resilience_policy()?, state, storage.cache_dir);
    let client = build_client()?;

    let outputs = generate_blocklist_outputs_with_resilience(&client, &config, &mut refresh)?;
    save_state(&storage.state_file, &refresh.state)?;
    let written = write_generated_outputs_if_changed(
        &args.inbound_output,
        &args.outbound_output,
        &outputs,
        config.output.timestamp_header,
    )?;
    print_refresh_result(&outputs, written.inbound_updated, written.outbound_updated);
    println!("State saved to {}", storage.state_file.display());
    Ok(())
}

async fn run_daemon(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading configuration from {}...", args.config);
    let config = load_config(&args.config)?;
    validate_runtime_config(&config)?;
    let schedule = config.schedule_config()?.clone();
    let storage = resolve_storage_paths(args.state_file, args.cache_dir)?;
    let state = load_state(&storage.state_file)?;

    let refresh_context = Arc::new(Mutex::new(RefreshContext::new(
        config.resilience_policy()?,
        state,
        storage.cache_dir,
    )));
    let shared_config = Arc::new(config);
    let shared_client = Arc::new(build_client()?);
    let state_file = Arc::new(storage.state_file);
    let inbound_output = Arc::new(args.inbound_output);
    let outbound_output = Arc::new(args.outbound_output);

    if schedule.run_on_startup {
        run_refresh(
            shared_client.as_ref(),
            shared_config.as_ref(),
            inbound_output.as_ref(),
            outbound_output.as_ref(),
            refresh_context.as_ref(),
            state_file.as_ref(),
        )
        .await?;
    }

    let mut scheduler = JobScheduler::new().await?;
    register_schedule(&scheduler, schedule, move || {
        let client = Arc::clone(&shared_client);
        let config = Arc::clone(&shared_config);
        let inbound_output = Arc::clone(&inbound_output);
        let outbound_output = Arc::clone(&outbound_output);
        let refresh_context = Arc::clone(&refresh_context);
        let state_file = Arc::clone(&state_file);
        async move {
            if let Err(error) = run_refresh(
                &client,
                &config,
                &inbound_output,
                &outbound_output,
                &refresh_context,
                &state_file,
            )
            .await
            {
                eprintln!("Scheduled refresh failed: {error}");
            }
        }
    })
    .await?;
    scheduler.start().await?;

    println!("Daemon started; waiting for scheduled refreshes.");
    wait_for_shutdown().await?;
    println!("Shutting down daemon...");
    scheduler.shutdown().await?;
    Ok(())
}

fn build_client() -> Result<reqwest::blocking::Client, Box<dyn std::error::Error>> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(Into::into)
}

async fn run_refresh(
    client: &reqwest::blocking::Client,
    config: &blockmerge::config::Config,
    inbound_output: &std::path::Path,
    outbound_output: &std::path::Path,
    refresh_context: &Mutex<RefreshContext>,
    state_file: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut refresh_context = refresh_context.lock().await;
    let outputs = tokio::task::block_in_place(|| {
        generate_blocklist_outputs_with_resilience(client, config, &mut refresh_context)
    })?;
    save_state(state_file, &refresh_context.state)?;
    let written = write_generated_outputs_if_changed(
        inbound_output,
        outbound_output,
        &outputs,
        config.output.timestamp_header,
    )?;
    print_refresh_result(&outputs, written.inbound_updated, written.outbound_updated);
    Ok(())
}

fn print_refresh_result(
    outputs: &blockmerge::generation::GeneratedBlocklistOutputs,
    inbound_updated: bool,
    outbound_updated: bool,
) {
    println!(
        "Inbound output: {} entries ({})",
        outputs.inbound_entries,
        if inbound_updated {
            "updated"
        } else {
            "unchanged"
        }
    );
    println!(
        "Outbound output: {} entries ({})",
        outputs.outbound_entries,
        if outbound_updated {
            "updated"
        } else {
            "unchanged"
        }
    );
}

#[cfg(unix)]
async fn wait_for_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(Into::into),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    tokio::signal::ctrl_c().await.map_err(Into::into)
}
