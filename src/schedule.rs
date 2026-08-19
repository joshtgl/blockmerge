//! Schedule validation and interval parsing.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, ScheduleConfig};
use tokio_cron_scheduler::JobScheduler;

impl ScheduleConfig {
    /// Validate that exactly one schedule form is configured.
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        match (self.interval.as_deref(), self.cron.as_deref()) {
            (Some(_), Some(_)) => {
                Err("schedule config must set exactly one of interval or cron".into())
            }
            (None, None) => Err("schedule config must set one of interval or cron".into()),
            (Some(interval), None) => {
                parse_interval_duration(interval)?;
                Ok(())
            }
            (None, Some(cron)) => {
                tokio_cron_scheduler::Job::new_async(cron, |_uuid, _lock| Box::pin(async move {}))?;
                Ok(())
            }
        }
    }
}

/// Validate refresh scheduling for a long-running runtime.
pub fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    config.schedule_config()?.validate()
}

/// Validate refresh scheduling for the web runtime.
pub fn validate_web_runtime_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    validate_runtime_config(config)
}

/// Register a task to run according to `schedule`.
///
/// The task is responsible for reporting its own execution errors so that a
/// single failed refresh does not stop subsequent scheduled runs.
pub async fn register_schedule<F, Fut>(
    scheduler: &JobScheduler,
    schedule: ScheduleConfig,
    task: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    schedule.validate()?;
    let task = Arc::new(task);
    let job = if let Some(interval) = schedule.interval {
        let duration = parse_interval_duration(&interval)?;
        tokio_cron_scheduler::Job::new_repeated_async(duration, move |_uuid, _lock| {
            let task = Arc::clone(&task);
            Box::pin(async move { task().await })
        })?
    } else if let Some(cron) = schedule.cron {
        tokio_cron_scheduler::Job::new_async(cron, move |_uuid, _lock| {
            let task = Arc::clone(&task);
            Box::pin(async move { task().await })
        })?
    } else {
        return Err("missing schedule interval or cron".into());
    };

    scheduler.add(job).await?;
    Ok(())
}

/// Parse a positive duration with `ms`, `s`, `m`, `h`, or `d` suffix.
pub fn parse_interval_duration(input: &str) -> Result<Duration, Box<dyn std::error::Error>> {
    let value = input.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err("schedule interval cannot be empty".into());
    }
    let (number, unit_seconds) = if let Some(number) = value.strip_suffix("ms") {
        return Ok(Duration::from_millis(
            number
                .trim()
                .parse::<u64>()
                .map_err(|error| format!("invalid interval '{}': {}", input, error))?,
        ));
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 60 * 60)
    } else if let Some(number) = value.strip_suffix('d') {
        (number, 60 * 60 * 24)
    } else {
        return Err(format!(
            "invalid interval '{}': expected suffix ms, s, m, h, or d",
            input
        )
        .into());
    };
    let quantity = number
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("invalid interval '{}': {}", input, error))?;
    Ok(Duration::from_secs(quantity.saturating_mul(unit_seconds)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_support::runtime_config_toml;
    use tokio::sync::Notify;

    #[test]
    fn parses_supported_interval_units() {
        assert_eq!(
            parse_interval_duration("150ms").unwrap(),
            Duration::from_millis(150)
        );
        assert_eq!(
            parse_interval_duration("15m").unwrap(),
            Duration::from_secs(900)
        );
        assert_eq!(
            parse_interval_duration("2d").unwrap(),
            Duration::from_secs(172_800)
        );
        assert!(parse_interval_duration("every day").is_err());
    }

    #[test]
    fn validates_exactly_one_schedule_type() {
        let config: Config = toml::from_str(
            r#"
[schedule]
interval = "15m"
cron = "0 0/15 * * * *"
"#,
        )
        .unwrap();

        assert!(validate_web_runtime_config(&config).is_err());
    }

    #[tokio::test]
    async fn runs_a_registered_interval_task() {
        let mut scheduler = JobScheduler::new().await.unwrap();
        let task_ran = Arc::new(Notify::new());
        let notification = Arc::clone(&task_ran);
        register_schedule(
            &scheduler,
            ScheduleConfig {
                interval: Some("10ms".to_string()),
                cron: None,
                run_on_startup: true,
            },
            move || {
                let notification = Arc::clone(&notification);
                async move { notification.notify_one() }
            },
        )
        .await
        .unwrap();
        scheduler.start().await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), task_ran.notified())
            .await
            .expect("scheduled task should run");
        scheduler.shutdown().await.unwrap();
    }

    #[test]
    fn test_validate_web_runtime_config_accepts_interval_schedule() {
        let config: Config = toml::from_str(&runtime_config_toml(r#"interval = "15m""#)).unwrap();

        validate_web_runtime_config(&config).unwrap();

        assert_eq!(
            config.web.unwrap().general.unwrap().host.as_deref(),
            Some("0.0.0.0")
        );
    }

    #[test]
    fn test_validate_web_runtime_config_accepts_cron_schedule() {
        let config: Config =
            toml::from_str(&runtime_config_toml(r#"cron = "0 0/15 * * * *""#)).unwrap();

        validate_web_runtime_config(&config).unwrap();

        assert_eq!(
            config.schedule.unwrap().cron.as_deref(),
            Some("0 0/15 * * * *")
        );
    }

    #[test]
    fn test_validate_web_runtime_config_rejects_both_interval_and_cron() {
        let config: Config = toml::from_str(&runtime_config_toml(
            r#"
interval = "15m"
cron = "0 0/15 * * * *"
"#,
        ))
        .unwrap();

        let err = validate_web_runtime_config(&config).unwrap_err();

        assert!(err.to_string().contains("exactly one of interval or cron"));
    }

    #[test]
    fn test_validate_web_runtime_config_rejects_missing_schedule_target() {
        let config: Config = toml::from_str(&runtime_config_toml("")).unwrap();

        let err = validate_web_runtime_config(&config).unwrap_err();

        assert!(err.to_string().contains("must set one of interval or cron"));
    }

    #[test]
    fn test_parse_interval_duration_supports_common_units() {
        assert_eq!(
            parse_interval_duration("150ms").unwrap(),
            Duration::from_millis(150)
        );
        assert_eq!(
            parse_interval_duration("15m").unwrap(),
            Duration::from_secs(900)
        );
        assert_eq!(
            parse_interval_duration("1h").unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            parse_interval_duration("2d").unwrap(),
            Duration::from_secs(172800)
        );
    }

    #[test]
    fn test_parse_interval_duration_rejects_invalid_values() {
        let err = parse_interval_duration("every day").unwrap_err();
        assert!(err.to_string().contains("expected suffix"));
    }
}
