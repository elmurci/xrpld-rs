use crate::enums::utils::{LogType, Process};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use env_logger::{fmt, Builder, Env, Target};
use log::{Level, Record};
use serde_json::json;

pub use log::{debug, error, info, trace, warn};

/// Initialize logger with [`env_logger`](https://crates.io/crates/env_logger).
pub fn log_init() {
    let env = Env::default()
        .default_filter_or("info") // RUST_LOG
        .default_write_style_or("never"); // RUST_LOG_STYLE

    Builder::from_env(env)
        .target(Target::Stdout)
        .format(log_format)
        .init();
}

/// Format function for log record.
fn log_format(buf: &mut fmt::Formatter, record: &Record<'_>) -> io::Result<()> {
    let level = record.level();
    let level_human = match level {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    };
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    write!(buf, "{{")?;
    write!(buf, r#""level":"{}""#, level_human)?;
    write!(buf, r#","time":{}"#, time)?;
    write!(buf, r#","msg":{}"#, json!(record.args().to_string()))?;
    if level == Level::Debug || level == Level::Trace {
        write!(buf, r#","target":"{}""#, record.target())?;
        if let Some(module) = record.module_path() {
            write!(buf, r#","module":"{}""#, module)?;
        }
        if let Some(file) = record.file() {
            write!(buf, r#","file":"{}""#, file)?;
        }
        if let Some(line) = record.line() {
            write!(buf, r#","line":"{}""#, line)?;
        }
    }
    writeln!(buf, "}}")
}

pub fn log(process: Process, log_type: LogType, key: &str, message: String) {
    let log_str = format!("{process}:{key} {message}");
    match log_type {
        LogType::Info => log::info!("{}", log_str),
        LogType::Debug => log::debug!("{}", log_str),
        LogType::Warn => log::warn!("{}", log_str),
        LogType::Trace => log::trace!("{}", log_str),
        LogType::Error => log::error!("{}", log_str),
    }
}