//! Experimental [XRP Ledger](https://xrpl.org/) node on [Rust](https://www.rust-lang.org/).
//! Based on [rippled](https://github.com/ripple/rippled/), crated as learning project.

use config::Config;
use lazy_static::lazy_static;
use overlay::Network;
use shared::{enums::utils::{LogType, Process}, structs::config::XrpldConfig, utils::logger::{log, log_init}};
use tokio::{sync::RwLock, task::JoinSet};
use std::{num::ParseIntError, sync::Arc};

mod args;

const LOG_KEY:&str = "Main";

// TODO: review this
lazy_static! {
    static ref SETTINGS: RwLock<Config> = RwLock::new(Config::default());
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Start Rust XRPL node.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    log_init();
    log(Process::Main, LogType::Info, LOG_KEY, format!("Starting node (v{})", VERSION));

    // let _args = args::get_args();

    let settings = Config::builder()
        .add_source(config::File::with_name("cfg/xrpld.json")) // TODO: read from command line
        .add_source(config::Environment::with_prefix("XRPLD"))
        .build()
        .unwrap();

    let config: Arc<XrpldConfig> = Arc::new(settings.try_deserialize::<XrpldConfig>().unwrap());

    log(Process::Main, LogType::Info, LOG_KEY, String::from("Configuration loaded!"));
    log(Process::Main, LogType::Debug, LOG_KEY, format!("Config {:?}", config));

    let mut set = JoinSet::new();

    set.spawn(async move {
        let mut overlay = Network::new(config);
        let _ = overlay.start().await;
    });

    set.join_all().await;

    // tokio::spawn(async move {
        
    //     if let Err(error) = network.start().await {
    //         log::error!("XRPLD:APP {}", error);
    //         std::process::exit(1);
    //     }
    // }).await.unwrap();


}
