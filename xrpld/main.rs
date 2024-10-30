//! Experimental [XRP Ledger](https://xrpl.org/) node on [Rust](https://www.rust-lang.org/).
//! Based on [rippled](https://github.com/ripple/rippled/), crated as learning project.
use overlay::Network;
use shared::{enums::utils::{LogType, Process}, utils::{config::xrpld_config, logger::{log, log_init}}};
use tokio::task::JoinSet;
use std::{num::ParseIntError, sync::Arc};

mod args;

const LOG_KEY:&str = "Main";

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

    let xrpld_config = xrpld_config(None);

    // let config: Arc<XrpldConfig> = Arc::new(settings.try_deserialize::<XrpldConfig>().unwrap());

    log(Process::Main, LogType::Info, LOG_KEY, String::from("Configuration loaded!"));
    log(Process::Main, LogType::Debug, LOG_KEY, format!("Config {:?}", xrpld_config));

    let mut set = JoinSet::new();

    set.spawn(async move {
        let mut overlay = Network::new();
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
