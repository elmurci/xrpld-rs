//! Experimental [XRP Ledger](https://xrpl.org/) node on [Rust](https://www.rust-lang.org/).
//! Based on [rippled](https://github.com/ripple/rippled/), crated as learning project.

use config::Config;
use lazy_static::lazy_static;
use overlay::Network;
use shared::{log, structs::config::XrpldConfig};
use tokio::sync::RwLock;

mod args;

lazy_static! {
    static ref SETTINGS: RwLock<Config> = RwLock::new(Config::default());
}

/// Start Rust XRPL node.
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    log::init();
    log::info!("Starting node (v{})", VERSION);
    let _args = args::get_args();

    let settings = Config::builder()
        .add_source(config::File::with_name("cfg/xrpld.json")) // TODO: read from command line
        .add_source(config::Environment::with_prefix("XRPLD"))
        .build()
        .unwrap();

    let config = settings.try_deserialize::<XrpldConfig>().unwrap();

    log::info!("Configuration loaded!");

    log::debug!("Config {:?}", config);

    tokio::spawn(async move {
        let mut network = Network::new(config);
        if let Err(error) = network.start().await {
            log::error!("XRPLD:APP {}", error);
            std::process::exit(1);
        }
    }).await.unwrap();

}
