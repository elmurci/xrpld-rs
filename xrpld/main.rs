//! Experimental [XRP Ledger](https://xrpl.org/) node on [Rust](https://www.rust-lang.org/).
//! Based on [rippled](https://github.com/ripple/rippled/), crated as learning project.

use std::collections::HashMap;
use config::Config;
use lazy_static::lazy_static;
use overlay::Network;
use shared::{log, structs::{config::XrpldConfig, field_info::field_info_lookup}, xrpl::deserializer::Deserializer};
use tokio::sync::RwLock;
use std::{fmt::Write, num::ParseIntError};

mod args;

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
    log::init();
    log::info!("Starting node (v{})", VERSION);

    // let _args = args::get_args();

    // let settings = Config::builder()
    //     .add_source(config::File::with_name("cfg/xrpld.json")) // TODO: read from command line
    //     .add_source(config::Environment::with_prefix("XRPLD"))
    //     .build()
    //     .unwrap();

    // let config = settings.try_deserialize::<XrpldConfig>().unwrap();

    // log::info!("Configuration loaded!");

    // log::debug!("Config {:?}", config);

    let field_info_map = field_info_lookup();
    let hex = "1200002280070000240013DAF5201B03CC4BC361D4D5DB3618B29F0000000000000000000000000055534400000000000A20B3C85F482532A9578DBB3950B85CA06594D168400000000000000C6940000000038C34007321EDD5551CDAD613AEB8DDBD4621B5EE66CBB0E9D322300AB8B8206208C63D562E597440BF4FBE6D56A5265430C63614AA085E4ECBB06459A22549DB978152DB3593173D07457C781DEB4BB59375255B286A0475C9CFF9772A05D40BBDE7134B43973E0381146EF659A5DEE7A1CF2DB67D0B66126B1013668DA883146EF659A5DEE7A1CF2DB67D0B66126B1013668DA8F9EA7C06636C69656E747D03726D32E1F1011230000000000000000000000000434E590000000000CED6E99370D5C00EF4EBF72567DA99F5661BFB3A00";

    let bytes = decode_hex(hex).unwrap();

    let mut parser = Deserializer::new(bytes, field_info_map.clone());

    log::debug!("deserializer {:?}", parser.deserialize_object());

    // tokio::spawn(async move {
    //     let mut network = Network::new(config);
    //     if let Err(error) = network.start().await {
    //         log::error!("XRPLD:APP {}", error);
    //         std::process::exit(1);
    //     }
    // }).await.unwrap();

}
