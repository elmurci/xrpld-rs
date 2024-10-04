use clap::Command;
//use clap::{App, AppSettings, Arg};

#[derive(Debug)]
pub enum Args {
    Node(ConfigNode),
}

#[derive(Debug)]
pub struct ConfigNode {

}

/// Parse program arguments to [`Args`][Args].
pub fn get_args() -> Args {
    let version = include_str!("./args.rs-version").trim();
    // if version.split_whitespace().collect::<Vec<&str>>()[0] != crate_version!() {
    //     panic!(
    //         "Saved version missmatch, saved: {}, CARGO_PKG_VERSION: {}",
    //         version,
    //         crate_version!()
    //     );
    // }

    let _matches = Command::new("xrpld")
        // .author(crate_authors!())
        // .about(crate_description!())
        .version(version);
        // .settings(&[AppSettings::DeriveDisplayOrder])
        // .args(&[Arg::// ::with_name("config")
        //     .long("config")
        //     .help("Path to config file")
        //     .value_name("config")
        //     .default_value("xrpld.cfg") // TODO
        //     .env("XRPLD_CONFIG")])
        // .get_matches();

    Args::Node(ConfigNode {})
}
