use once_cell::sync::OnceCell;
use config::Config;
use crate::structs::config::XrpldConfig;

pub fn xrpld_config(path: Option<&str>) -> &'static XrpldConfig {
    static XRPLD_CONFIG: OnceCell<XrpldConfig> = OnceCell::new();
    XRPLD_CONFIG.get_or_init(|| {
        let settings: Config = Config::builder()
    .add_source(config::File::with_name(if path.is_none() { "cfg/xrpld.json" } else { path.unwrap() })) // TODO: read from command line
    .add_source(config::Environment::with_prefix("XRPLD"))
    .build()
    .unwrap();
    settings.try_deserialize::<XrpldConfig>().unwrap()
    })
}