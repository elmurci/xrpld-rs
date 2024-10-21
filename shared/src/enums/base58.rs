/// Data prefix.
/// https://github.com/ripple/rippled/blob/1.5.0/src/ripple/protocol/tokens.h#L29-L39
#[derive(Debug)]
pub enum Version {
    // None,
    NodePublic,
    NodePrivate,
    AccountID,
    AccountPublic,
    AccountSecret,
    // FamilyGenerator,
    FamilySeed,
}

impl Version {
    /// Resolve enum variant to `u8`.
    pub fn value(&self) -> u8 {
        match *self {
            // Version::None => 1,
            Version::NodePublic => 28,
            Version::NodePrivate => 32,
            Version::AccountID => 0,
            Version::AccountPublic => 35,
            Version::AccountSecret => 34,
            // Version::FamilyGenerator => 41,
            Version::FamilySeed => 33,
        }
    }
}