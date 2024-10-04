use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum NetworkId {
    Main,
    Test,
    Parallel(u32),
}

impl NetworkId {
    /// Network id represented by 32-bit unsigned integer.
    pub fn value(&self) -> u32 {
        match *self {
            NetworkId::Main => 0,
            NetworkId::Test => 1,
            NetworkId::Parallel(id) => id,
        }
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, ", {}", self.value())?;
        Ok(())
    }
}

impl std::str::FromStr for NetworkId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.parse::<u32>()? {
            0 => NetworkId::Main,
            1 => NetworkId::Test,
            id => NetworkId::Parallel(id),
        })
    }
}