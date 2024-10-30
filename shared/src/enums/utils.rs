use core::fmt;

#[derive(Debug)]
pub enum Process {
    Main,
    Networking,
    Consensus,
    Other
}

impl fmt::Display for Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub enum LogType {
    Info,
    Debug,
    Warn,
    Error,
    Trace
}