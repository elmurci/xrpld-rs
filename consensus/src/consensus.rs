/// Encode given input with prefix to base58-check based on Ripple alphabet.
pub fn should_close_ledger(
    anyTransactions: bool,
    prevProposers: bool,
    proposersClosed: bool,
    proposersValidated: bool,
    prevRoundTime: bool,
    timeSincePrevClose: bool,              // Time since last ledger's close time
    openTime: bool,  // Time waiting to close this ledger
    idleInterval: bool,
    params: bool,
) -> bool {

    // if ((prevRoundTime < -1s) || (prevRoundTime > 10min) ||
    //     (timeSincePrevClose > 10min))
    // {
    //     // These are unexpected cases, we just close the ledger
    //     log::warn!("CONS:Ledger shouldCloseLedger [anyTransactions: {}, prevProposers: {}, timeSincePrevClose: {}, prevRoundTime: {}]", anyTransactions, prevProposers, timeSincePrevClose, prevRoundTime);
    //     return true;
    // }
    true
}
    