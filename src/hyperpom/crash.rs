/// Represents the type of exit returned after executing the guest.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ExitKind {
    Continue,
    EarlyFunctionReturn,
    Crash(String),
    Timeout,
    Exit,
}
