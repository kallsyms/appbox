/// Represents the type of exit returned after executing the guest.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ExitKind {
    Continue,
    EarlyFunctionReturn,
    Crash(String),
    Timeout,
    Exit,
    /// In parallel (see [`crate::threading`]): the guest thread on this vCPU is gone, so its host
    /// thread is done; the process carries on.
    ThreadExit,
    /// The guest called `execve()`; see [`crate::exec`].
    Exec(crate::exec::ExecRequest),
}
