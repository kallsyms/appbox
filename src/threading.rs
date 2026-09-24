//! How a guest's threads map onto vCPUs.
//!
//! By default they're time-shared on one vCPU (see [`crate::threads`]): one guest thread runs at
//! a time and appbox decides when threads switch, so a run can be recorded and replayed exactly.
//! With [`use_parallel_vcpus`], each guest thread instead gets its own vCPU, on its own host
//! thread, and they all run at once, at the price of that determinism: replays can't work,
//! checkpoints aren't available, and guests race as they would natively.

/// Set in the environment for parallel vCPUs, so that every host process a guest spawns (and
/// the image a guest execs) inherits the choice.
const ENV: &str = "APPBOX_THREADING";
const PARALLEL: &str = "parallel";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadingModel {
    /// One vCPU, which guest threads take turns on.
    TimeShared,
    /// A vCPU per guest thread, all running at once.
    Parallel,
}

/// Opts this process, and every host process its guests spawn, into [`ThreadingModel::Parallel`].
/// Call it before creating a VM or trap handler, and before starting any threads (it sets an
/// environment variable).
///
/// Guests then run nondeterministically: they can't be recorded and replayed, nor
/// checkpointed.
pub fn use_parallel_vcpus() {
    std::env::set_var(ENV, PARALLEL);
}

/// The threading model this process uses.
pub fn model() -> ThreadingModel {
    match std::env::var(ENV) {
        Ok(value) if value == PARALLEL => ThreadingModel::Parallel,
        _ => ThreadingModel::TimeShared,
    }
}
