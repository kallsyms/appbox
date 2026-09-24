//! How a guest's threads map onto vCPUs; see [`ThreadingModel`].

/// How a [`DefaultTrapHandler`](crate::trap::DefaultTrapHandler) runs a guest's threads.
///
/// Processes the guest spawns use the same model as the one that spawned them, whatever their
/// embedder asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadingModel {
    /// One vCPU, which guest threads take turns on (see [`crate::threads`]): one runs at a time
    /// and appbox decides when threads switch, so a run can be recorded and replayed exactly.
    TimeShared,
    /// A vCPU per guest thread, on a host thread of its own, all running at once (see
    /// [`crate::runner`]). Guests then race as they would natively, so they can't be recorded and
    /// replayed, nor checkpointed.
    Parallel,
}

/// How a process spawned for a guest learns its spawner's model.
const ENV: &str = "APPBOX_THREADING";

impl ThreadingModel {
    /// The model to hand down to a process spawned for a guest, as an environment variable.
    pub(crate) fn env(self) -> (&'static str, String) {
        (ENV, format!("{self:?}"))
    }

    /// The model this process was spawned with, if it was spawned for a guest.
    pub(crate) fn inherited() -> Option<Self> {
        Self::parse(&std::env::var(ENV).ok()?)
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::TimeShared, Self::Parallel]
            .into_iter()
            .find(|model| format!("{model:?}") == value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn models_survive_the_trip_to_a_spawned_process() {
        for model in [ThreadingModel::TimeShared, ThreadingModel::Parallel] {
            let (name, value) = model.env();
            assert_eq!(name, ENV);
            assert_eq!(ThreadingModel::parse(&value), Some(model));
        }
        assert_eq!(ThreadingModel::parse("sideways"), None);
    }
}
