//! Running a guest's threads, time-shared on one vCPU or each on a vCPU (and host thread) of its
//! own; see [`ThreadingModel`].
//!
//! An embedder writes one loop that runs a guest thread's vCPU and handles its traps (a
//! [`ThreadRunner`]), and [`DefaultTrapHandler::run`] runs it for the guest's main thread, on the
//! calling thread. Time-shared, that's the only one: guest threads take turns on its vCPU. In
//! parallel, each thread the guest starts gets a host thread running the same loop on a new vCPU
//! of the same VM, and the process ends (for all of them) when one of them ends it.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use log::{debug, warn};

use crate::hyperpom::crash::ExitKind;
use crate::loader::Loader;
use crate::threading::ThreadingModel;
use crate::threads::{Message, ThreadId, ThreadSwitch};
use crate::trap::{DefaultTrapHandler, SyscallContext, SyscallResult, TrapHandler};
use crate::vm::{SharedVm, VmManager};

/// Runs a guest thread's vCPU, handling its traps through the [`GuestThread`], until the thread
/// or the process is done: returns [`ExitKind::ThreadExit`] if only the thread is (e.g. a
/// syscall result says so), and whatever else ended the process otherwise. It should return once
/// [`VmManager::run`] reports [`VmRunResult::Stopped`](crate::vm::VmRunResult::Stopped).
pub type ThreadRunner =
    dyn Fn(&mut VmManager, &mut GuestThread, &Loader) -> Result<ExitKind> + Send + Sync;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A guest thread's (time-shared: the vCPU's) way into the trap handler the guest's threads
/// share.
pub struct GuestThread {
    handler: Arc<Mutex<DefaultTrapHandler>>,
    id: ThreadId,
    /// In parallel: where the thread's host thread waits whenever the thread can't run.
    mailbox: Option<Receiver<Message>>,
}

impl GuestThread {
    /// The shared trap handler.
    pub fn handler(&self) -> MutexGuard<'_, DefaultTrapHandler> {
        lock(&self.handler)
    }

    /// The guest thread on the vCPU.
    pub fn current_thread(&self) -> ThreadId {
        match self.mailbox {
            Some(_) => self.id,
            None => self.handler().current_thread(),
        }
    }

    /// Handles a syscall (see [`TrapHandler::handle_syscall`]). In parallel, a syscall that
    /// blocks (in the host, or one appbox emulates) returns once it's done, with its result
    /// already in the thread's registers.
    pub fn handle_syscall(
        &mut self,
        ctx: &SyscallContext,
        vm: &mut VmManager,
        loader: &Loader,
    ) -> Result<SyscallResult> {
        let handler_ref = self.handler.clone();
        let mut handler = lock(&handler_ref);
        if self.mailbox.is_some() {
            handler.threads.set_current(self.id);
        }
        let result = handler.handle_syscall(ctx, vm, loader)?;
        if !result.waiting {
            return Ok(result);
        }
        self.wait(&handler_ref, handler, vm)
    }

    /// See [`DefaultTrapHandler::handle_timer`].
    pub fn handle_timer(&mut self, vm: &mut VmManager) -> Result<Option<ThreadSwitch>> {
        self.handler().handle_timer(vm)
    }

    /// In parallel: waits (with `handler` unlocked) until the thread can run, and puts it on
    /// the vCPU.
    fn wait<'h>(
        &self,
        handler_ref: &'h Mutex<DefaultTrapHandler>,
        mut handler: MutexGuard<'h, DefaultTrapHandler>,
        vm: &mut VmManager,
    ) -> Result<SyscallResult> {
        let mailbox = self.mailbox.as_ref().expect("only parallel threads wait");
        loop {
            if let Some(regs) = handler.threads.take_runnable(self.id) {
                regs.restore(&vm.vcpu)?;
                let shared = vm.shared().clone();
                let switched_in = handler.switched_in(&vm.vcpu, &mut shared.vma(), self.id)?;
                if switched_in {
                    return Ok(SyscallResult::resumed(
                        regs.x[0],
                        regs.x[1],
                        regs.cpsr & (0b1111 << 28),
                    ));
                }
            }
            drop(handler);
            let message = mailbox.recv().context("trap handler gone")?;
            handler = lock(handler_ref);
            handler.threads.set_current(self.id);
            match message {
                Message::Completed(_, ret) => handler.threads.completed(self.id, ret),
                Message::Stop => return Ok(SyscallResult::exit(ExitKind::ThreadExit)),
                Message::Runnable | Message::KeventsPending(_) => {}
            }
        }
    }
}

/// How the process ended, once one of its threads has ended it.
#[derive(Default)]
struct ProcessEnd {
    outcome: Mutex<Option<(Result<ExitKind>, ThreadId)>>,
    ended: Condvar,
}

/// In parallel: what starting a host thread for a guest thread takes.
#[derive(Clone)]
pub(crate) struct Runtime {
    handler: Weak<Mutex<DefaultTrapHandler>>,
    vm: Arc<SharedVm>,
    loader: Arc<Loader>,
    runner: Arc<ThreadRunner>,
    end: Arc<ProcessEnd>,
    host_threads: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Runtime {
    fn spawn(&self, name: String, body: impl FnOnce(Runtime) + Send + 'static) -> Result<()> {
        let runtime = self.clone();
        let host_thread = std::thread::Builder::new()
            .name(name)
            .spawn(move || body(runtime))
            .context("starting a host thread")?;
        lock(&self.host_threads).push(host_thread);
        Ok(())
    }

    /// Runs guest thread `id` (waiting on `mailbox`) on a new vCPU, on the calling thread.
    fn run_thread(&self, id: ThreadId, mailbox: Receiver<Message>) {
        let outcome = (|| {
            let handler = self.handler.upgrade().context("trap handler gone")?;
            let mut vm = VmManager::attach(&self.vm)?;
            let mut thread = GuestThread {
                handler: handler.clone(),
                id,
                mailbox: Some(mailbox),
            };
            let started = thread.wait(&handler, lock(&handler), &mut vm)?;
            if started.exit != ExitKind::Continue {
                return Ok(started.exit);
            }
            (self.runner)(&mut vm, &mut thread, &self.loader)
        })();
        if !matches!(outcome, Ok(ExitKind::ThreadExit)) {
            self.finish(outcome, id);
        }
    }

    /// Handles kevents arriving for the guest's workqueue and workloops, which a scheduler
    /// otherwise would.
    fn pump_kevents(&self, messages: Receiver<Message>) {
        for message in messages {
            match message {
                Message::KeventsPending(source) => {
                    let Some(handler) = self.handler.upgrade() else {
                        return;
                    };
                    let mut handler = lock(&handler);
                    if let Err(err) = handler.kevents_pending(&mut self.vm.vma(), source) {
                        warn!("delivering kevents: {err:#}");
                    }
                }
                Message::Stop => return,
                Message::Completed(..) | Message::Runnable => {}
            }
        }
    }

    /// Ends the process with `outcome` (unless it already has), which thread `id` came to, and
    /// stops every thread.
    fn finish(&self, outcome: Result<ExitKind>, id: ThreadId) {
        {
            let mut ended = lock(&self.end.outcome);
            if ended.is_none() {
                *ended = Some((outcome, id));
            }
        }
        self.end.ended.notify_all();
        if let Some(handler) = self.handler.upgrade() {
            lock(&handler).threads.stop_all();
        }
        self.vm.stop();
    }

    /// Waits for the process to end, and for all its threads to stop.
    fn wait_for_end(&self) -> (Result<ExitKind>, ThreadId) {
        let mut ended = lock(&self.end.outcome);
        while ended.is_none() {
            ended = self
                .end
                .ended
                .wait(ended)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        let outcome = ended.take().unwrap();
        drop(ended);
        // A thread being started meanwhile adds itself, so keep going until none are left.
        loop {
            let host_threads = std::mem::take(&mut *lock(&self.host_threads));
            if host_threads.is_empty() {
                break;
            }
            for host_thread in host_threads {
                let _ = host_thread.join();
            }
        }
        outcome
    }
}

/// In parallel: starts guest thread `id`'s host thread.
pub(crate) fn start_host_thread(handler: &mut DefaultTrapHandler, id: ThreadId) -> Result<()> {
    let runtime = handler
        .runtime
        .as_ref()
        .context("guest threads in parallel need DefaultTrapHandler::run")?;
    let mailbox = handler
        .threads
        .claim_mailbox(id)
        .context("new guest threads have mailboxes")?;
    runtime.spawn(format!("appbox-guest-{id}"), move |runtime| {
        runtime.run_thread(id, mailbox)
    })
}

impl DefaultTrapHandler {
    /// Runs the guest: `runner` for its main thread on `vm` (the calling thread's), and in
    /// parallel for each thread the guest starts too, on a vCPU and host thread of its own.
    /// Returns how the guest ended (e.g. [`ExitKind::Exec`], to carry on with a new image), and
    /// this handler.
    pub fn run(
        self,
        vm: &mut VmManager,
        loader: &Arc<Loader>,
        runner: &Arc<ThreadRunner>,
    ) -> Result<(ExitKind, Self)> {
        let parallel = self.threads.model() == ThreadingModel::Parallel;
        debug!("running the guest's threads {}", if parallel { "in parallel" } else { "time-shared" });
        let handler = Arc::new(Mutex::new(self));
        let (id, mailbox, runtime) = {
            let mut guard = lock(&handler);
            let id = guard.threads.current();
            let mailbox = parallel.then(|| {
                guard
                    .threads
                    .claim_mailbox(id)
                    .or_else(|| guard.threads.rebind_current_mailbox())
                    .expect("parallel threads have mailboxes")
            });
            let runtime = parallel.then(|| Runtime {
                handler: Arc::downgrade(&handler),
                vm: vm.shared().clone(),
                loader: loader.clone(),
                runner: runner.clone(),
                end: Arc::default(),
                host_threads: Arc::default(),
            });
            if let Some(runtime) = &runtime {
                let messages = guard.threads.take_messages();
                runtime.spawn("appbox-kevents".into(), move |runtime| {
                    runtime.pump_kevents(messages)
                })?;
            }
            guard.runtime = runtime.clone();
            (id, mailbox, runtime)
        };

        let mut main = GuestThread {
            handler: handler.clone(),
            id,
            mailbox,
        };
        let outcome = runner(vm, &mut main, loader);
        drop(main);
        let exit = match runtime {
            None => outcome?,
            Some(runtime) => {
                if !matches!(outcome, Ok(ExitKind::ThreadExit)) {
                    runtime.finish(outcome, id);
                }
                let (outcome, ended_by) = runtime.wait_for_end();
                let mut guard = lock(&handler);
                guard.runtime = None;
                guard.threads.set_current(ended_by);
                outcome?
            }
        };
        let handler = Arc::try_unwrap(handler)
            .map_err(|_| anyhow::anyhow!("guest threads outlived the guest"))?
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok((exit, handler))
    }
}
