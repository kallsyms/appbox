//! The guest's workqueue: libdispatch's pool of worker threads, and the kqueues whose events the
//! kernel hands to them (the process's workqueue kqueue and its workloops). All of it is emulated
//! rather than forwarded, since the host kernel would start real host threads running the host's
//! libdispatch.
//!
//! Workqueue threads are guest threads (see [`crate::threads`]) laid out and started as the
//! kernel does (see workq_setup_thread in libpthread's kern/kern_support.c).
//!
//! Each kqueue is backed by a real host kqueue for its ordinary events (fds, timers, mach ports,
//! ...), which a host watcher thread notices becoming ready. Events are then dequeued straight onto
//! a workqueue thread's stack like the kernel's `KEVENT_FLAG_STACK_DATA` delivery. Like the kernel,
//! each kqueue is serviced by at most one thread at a time, which gets any events that arrive
//! meanwhile when it returns. Everything on the workqueue kqueue goes to an event manager thread,
//! as without per-QoS kevent delivery.
//!
//! Workloops' `EVFILT_WORKLOOP` knotes (thread requests and `dispatch_sync` waiters) are
//! emulated here entirely; see filt_wl* in xnu's bsd/kern/kern_event.c. Owners and QoS overrides
//! are ignored, since only one guest thread runs at a time anyway.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::debug;

use crate::applevisor as av;
use crate::hyperpom::memory::VirtMemAllocator;
use crate::threads::{Message, Registers, ThreadId};
use crate::trap::DefaultTrapHandler;

// See bsd/pthread/workqueue_syscalls.h in xnu.
const WQOPS_THREAD_RETURN: u64 = 0x004;
const WQOPS_QUEUE_NEWSPISUPP: u64 = 0x010;
const WQOPS_QUEUE_REQTHREADS: u64 = 0x020;
const WQOPS_QUEUE_REQTHREADS2: u64 = 0x030;
const WQOPS_THREAD_KEVENT_RETURN: u64 = 0x040;
const WQOPS_SET_EVENT_MANAGER_PRIORITY: u64 = 0x080;
const WQOPS_THREAD_WORKLOOP_RETURN: u64 = 0x100;
const WQOPS_SHOULD_NARROW: u64 = 0x200;
const WQOPS_SETUP_DISPATCH: u64 = 0x400;

const WQ_FLAG_THREAD_PRIO_QOS: u32 = 0x0000_4000;
const WQ_FLAG_THREAD_OVERCOMMIT: u32 = 0x0001_0000;
const WQ_FLAG_THREAD_REUSE: u32 = 0x0002_0000;
const WQ_FLAG_THREAD_NEWSPI: u32 = 0x0004_0000;
const WQ_FLAG_THREAD_KEVENT: u32 = 0x0008_0000;
const WQ_FLAG_THREAD_EVENT_MANAGER: u32 = 0x0010_0000;
const WQ_FLAG_THREAD_TSD_BASE_SET: u32 = 0x0020_0000;
const WQ_FLAG_THREAD_WORKLOOP: u32 = 0x0040_0000;

const WQ_KEVENT_LIST_LEN: usize = 16;
const WQ_KEVENT_DATA_SIZE: u64 = 32 * 1024;

// See bsd/sys/event_private.h in xnu.
const EVFILT_WORKLOOP: i16 = -17;
pub(crate) const KEVENT_FLAG_WORKQ: u64 = 0x20;
const KEVENT_FLAG_IMMEDIATE: u32 = 0x1;
const KEVENT_FLAG_ERROR_EVENTS: u32 = 0x2;
const KEVENT_FLAG_STACK_DATA: u32 = 0x8;
const KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST: u32 = 0x02_0000;
const KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST: u32 = 0x04_0000;

const NOTE_WL_THREAD_REQUEST: u32 = 0x0000_0001;
const NOTE_WL_SYNC_WAIT: u32 = 0x0000_0004;
const NOTE_WL_SYNC_WAKE: u32 = 0x0000_0008;
const NOTE_WL_SYNC_IPC: u32 = 0x8000_0000;
const NOTE_WL_COMMANDS_MASK: u32 = 0x8000_000f;
const NOTE_WL_UPDATE_QOS: u32 = 0x0000_0010;
const NOTE_WL_END_OWNERSHIP: u32 = 0x0000_0020;
const NOTE_WL_DISCOVER_OWNER: u32 = 0x0000_0080;
const NOTE_WL_IGNORE_ESTALE: u32 = 0x0000_0100;
const NOTE_WL_UPDATES_MASK: u32 = 0x0000_01f0;

const EV_EXTIDX_WL_ADDR: usize = 1;
const EV_EXTIDX_WL_MASK: usize = 2;
const EV_EXTIDX_WL_VALUE: usize = 3;

const EV_ADD: u16 = nix::libc::EV_ADD;
const EV_DELETE: u16 = nix::libc::EV_DELETE;
const EV_ENABLE: u16 = nix::libc::EV_ENABLE;
const EV_DISABLE: u16 = nix::libc::EV_DISABLE;
const EV_CLEAR: u16 = nix::libc::EV_CLEAR;
const EV_ERROR: u16 = nix::libc::EV_ERROR;

// See bsd/pthread/priority_private.h in xnu.
const PTHREAD_PRIORITY_OVERCOMMIT_FLAG: u64 = 0x8000_0000;
const PTHREAD_PRIORITY_SCHED_PRI_FLAG: u64 = 0x2000_0000;
const PTHREAD_PRIORITY_EVENT_MANAGER_FLAG: u64 = 0x0200_0000;
const PTHREAD_PRIORITY_VALID_QOS_CLASS_MASK: u64 = 0x3f00;
const THREAD_QOS_LEGACY: u32 = 4;

// See libpthread's kern/kern_support.c.
const PAGE_SIZE: u64 = 0x4000;
const STACK_SIZE: u64 = 512 * 1024;
const PTHREAD_T_OFFSET: u64 = 12 * 1024;

/// `struct kevent_qos_s`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct KeventQos {
    ident: u64,
    filter: i16,
    flags: u16,
    qos: i32,
    udata: u64,
    fflags: u32,
    xflags: u32,
    data: i64,
    ext: [u64; 4],
}

const KEVENT_QOS_SIZE: u64 = std::mem::size_of::<KeventQos>() as u64;
const _: () = assert!(KEVENT_QOS_SIZE == 72);

impl KeventQos {
    fn error(mut self, errno: i32) -> Self {
        self.flags |= EV_ERROR;
        self.data = errno as i64;
        self
    }
}

unsafe extern "C" {
    fn kevent_qos(
        kq: i32,
        changelist: *const KeventQos,
        nchanges: i32,
        eventlist: *mut KeventQos,
        nevents: i32,
        data_out: *mut u8,
        data_available: *mut usize,
        flags: u32,
    ) -> i32;
}

fn read_kevents(vma: &VirtMemAllocator, addr: u64, count: i32) -> Result<Vec<KeventQos>> {
    let mut events = vec![KeventQos::default(); count.max(0) as usize];
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            events.as_mut_ptr() as *mut u8,
            events.len() * KEVENT_QOS_SIZE as usize,
        )
    };
    vma.read(addr, bytes)?;
    Ok(events)
}

fn write_kevent(vma: &mut VirtMemAllocator, addr: u64, event: &KeventQos) -> Result<()> {
    let bytes = unsafe {
        std::slice::from_raw_parts(event as *const KeventQos as *const u8, KEVENT_QOS_SIZE as _)
    };
    vma.write(addr, bytes)?;
    Ok(())
}

fn thread_qos(pp: u64) -> u32 {
    let classes = (pp & PTHREAD_PRIORITY_VALID_QOS_CLASS_MASK) >> 8;
    if classes == 0 {
        0
    } else {
        classes.trailing_zeros() + 1
    }
}

/// Upcall flags for a thread requested with priority `pp`, or `None` if it's invalid.
fn request_flags(pp: u64) -> Option<u32> {
    if pp & (PTHREAD_PRIORITY_SCHED_PRI_FLAG | PTHREAD_PRIORITY_EVENT_MANAGER_FLAG) != 0 {
        return None;
    }
    let qos = thread_qos(pp);
    if qos == 0 {
        return None;
    }
    let mut flags = WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_PRIO_QOS | qos;
    if pp & PTHREAD_PRIORITY_OVERCOMMIT_FLAG != 0 {
        flags |= WQ_FLAG_THREAD_OVERCOMMIT;
    }
    Some(flags)
}

/// Where things are in a workqueue thread's stack region.
struct ThreadAddrs {
    pthread: u64,
    stack_bottom: u64,
    kevent_list: u64,
    kevent_data: u64,
}

impl ThreadAddrs {
    fn new(stack_region: u64) -> Self {
        let pthread = stack_region + PAGE_SIZE + STACK_SIZE + PTHREAD_T_OFFSET;
        let kevent_list = pthread - WQ_KEVENT_LIST_LEN as u64 * KEVENT_QOS_SIZE;
        Self {
            pthread,
            stack_bottom: stack_region + PAGE_SIZE,
            kevent_list,
            kevent_data: kevent_list - WQ_KEVENT_DATA_SIZE,
        }
    }
}

fn stack_region_size(pthread_size: u32) -> u64 {
    let pthread_area = (pthread_size as u64 + PTHREAD_T_OFFSET).next_multiple_of(PAGE_SIZE);
    PAGE_SIZE + STACK_SIZE + pthread_area
}

/// A kqueue whose events go to workqueue threads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EventSource {
    Workq,
    Workloop(u64),
}

impl EventSource {
    // Workloop IDs are libdispatch queue addresses, so never 0.
    fn to_udata(self) -> usize {
        match self {
            Self::Workq => 0,
            Self::Workloop(id) => id as usize,
        }
    }

    fn from_udata(udata: usize) -> Self {
        match udata {
            0 => Self::Workq,
            id => Self::Workloop(id as u64),
        }
    }
}

fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn kevent(kq: i32, change: &nix::libc::kevent) -> std::io::Result<()> {
    let ret =
        unsafe { nix::libc::kevent(kq, change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    if ret < 0 {
        return Err(last_os_error());
    }
    Ok(())
}

fn new_kqueue() -> std::io::Result<OwnedFd> {
    let fd = unsafe { nix::libc::kqueue() };
    if fd < 0 {
        return Err(last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

const WATCHER_STOP: usize = 0;

/// A host thread telling the scheduler when the host kqueues backing the guest's have events.
/// Each kqueue is watched with `EV_DISPATCH`, so it's reported once until watched again.
struct Watcher {
    kq: Arc<OwnedFd>,
}

impl Watcher {
    fn new(messages: Sender<Message>) -> Result<Self> {
        let kq = Arc::new(new_kqueue().context("creating kqueue watcher")?);
        let stop = nix::libc::kevent {
            ident: WATCHER_STOP,
            filter: nix::libc::EVFILT_USER,
            flags: EV_ADD,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        kevent(kq.as_raw_fd(), &stop).context("adding kqueue watcher stop event")?;
        let watcher_kq = kq.clone();
        std::thread::Builder::new()
            .name("appbox-kqueue-watcher".into())
            .spawn(move || loop {
                let mut event: nix::libc::kevent = unsafe { std::mem::zeroed() };
                let ret = unsafe {
                    nix::libc::kevent(
                        watcher_kq.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        &mut event,
                        1,
                        std::ptr::null(),
                    )
                };
                if ret <= 0 {
                    continue;
                }
                if event.filter == nix::libc::EVFILT_USER {
                    break;
                }
                let source = EventSource::from_udata(event.udata as usize);
                if messages.send(Message::KeventsPending(source)).is_err() {
                    break;
                }
            })
            .context("spawning kqueue watcher")?;
        Ok(Self { kq })
    }

    /// Reports `kq` the next time it has events.
    fn watch(&self, kq: i32, source: EventSource, first: bool) -> Result<()> {
        let flags = if first { EV_ADD } else { EV_ENABLE };
        let watch = nix::libc::kevent {
            // A kqueue is readable while it has events.
            ident: kq as usize,
            filter: nix::libc::EVFILT_READ,
            flags: flags | nix::libc::EV_DISPATCH,
            fflags: 0,
            data: 0,
            udata: source.to_udata() as *mut _,
        };
        kevent(self.kq.as_raw_fd(), &watch).context("watching kqueue")?;
        Ok(())
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        let mut stop: nix::libc::kevent = unsafe { std::mem::zeroed() };
        stop.ident = WATCHER_STOP;
        stop.filter = nix::libc::EVFILT_USER;
        stop.fflags = nix::libc::NOTE_TRIGGER;
        let _ = kevent(self.kq.as_raw_fd(), &stop);
    }
}

/// A workloop's `NOTE_WL_THREAD_REQUEST` knote, which (while active) asks for a thread to
/// service the workloop.
struct ThreadRequest {
    /// The kevent delivered for it.
    event: KeventQos,
    active: bool,
}

/// A `NOTE_WL_SYNC_*` knote.
struct SyncKnote {
    fflags: u32,
    /// A thread blocked until the knote is woken, and what its syscall will return.
    waiter: Option<(ThreadId, u64)>,
}

#[derive(Default)]
struct EventQueue {
    /// Host kqueue for everything but `EVFILT_WORKLOOP` knotes, created when first needed.
    kqueue: Option<OwnedFd>,
    /// Whether the host kqueue might have events.
    host_pending: bool,
    /// The thread delivered this queue's events and not yet returned.
    servicer: Option<ThreadId>,
    thread_request: Option<ThreadRequest>,
    sync: BTreeMap<u64, SyncKnote>,
}

impl EventQueue {
    fn is_unused(&self) -> bool {
        self.kqueue.is_none()
            && self.servicer.is_none()
            && self.thread_request.is_none()
            && self.sync.is_empty()
    }
}

#[derive(Default)]
pub(crate) struct Workqueue {
    /// Every workqueue thread's stack region.
    stacks: Vec<(ThreadId, u64)>,
    /// Workqueue threads waiting for work, most recently parked last.
    idle: Vec<ThreadId>,
    /// Threads bound to service a kqueue, whose events are dequeued when they get on the vCPU.
    deliveries: BTreeMap<ThreadId, Delivery>,
    /// Idle threads that were parked again before ever running.
    unstarted: BTreeSet<ThreadId>,
    watcher: Option<Watcher>,
    queues: BTreeMap<EventSource, EventQueue>,
}

impl Workqueue {
    fn stack(&self, id: ThreadId) -> Option<u64> {
        self.stacks
            .iter()
            .find_map(|&(thread, stack)| (thread == id).then_some(stack))
    }

    /// Whether events could still arrive to wake a parked workqueue thread.
    pub(crate) fn has_event_sources(&self) -> bool {
        self.queues.values().any(|queue| queue.kqueue.is_some())
    }

    fn serviced_by(&self, id: ThreadId) -> Option<EventSource> {
        self.queues
            .iter()
            .find_map(|(&source, queue)| (queue.servicer == Some(id)).then_some(source))
    }
}

pub(crate) enum WorkqReturn {
    Done(std::result::Result<u64, i32>),
    /// The current thread left the vCPU (parked or blocked), so another must be scheduled.
    Descheduled,
}

/// The outcome of registering one `EVFILT_WORKLOOP` change.
enum Registered {
    Done,
    Error(i32),
    /// The caller must block until the sync knote `ident` is woken.
    Wait(u64),
}

/// Events due to a thread bound to service `source`.
struct Delivery {
    source: EventSource,
    /// Changes its last servicer handed back that failed.
    errors: Vec<KeventQos>,
}

impl DefaultTrapHandler {
    fn watcher(&mut self) -> Result<&Watcher> {
        if self.workq.watcher.is_none() {
            self.workq.watcher = Some(Watcher::new(self.threads.message_sender())?);
        }
        Ok(self.workq.watcher.as_ref().unwrap())
    }

    /// The host kqueue backing `source`'s ordinary events.
    fn host_kqueue(&mut self, source: EventSource) -> Result<i32> {
        if let Some(kq) = self.workq.queues.get(&source).and_then(|q| q.kqueue.as_ref()) {
            return Ok(kq.as_raw_fd());
        }
        let kq = new_kqueue().context("creating host kqueue")?;
        self.watcher()?.watch(kq.as_raw_fd(), source, true)?;
        let fd = kq.as_raw_fd();
        self.workq.queues.entry(source).or_default().kqueue = Some(kq);
        Ok(fd)
    }

    /// The host kqueue backing the guest's workqueue kqueue.
    pub(crate) fn workq_kqueue(&mut self) -> Result<i32> {
        self.host_kqueue(EventSource::Workq)
    }

    /// Handles the watcher reporting that `source`'s host kqueue has events.
    pub(crate) fn kevents_pending(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &mut VirtMemAllocator,
        source: EventSource,
    ) -> Result<()> {
        let Some(queue) = self.workq.queues.get_mut(&source) else {
            return Ok(());
        };
        queue.host_pending = true;
        self.service(vcpu, vma, source, Vec::new())
    }

    /// `__workq_kernreturn(options, item, arg2, arg3)`.
    pub(crate) fn workq_kernreturn(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &mut VirtMemAllocator,
        args: &[u64; 16],
    ) -> Result<WorkqReturn> {
        let (options, item, count, priority) = (args[0], args[1], args[2] as i32, args[3]);
        if self.pthread.is_none() {
            return Ok(WorkqReturn::Done(Err(nix::libc::EINVAL)));
        }
        let current = self.threads.current();
        let is_workq_thread = self.workq.stack(current).is_some();
        let serviced = self.workq.serviced_by(current);
        Ok(WorkqReturn::Done(match options {
            WQOPS_QUEUE_NEWSPISUPP | WQOPS_SETUP_DISPATCH | WQOPS_SET_EVENT_MANAGER_PRIORITY => {
                Ok(0)
            }
            // Only one thread runs at a time anyway.
            WQOPS_SHOULD_NARROW => Ok(0),
            WQOPS_QUEUE_REQTHREADS | WQOPS_QUEUE_REQTHREADS2 => {
                match (request_flags(priority), count) {
                    (Some(flags), 1..) => {
                        for _ in 0..count {
                            let (reused, stack) = self.workq_thread_stack(vma)?;
                            self.start_workq_thread(vcpu, vma, reused, stack, flags)?;
                        }
                        Ok(0)
                    }
                    _ => Err(nix::libc::EINVAL),
                }
            }
            WQOPS_THREAD_RETURN if is_workq_thread && serviced.is_none() => {
                self.park_workq_thread();
                return Ok(WorkqReturn::Descheduled);
            }
            WQOPS_THREAD_KEVENT_RETURN if serviced == Some(EventSource::Workq) => {
                self.return_from_events(vcpu, vma, EventSource::Workq, item, count)?;
                return Ok(WorkqReturn::Descheduled);
            }
            WQOPS_THREAD_WORKLOOP_RETURN
                if matches!(serviced, Some(EventSource::Workloop(_))) =>
            {
                self.return_from_events(vcpu, vma, serviced.unwrap(), item, count)?;
                return Ok(WorkqReturn::Descheduled);
            }
            _ => Err(nix::libc::EINVAL),
        }))
    }

    fn park_workq_thread(&mut self) {
        let id = self.threads.current();
        self.threads.park_current();
        self.workq.idle.push(id);
    }

    /// The current thread is done with `source`'s events: applies the changes it hands back,
    /// then parks it, to be given more events straight away if there are any.
    fn return_from_events(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &mut VirtMemAllocator,
        source: EventSource,
        changes: u64,
        count: i32,
    ) -> Result<()> {
        let changes = if changes == 0 {
            Vec::new()
        } else {
            read_kevents(vma, changes, count)?
        };
        // Failed changes go back to the thread as events, like the kernel does.
        let mut errors = Vec::new();
        for mut change in changes {
            let result = match source {
                EventSource::Workloop(id) if change.filter == EVFILT_WORKLOOP => {
                    match self.register_workloop_change(id, &mut change, vma)? {
                        Registered::Done => None,
                        Registered::Error(errno) => Some(errno),
                        Registered::Wait(_) => Some(nix::libc::EINVAL),
                    }
                }
                _ => self.register_host_change(source, change)?,
            };
            if let Some(errno) = result {
                errors.push(change.error(errno));
            }
        }
        let queue = self.workq.queues.get_mut(&source).expect("serviced queue");
        queue.servicer = None;
        queue.host_pending = queue.kqueue.is_some();
        self.park_workq_thread();
        self.service(vcpu, vma, source, errors)
    }

    /// Registers an ordinary (not `EVFILT_WORKLOOP`) change on `source`'s host kqueue, returning
    /// the error it failed with, if any.
    fn register_host_change(
        &mut self,
        source: EventSource,
        change: KeventQos,
    ) -> Result<Option<i32>> {
        let kq = self.host_kqueue(source)?;
        let mut result = KeventQos::default();
        let failed = unsafe {
            kevent_qos(
                kq,
                &change,
                1,
                &mut result,
                1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS,
            )
        };
        Ok(match failed {
            0 => None,
            1 => Some(result.data as i32),
            _ => Some(last_os_error().raw_os_error().unwrap_or(nix::libc::EINVAL)),
        })
    }

    /// Binds a workqueue thread to service `source`'s events (and `errors` from its last
    /// servicer's changes), if there are any and it isn't already being serviced. Like the
    /// kernel, the events are only dequeued when the thread gets to run (see
    /// [`Self::deliver_kevents`]): by then, other threads may have dealt with some of them.
    fn service(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &mut VirtMemAllocator,
        source: EventSource,
        errors: Vec<KeventQos>,
    ) -> Result<()> {
        let Some(queue) = self.workq.queues.get_mut(&source) else {
            return Ok(());
        };
        let thread_request_active = queue.thread_request.as_ref().is_some_and(|tr| tr.active);
        if queue.servicer.is_some()
            || (errors.is_empty() && !thread_request_active && !queue.host_pending)
        {
            if queue.is_unused() {
                self.workq.queues.remove(&source);
            }
            return Ok(());
        }

        let (reused, stack) = self.workq_thread_stack(vma)?;
        let flags = WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_KEVENT;
        let id = self.start_workq_thread(vcpu, vma, reused, stack, flags)?;
        self.workq.queues.get_mut(&source).unwrap().servicer = Some(id);
        self.workq.deliveries.insert(id, Delivery { source, errors });
        debug!("{source:?}: bound thread {id}");
        Ok(())
    }

    /// Dequeues the events due to thread `id`, which was just switched to, onto its stack.
    /// Returns false if there were none any more, in which case the thread is parked again.
    pub(crate) fn deliver_kevents(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &mut VirtMemAllocator,
        id: ThreadId,
    ) -> Result<bool> {
        let Some(Delivery { source, errors: mut events }) = self.workq.deliveries.remove(&id) else {
            return Ok(true);
        };
        let addrs = ThreadAddrs::new(self.workq.stack(id).expect("workqueue thread"));
        let queue = self.workq.queues.get_mut(&source).expect("serviced queue");
        let mut data_available = WQ_KEVENT_DATA_SIZE as usize;
        let mut flags = WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_KEVENT;
        match source {
            EventSource::Workq => flags |= WQ_FLAG_THREAD_EVENT_MANAGER,
            EventSource::Workloop(id) => {
                // The workloop's ID goes just above its events.
                data_available -= 8;
                vma.write_qword(addrs.kevent_list - 8, id)?;
                let pp = queue
                    .thread_request
                    .as_ref()
                    .map_or(0, |tr| tr.event.qos as u32 as u64);
                let qos = match thread_qos(pp) {
                    0 => THREAD_QOS_LEGACY,
                    qos => qos,
                };
                flags |= WQ_FLAG_THREAD_WORKLOOP | WQ_FLAG_THREAD_PRIO_QOS | qos;
                if pp & PTHREAD_PRIORITY_OVERCOMMIT_FLAG != 0 {
                    flags |= WQ_FLAG_THREAD_OVERCOMMIT;
                }
            }
        }
        events.truncate(WQ_KEVENT_LIST_LEN);
        if let Some(tr) = queue.thread_request.as_mut().filter(|tr| tr.active) {
            if events.len() < WQ_KEVENT_LIST_LEN {
                // Delivering it consumes it (it's EV_CLEAR).
                tr.active = false;
                events.push(tr.event);
            }
        }
        for (i, event) in events.iter().enumerate() {
            write_kevent(vma, addrs.kevent_list + i as u64 * KEVENT_QOS_SIZE, event)?;
        }
        let mut count = events.len();
        if queue.host_pending && count < WQ_KEVENT_LIST_LEN {
            let kq = queue.kqueue.as_ref().expect("pending host kqueue").as_raw_fd();
            let dequeued = unsafe {
                kevent_qos(
                    kq,
                    std::ptr::null(),
                    0,
                    (addrs.kevent_list + count as u64 * KEVENT_QOS_SIZE) as *mut KeventQos,
                    (WQ_KEVENT_LIST_LEN - count) as i32,
                    addrs.kevent_data as *mut u8,
                    &mut data_available,
                    KEVENT_FLAG_STACK_DATA | KEVENT_FLAG_IMMEDIATE,
                )
            };
            if dequeued < 0 {
                return Err(last_os_error()).context("dequeuing kevents");
            }
            count += dequeued as usize;
            queue.host_pending = false;
            self.watcher()?.watch(kq, source, false)?;
        }

        let started_flags = vcpu.get_reg(av::Reg::X4)? as u32;
        if count == 0 {
            debug!("{source:?}: nothing left for thread {id}");
            let queue = self.workq.queues.get_mut(&source).unwrap();
            queue.servicer = None;
            if queue.is_unused() {
                self.workq.queues.remove(&source);
            }
            self.park_workq_thread();
            if started_flags & WQ_FLAG_THREAD_TSD_BASE_SET != 0 {
                self.workq.unstarted.insert(id);
            }
            return Ok(false);
        }

        let data_start = addrs.kevent_data + data_available as u64;
        self.note_guest_write(
            data_start,
            addrs.kevent_list + count as u64 * KEVENT_QOS_SIZE - data_start,
        );
        let first_use = started_flags & (WQ_FLAG_THREAD_REUSE | WQ_FLAG_THREAD_TSD_BASE_SET);
        vcpu.set_reg(av::Reg::X3, addrs.kevent_list)?;
        vcpu.set_reg(av::Reg::X4, (flags | first_use) as u64)?;
        vcpu.set_reg(av::Reg::X5, count as u64)?;
        vcpu.set_sys_reg(av::SysReg::SP_EL0, data_start & !15)?;
        debug!("{source:?}: delivered {count} kevents to thread {id}");
        Ok(true)
    }

    /// The thread to start next: the most recently parked idle one (with its stack), or a new
    /// one's stack.
    fn workq_thread_stack(&mut self, vma: &mut VirtMemAllocator) -> Result<(Option<ThreadId>, u64)> {
        if let Some(&id) = self.workq.idle.last() {
            return Ok((Some(id), self.workq.stack(id).expect("workqueue thread")));
        }
        let registration = self.pthread.context("workqueue before pthread registration")?;
        let size = stack_region_size(registration.pthread_size);
        Ok((None, self.allocate_guest_memory(vma, size)?))
    }

    /// Makes workqueue thread `reused` (the last idle one), or a new one on `stack`, runnable
    /// with upcall `flags` (and no kevents, which [`Self::deliver_kevents`] adds).
    fn start_workq_thread(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &mut VirtMemAllocator,
        reused: Option<ThreadId>,
        stack: u64,
        flags: u32,
    ) -> Result<ThreadId> {
        let registration = self.pthread.context("workqueue before pthread registration")?;
        let addrs = ThreadAddrs::new(stack);
        let first_use = reused.is_none_or(|id| self.workq.unstarted.remove(&id));
        let flags = flags
            | if first_use {
                WQ_FLAG_THREAD_TSD_BASE_SET
            } else {
                WQ_FLAG_THREAD_REUSE
            };
        let template = Registers::save_at_syscall(vcpu)?;
        let tsd = addrs.pthread + registration.tsd_offset as u64;
        let regs = |port: u32| {
            let mut regs = Registers {
                pc: registration.wq_thread,
                sp: addrs.pthread & !15,
                // The EL0 mode the other threads run in, without condition flags.
                cpsr: template.cpsr & !(0b1111 << 28),
                fpcr: template.fpcr,
                tpidrro: tsd,
                ..Default::default()
            };
            regs.x[..6].copy_from_slice(&[
                addrs.pthread,
                port as u64,
                addrs.stack_bottom,
                0,
                flags as u64,
                0,
            ]);
            regs
        };

        match reused {
            Some(id) => {
                debug_assert_eq!(self.workq.idle.last(), Some(&id));
                self.workq.idle.pop();
                let regs = regs(self.threads.port(id));
                self.threads.unpark(id, regs);
                Ok(id)
            }
            None => {
                let id = self.threads.spawn(regs)?;
                if registration.mach_thread_self_offset != 0 {
                    let port = self.threads.port(id) as u64;
                    let addr = tsd + registration.mach_thread_self_offset as u64;
                    vma.write_qword(addr, port)?;
                    self.note_guest_write(addr, 8);
                }
                self.workq.stacks.push((id, stack));
                debug!("created workqueue thread {id} (flags {flags:#x})");
                Ok(id)
            }
        }
    }

    /// `kevent_id(id, changelist, nchanges, eventlist, nevents, data_out, data_available,
    /// flags)`: changes to workloop `id`, and (only for the thread servicing it) its events.
    pub(crate) fn kevent_id(
        &mut self,
        vcpu: &av::Vcpu,
        vma: &mut VirtMemAllocator,
        args: &[u64; 16],
    ) -> Result<WorkqReturn> {
        let (id, changelist, nchanges, eventlist, nevents, data_out, data_available, flags) = (
            args[0],
            args[1],
            args[2] as i32,
            args[3],
            args[4] as i32,
            args[5],
            args[6],
            args[7] as u32,
        );
        let source = EventSource::Workloop(id);
        let exists = self.workq.queues.contains_key(&source);
        if id == 0 {
            return Ok(WorkqReturn::Done(Err(nix::libc::EINVAL)));
        }
        if flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST != 0 && !exists {
            return Ok(WorkqReturn::Done(Err(nix::libc::ENOENT)));
        }
        if flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST != 0 && exists {
            return Ok(WorkqReturn::Done(Err(nix::libc::EEXIST)));
        }
        self.workq.queues.entry(source).or_default();
        let error_events = flags & KEVENT_FLAG_ERROR_EVENTS != 0;

        let mut errors = 0;
        let mut wait = None;
        let changes = read_kevents(vma, changelist, nchanges)?;
        let last = changes.len().saturating_sub(1);
        for (i, mut change) in changes.into_iter().enumerate() {
            let result = if change.filter == EVFILT_WORKLOOP {
                match self.register_workloop_change(id, &mut change, vma)? {
                    Registered::Done => None,
                    Registered::Error(errno) => Some(errno),
                    // Like the kernel, only supported as the last change, with room for errors.
                    Registered::Wait(ident) if i == last && error_events && errors < nevents => {
                        wait = Some(ident);
                        break;
                    }
                    Registered::Wait(_) => Some(nix::libc::ENOTSUP),
                }
            } else {
                self.register_host_change(source, change)?
            };
            if let Some(errno) = result {
                if errors >= nevents {
                    return Ok(WorkqReturn::Done(Err(errno)));
                }
                let event = change.error(errno);
                let addr = eventlist + errors as u64 * KEVENT_QOS_SIZE;
                write_kevent(vma, addr, &event)?;
                self.note_guest_write(addr, KEVENT_QOS_SIZE);
                errors += 1;
            }
        }

        if let Some(ident) = wait {
            let waiter = self.threads.current();
            let knote = self.workloop_sync_knote(id, ident);
            knote.waiter = Some((waiter, errors as u64));
            self.threads.block_current(vcpu)?;
            self.service(vcpu, vma, source, Vec::new())?;
            return Ok(WorkqReturn::Descheduled);
        }

        let mut received = errors as u64;
        let servicer = self.workq.queues[&source].servicer;
        if !error_events && nevents > 0 && errors == 0 && servicer == Some(self.threads.current()) {
            // Waiting for events isn't supported; they're always polled.
            received = self.poll_workloop(source, eventlist, nevents, data_out, data_available, flags, vma)?;
        }
        self.service(vcpu, vma, source, Vec::new())?;
        Ok(WorkqReturn::Done(Ok(received)))
    }

    /// Dequeues workloop events for its servicer, as the kernel's kqueue_scan.
    #[allow(clippy::too_many_arguments)]
    fn poll_workloop(
        &mut self,
        source: EventSource,
        eventlist: u64,
        nevents: i32,
        data_out: u64,
        data_available: u64,
        flags: u32,
        vma: &mut VirtMemAllocator,
    ) -> Result<u64> {
        let data_size = if data_out != 0 && data_available != 0 {
            vma.read_qword(data_available)?
        } else {
            0
        };
        let queue = self.workq.queues.get_mut(&source).unwrap();
        let mut count = 0;
        if let Some(tr) = queue.thread_request.as_mut().filter(|tr| tr.active) {
            tr.active = false;
            write_kevent(vma, eventlist, &tr.event)?;
            count += 1;
        }
        if let Some(kq) = &queue.kqueue {
            let dequeued = unsafe {
                kevent_qos(
                    kq.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    (eventlist + count * KEVENT_QOS_SIZE) as *mut KeventQos,
                    nevents - count as i32,
                    data_out as *mut u8,
                    data_available as *mut usize,
                    (flags & KEVENT_FLAG_STACK_DATA) | KEVENT_FLAG_IMMEDIATE,
                )
            };
            if dequeued < 0 {
                return Err(last_os_error()).context("polling workloop kevents");
            }
            count += dequeued as u64;
        }
        self.note_guest_write(eventlist, count * KEVENT_QOS_SIZE);
        self.note_guest_write(data_out, data_size);
        if data_size != 0 {
            self.note_guest_write(data_available, 8);
        }
        Ok(count)
    }

    fn workloop_sync_knote(&mut self, id: u64, ident: u64) -> &mut SyncKnote {
        let queue = self.workq.queues.get_mut(&EventSource::Workloop(id)).unwrap();
        queue.sync.get_mut(&ident).expect("sync knote")
    }

    /// Registers an `EVFILT_WORKLOOP` change on workloop `id`, as kevent_register and filt_wl*
    /// would.
    fn register_workloop_change(
        &mut self,
        id: u64,
        kev: &mut KeventQos,
        vma: &VirtMemAllocator,
    ) -> Result<Registered> {
        let requested_flags = kev.flags;
        if kev.flags & EV_DELETE != 0 {
            kev.flags &= !EV_ADD;
        }
        if kev.flags & EV_DISABLE != 0 {
            kev.flags &= !EV_ENABLE;
        }
        let command = kev.fflags & NOTE_WL_COMMANDS_MASK;
        let queue = self
            .workq
            .queues
            .entry(EventSource::Workloop(id))
            .or_default();
        let is_thread_request = kev.ident == id;
        let exists = if is_thread_request {
            queue.thread_request.is_some()
        } else {
            queue.sync.contains_key(&kev.ident)
        };

        // The debounce check: the value at ext[ADDR] must still match (under ext[MASK]).
        let addr = kev.ext[EV_EXTIDX_WL_ADDR];
        let stale = if addr != 0 {
            let current = vma.read_qword(addr)?;
            let mask = kev.ext[EV_EXTIDX_WL_MASK];
            let stale = current & mask != kev.ext[EV_EXTIDX_WL_VALUE] & mask;
            kev.ext[EV_EXTIDX_WL_VALUE] = current;
            stale
        } else {
            false
        };
        let ignore_stale = kev.fflags & NOTE_WL_IGNORE_ESTALE != 0;

        if !exists && kev.flags & EV_ADD == 0 {
            if requested_flags & EV_ADD != 0 && requested_flags & EV_DELETE != 0 {
                return Ok(Registered::Done);
            }
            return Ok(Registered::Error(nix::libc::ENOENT));
        }

        if !exists {
            // filt_wlattach
            match command {
                NOTE_WL_THREAD_REQUEST => {
                    if !is_thread_request {
                        return Ok(Registered::Error(nix::libc::EINVAL));
                    }
                    if thread_qos(kev.qos as u32 as u64) == 0 {
                        return Ok(Registered::Error(nix::libc::ERANGE));
                    }
                }
                NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE | NOTE_WL_SYNC_IPC => {
                    if is_thread_request || kev.flags & EV_DISABLE == 0 {
                        return Ok(Registered::Error(nix::libc::EINVAL));
                    }
                    let invalid = match command {
                        NOTE_WL_SYNC_IPC => NOTE_WL_UPDATE_QOS | NOTE_WL_DISCOVER_OWNER,
                        _ => NOTE_WL_END_OWNERSHIP,
                    };
                    if kev.fflags & invalid != 0 {
                        return Ok(Registered::Error(nix::libc::EINVAL));
                    }
                }
                _ => return Ok(Registered::Error(nix::libc::EINVAL)),
            }
            if stale {
                return Ok(if ignore_stale {
                    Registered::Done
                } else {
                    Registered::Error(nix::libc::ESTALE)
                });
            }
            if is_thread_request {
                kev.flags |= EV_CLEAR;
                queue.thread_request = Some(ThreadRequest {
                    event: *kev,
                    active: true,
                });
                return Ok(Registered::Done);
            }
            queue.sync.insert(
                kev.ident,
                SyncKnote {
                    fflags: kev.fflags,
                    waiter: None,
                },
            );
            return Ok(if command == NOTE_WL_SYNC_WAIT {
                Registered::Wait(kev.ident)
            } else {
                Registered::Done
            });
        }

        // filt_wlvalidate_kev_flags
        let saved_command = if is_thread_request {
            NOTE_WL_THREAD_REQUEST
        } else {
            queue.sync[&kev.ident].fflags & NOTE_WL_COMMANDS_MASK
        };
        let deleting = kev.flags & EV_DELETE != 0;
        let invalid = (kev.fflags & NOTE_WL_DISCOVER_OWNER != 0 && deleting)
            || (kev.fflags & NOTE_WL_UPDATE_QOS != 0
                && (deleting || saved_command != NOTE_WL_THREAD_REQUEST))
            || match command {
                NOTE_WL_THREAD_REQUEST => saved_command != NOTE_WL_THREAD_REQUEST,
                NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE => {
                    (command == NOTE_WL_SYNC_WAIT && kev.fflags & NOTE_WL_END_OWNERSHIP != 0)
                        || saved_command & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE) == 0
                        || kev.flags & (EV_ENABLE | EV_DELETE) == EV_ENABLE
                }
                NOTE_WL_SYNC_IPC => {
                    saved_command != NOTE_WL_SYNC_IPC
                        || kev.flags & (EV_ENABLE | EV_DELETE) == EV_ENABLE
                }
                _ => true,
            };
        if invalid {
            return Ok(Registered::Error(nix::libc::EINVAL));
        }
        if stale {
            return Ok(if ignore_stale {
                Registered::Done
            } else {
                Registered::Error(nix::libc::ESTALE)
            });
        }

        if deleting {
            // filt_wlallow_drop, then knote_drop
            if is_thread_request {
                queue.thread_request = None;
            } else {
                let knote = queue.sync.remove(&kev.ident).unwrap();
                // Deleting a waiter nobody woke wakes it.
                if knote.fflags & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE) == NOTE_WL_SYNC_WAIT {
                    if let Some((waiter, ret)) = knote.waiter {
                        self.threads.wake(waiter, (ret, 0, 0));
                    }
                }
            }
            return Ok(Registered::Done);
        }

        // filt_wltouch
        if is_thread_request {
            let tr = queue.thread_request.as_mut().unwrap();
            let fflags = (tr.event.fflags & !NOTE_WL_UPDATES_MASK) | kev.fflags;
            tr.event = KeventQos {
                flags: tr.event.flags,
                fflags,
                qos: if kev.fflags & NOTE_WL_UPDATE_QOS != 0 {
                    kev.qos
                } else {
                    tr.event.qos
                },
                ..*kev
            };
            tr.active = true;
            return Ok(Registered::Done);
        }
        let knote = queue.sync.get_mut(&kev.ident).unwrap();
        knote.fflags = (knote.fflags & !NOTE_WL_UPDATES_MASK) | kev.fflags;
        if kev.fflags & NOTE_WL_SYNC_WAKE != 0 {
            if let Some((waiter, ret)) = knote.waiter.take() {
                self.threads.wake(waiter, (ret, 0, 0));
            }
        }
        if command == NOTE_WL_SYNC_WAIT && knote.fflags & NOTE_WL_SYNC_WAKE == 0 {
            return Ok(Registered::Wait(kev.ident));
        }
        Ok(Registered::Done)
    }

    /// Forgets the workqueue, as exec does. Its threads' stacks are guest memory, released with
    /// the rest.
    pub(crate) fn reset_workq(&mut self) {
        self.workq = Workqueue::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_flags_encode_qos_and_overcommit() {
        // QOS_CLASS_DEFAULT (thread QoS 4) is bit 3 of the class field.
        let default = 1 << (8 + 3);
        assert_eq!(
            request_flags(default),
            Some(WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_PRIO_QOS | 4)
        );
        assert_eq!(
            request_flags(default | PTHREAD_PRIORITY_OVERCOMMIT_FLAG),
            Some(WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_PRIO_QOS | 4 | WQ_FLAG_THREAD_OVERCOMMIT)
        );
        assert_eq!(request_flags(0), None);
        assert_eq!(
            request_flags(default | PTHREAD_PRIORITY_EVENT_MANAGER_FLAG),
            None
        );
    }

    #[test]
    fn stack_region_matches_the_kernel() {
        // A 16K pthread_t: guard page, 512K stack, then 12K + 16K rounded up to 32K.
        assert_eq!(stack_region_size(0x4000), 0x4000 + 0x80000 + 0x8000);
        let addrs = ThreadAddrs::new(0x1_0000_0000);
        assert_eq!(addrs.stack_bottom, 0x1_0000_4000);
        assert_eq!(addrs.pthread, 0x1_0000_4000 + 0x80000 + 0x3000);
        assert_eq!(addrs.kevent_list, addrs.pthread - 16 * 72);
        assert_eq!(addrs.kevent_data, addrs.kevent_list - 0x8000);
    }
}
