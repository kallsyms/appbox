# Tricks

The non-obvious things AppBox (and warpspeed, on top of it) does to run macOS binaries in a VM
and replay them. Most of them work around a kernel panic, a missing hardware feature, or macOS
assuming it owns the process. The commit messages have the details.

## Memory

### 1:1 mapping

Guest virtual addresses are mapped to the same host virtual addresses, so a syscall's pointers
work unchanged when forwarded to the host kernel. That means every address the guest expects to
be free must also be free in the host process, and most of the tricks below follow from that.

### Lazy private copies instead of mapping file pages (avoiding an SPTM panic)

Passing `hv_vm_map` a page that SPTM has typed `XNU_USER_EXEC` panics the kernel
(`VIOLATION_ILLEGAL_MAPPING_TYPE`). Plenty of ordinary memory is typed that way. Unwritten pages
of a private file mapping share physical pages with every other mapping of the file. So if any
process maps a dylib or the shared cache executable, our copy of those pages is "executable"
too. So:

- Host mappings made for the guest never have `PROT_EXEC`. The host never executes guest code,
  and the VM maps everything RWX regardless of host protections.
- Guest private file mappings are mapped into the VM lazily (`map_1to1_lazy`). On a stage-2
  fault, appbox writes to each page of the faulting 1 MiB chunk, which forces a private copy, and
  only then `hv_vm_map`s the chunk.
- The shared cache is mapped from appbox's own copy of its files instead (see below). Nothing
  ever maps that copy executable, so its pages go into the VM as they are.
- Read-only *shared* file mappings are mapped privately instead, because `hv_vm_map` refuses
  some of them (e.g. ICU's data file, which broke `sw_vers`).

### Walking the dyld shared cache ourselves

The kernel's shared region can't be mapped into a VM, so `dyld.rs` maps the cache files
itself: it reserves the region, maps each subcache's mappings, and applies the slide info.
`shared_region_check_np` then returns our copy's address. See Apple's `dsc_extractor.cpp`
when a new cache or slide format shows up.

It maps a private copy of the files, not the system's own in the OS cryptex, so the text pages
are clean file pages rather than the host's executable ones:
- The kernel can page them in and out.
- Concurrent appbox processes share them.
- No per-page copying is needed to dodge the SPTM panic above.

The copy lives in `~/Library/Caches/appbox/dyld/<cache UUID>/` (or `$APPBOX_SHARED_CACHE_DIR`).
It's about 2.3 GB, and a full copy, since APFS can't clone across volumes and the cryptex is on
the Preboot volume. It's made on first use, and again whenever the system cache's UUID changes.
If it can't be made, appbox falls back to mapping the system's files lazily, with the copying
described above.

### Pinning the host's malloc so the guest's xzone heap fits

macOS 27's xzone malloc reserves 24 GiB at a fixed address, chosen from `malloc_entropy[1]`
within `[0x71_8000_0000, 0x80_0000_0000)`, and aborts if it can't get it. The host's own libmalloc
does the same in the same window, so guest and host (sharing one address space) usually
collided, and only about 20% of processes had room for both.

- `respawn()` re-runs the host program suspended, with ASLR disabled. Through `task_for_pid` it
  overwrites the child's `malloc_entropy` string on its stack, so the *host's* heap lands at the
  top of the window, and then resumes it. This needs the `cs.debugger` and `get-task-allow`
  entitlements.
- Before loading the guest, appbox reserves a free candidate at the bottom of the window. It
  then hands the guest an `apple[]` `malloc_entropy` that selects that candidate. When the
  guest maps its heap there, it's allowed to overwrite the placeholder, exactly once.
- As a bonus, the host's layout is deterministic, which record/replay needs.

### Other address-space squatting

- **Fixed mapping pool:** guest `mmap`s without a fixed address are placed from a pool appbox
  reserves at `0x80_0000_0000`, above the range macOS 27 reserves in every process
  (`0x1_8000_0000..~0x70_0000_0000`). That keeps them away from the host's allocations and makes
  them deterministic for replay.
- **Real `mach_vm_map` semantics:** `mach_vm_map` goes through the host's `mach_vm_map`, not
  `mmap(MAP_FIXED)`. A fixed mapping without `VM_FLAGS_OVERWRITE` must fail rather than land on
  top of, say, hyperpom's page tables.
- **Real unmaps:** `munmap` and `mach_vm_deallocate` really unmap. The guest often unmaps and
  then maps fixed over the same range, e.g. dyld putting a guard range over its own original
  image. Rust `MemoryMap`s overlapping an unmapped range are leaked, so dropping them can't
  unmap whatever is there later.
- **Recycled guest-physical space:** 1:1 ranges get guest-physical (IPA) space from a free
  list, and mapping over an existing 1:1 range retires the old pages first. The VM's default
  IPA space is only 64 GiB, which a replay remapping the 24 GiB heap a few times exhausts.

### Host descriptors out of the guest's way

Guest and host share one fd table, and guest fds are forwarded by number. So appbox's own
descriptors live elsewhere:
- The GDB stub's sockets are at or above 1000, with no mio `Poll`, whose kqueue took a low fd.
- Descriptors stashed for checkpoints are at or above 4096.

Close-on-exec only closes descriptors that belong to the guest: those inherited without
`FD_CLOEXEC`, plus those its syscalls created.

## Processes and threads

### exec and spawn never touch the host process

Execing a process with a live vCPU panics the kernel (a NULL VM dereference in
`hv_vcpu_destroy`). So:
- `execve` and `posix_spawn(POSIX_SPAWN_SETEXEC)` are done inside the VM (`appbox::exec`). Only
  one VM can exist per process, so this means dropping the old VM, loading the new image into a
  fresh one, and applying close-on-exec.
- A guest `posix_spawn` of a new process starts another pinned copy of the *host* program. That
  copy runs the requested guest (`APPBOX_SPAWN_REQUEST`), and the guest gets the real pid.
- `fork` and `vfork` are refused.

### Emulated sigaction

Forwarding `sigaction` would install guest code addresses as host signal handlers. The guest's
actions are kept in the trap handler instead, and only `SIG_DFL`/`SIG_IGN` reach the host.

### Guest threads time-share one vCPU

There's one vCPU, and guest pthreads take turns on it. `bsdthread_create` and friends are
emulated. A thread's EL0 state (GPRs, SIMD/FP, SP, PC/PSTATE, TPIDR/TPIDRRO) is saved and
restored when switching. Threads switch when one blocks, yields or exits, or when its time slice
ends (see below).

### Or a vCPU each, in parallel (opt-in)

`DefaultTrapHandler::new(ThreadingModel::Parallel)` gives each guest thread a vCPU of its own, on
a host thread of its own, so threads really run at once. The cost is determinism: no
record/replay and no checkpoints. Processes a guest spawns get the same model whatever their
embedder asks for: it's passed down in their environment (`APPBOX_THREADING`). An exec keeps the
handler, and so the model.

The two models share nearly all their code:
- The thread states and transitions in `Threads` are the same. A thread becoming runnable
  (woken, unparked, created, or its syscall done) just also nudges that thread's mailbox, where
  its host thread waits whenever it can't run. The host thread then takes the thread's registers
  and does the same switch-in work the time-shared scheduler would (delivering kevents, finishing
  a blocked syscall's bookkeeping).
- The trap handler is shared behind a mutex. `handle_syscall` releases it while a thread waits.
- Syscall proxies stay. A syscall that can block goes to the thread's proxy, which replies to the
  thread's mailbox; one that can't runs directly on the caller.
- A small pump thread handles workqueue kevents, since no scheduler polls for them.

The embedder writes one loop for a guest thread's vCPU (a `ThreadRunner`), and
`DefaultTrapHandler::run` runs it for every thread. `SharedVm::stop` kicks all the vCPUs out when
one thread ends the process.

Two things surfaced that time-sharing had hidden:
- Every vCPU needs the same system registers. `TCR_EL1.TBI0` (without which libobjc crashes) used
  to be set on the first vCPU only, by the loader.
- Stale stage-1 TLB entries need an inner-shareable invalidation after page tables change.

### Proxy threads for syscalls

Each guest thread has a host proxy thread that runs its forwarded syscalls. The kernel then
sees one thread per guest thread, with the right thread port, ulock ownership, signal mask and
QoS. A forwarded syscall that hasn't returned after 1 ms, while another guest thread could run,
blocks its guest thread instead of the vCPU. Its result is written into the thread's saved
registers when the proxy returns. Syscalls that map or unmap memory never switch threads, since
the VM has to be updated right after them.

### libdispatch without kernel workqueues

The kernel's workqueue would start real host threads running the host's libdispatch, so
`workq_open`/`workq_kernreturn` are refused. Workqueue threads, the workqueue kqueue and
workloops (`kevent_id`, `EVFILT_WORKLOOP`) are emulated instead:
- Ordinary events come from host kqueues, which a watcher thread monitors.
- Thread requests and `dispatch_sync` waiters are emulated entirely.
- Like the kernel, a thread dequeues its kevents onto its own stack only when it starts running.
  Dequeuing them earlier handed libdispatch stale thread requests ("Invalid wlh state").

### Preemption without a PMU

There's no guest PMU on M1. (Hypervisor.framework can emulate one with EL2, which needs M3 or
later.) Two things stand in for it:

- **Kicking the guest:** the vCPU's own virtual timer (`CNTV_CVAL`/`CTL`) interrupts the guest
  every 1 ms slice when another thread could run. It fires on the vCPU's core, so it's far more
  punctual than `hv_vcpus_exit` from another thread, whose latency tail reached hundreds of
  microseconds. Threads are only preempted at EL0: in appbox's exception vectors, part of their
  state is in EL1 registers.
- **Counting instructions:** the host's per-thread fixed counter (`thread_selfcounts`) on the
  vCPU thread includes the guest's instructions. appbox subtracts a calibrated per-run overhead.
  The result is exact except for host interrupts, which only ever add, up to about 100k in a few
  ms.

## Record/replay (warpspeed)

### Capturing syscall side effects

Before a syscall is forwarded, the pages its arguments point to (followed two pointers deep,
`explore_pointers`) are snapshotted. Afterwards they're diffed, and the changes are recorded.
Memory appbox writes itself isn't pointed to by any argument, e.g. workqueue thread stacks and
kevents. appbox reports those writes explicitly, and replay repeats its allocations in the same
order so later mappings land in the same places.

### Replaying preemptions: coarse, then fine

A preemption is recorded as the preempted thread's registers plus the guest instructions retired
since the previous event. Replay finds that point again in two phases:

1. **Coarse:** run the guest in timer-bounded slices sized as if it retired 26 instructions/ns,
   faster than any Apple core can, so a slice can't overshoot. Stop 150k instructions short of
   the target.
2. **Fine:** put a hardware breakpoint on the recorded pc, and stop at the first hit whose
   registers match. If the registers don't change between iterations of a loop, the loop isn't
   changing anything, so any iteration is the same point.

Counts are only ever relative to the last event. The per-run overhead differs by exit type and
between record and replay, so sums across syscalls drift.
- **Detecting a miss:** a miss (the timer fired late) shows up as the hit-count bound being
  exceeded, or as reaching the next syscall.
- **Recovering:** replay goes back to the latest checkpoint before it and finds that preemption
  with breakpoints alone. While catching up, stdout/stderr writes aren't repeated, and debugger
  hits aren't reported.

### Copy-on-write checkpoints and reverse-continue

There's no `fork` for a process with a vCPU. Instead, a checkpoint write-protects the guest's
1:1 memory in stage 2 (`hv_vm_protect`).
- **Guest writes:** the first write to each page afterwards faults. The fault saves the 16 KiB
  host page into that interval's undo log and makes the page writable again (about 5 µs a page).
- **Host writes:** writes the host makes on the guest's behalf (forwarded syscalls, replayed side
  effects) are logged up front.
- **Handler state:** the trap handler snapshots its own state (mappings, next fixed address, fds,
  signals, TSD).
- **Journal:** the handler also journals what the guest does to host resources, so a restore can
  undo it: mappings created or removed (with the removed contents), fds opened or closed
  (closed ones are duplicated into the stash), and the malloc reservation being taken.

Restoring applies the undo logs newest first. Discarding a checkpoint merges its log into the
previous one, where older contents win. Replay keeps at most two checkpoints per power-of-two
age, so recent history is dense and old history sparse.

Reverse-continue:
1. Restore the latest checkpoint before the current position.
2. Replay forwards to the current position, noting each debugger hit. A hit is exactly "the
   nth hit of this breakpoint/watchpoint since event e".
3. Restore again and land on the last hit.
4. If there were no hits, repeat from the checkpoint before, down to the start of the
   recording.

Debugger breakpoints and watchpoints are hardware ones, so guest memory stays untouched.

Reverse-stepi finds the previous instruction by brute force, and handles jumps into the current
pc without any special cases:
1. Replay from a checkpoint to the start of the current event.
2. Run coarsely to within the position margin of the current position.
3. Single-step the rest of the way, remembering each state (under a second, at a few µs a step).
4. Replay to the state before the current position.

At the first instruction after an event, the previous instruction belongs to the event before.
For a syscall, that's the `svc`: replay runs into it and backs out of the exception by setting pc
to `ELR_EL1 - 4` and PSTATE to `SPSR_EL1`. For a preemption, it's the preempted thread's
position.

### Exclusive monitors

Any VM exit between a `ldxr` and its `stxr` clears the exclusive monitor, and the `stxr` fails.
Which exits happen (faults for lazy mapping, dirty tracking or checkpoints; timers; debugger
traps) differs between recording and replay, so an LL/SC sequence could succeed in one and fail
in the other. dyld's pid cache did exactly that.
- **The fix:** whenever the guest resumes inside a short, side-effect-free `ldxr…stxr` window,
  appbox rewinds the pc to the `ldxr`, as if the exit had come just before it.
- **Remaining gaps:** single-stepping through such a sequence can still make it fail, and so can
  host interrupts during recording (rare). Reverse-stepi's stepping stretch is exposed to this:
  a failed `stxr` there can keep it from reaching the position it steps towards, in which case
  it stays put with a warning.
