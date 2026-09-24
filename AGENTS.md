This is AppBox, a virtualization layer of sorts which allows macOS binaries to be run inside micro VMs to provide a hard isolation boundary for inspection, security, etc.
When a syscall is executed by the target application, the VM traps out to the AppBox runtime which can then forward the syscall to the host (see e.g. [examples/strace/](./examples/strace/)), deny the syscall before it hits the host (e.g. [examples/ebpf\_syscall\_guard/](./examples/ebpf_syscall_guard/)), or anything else.

## Implementation details
* A core idea is the idea of 1:1 memory mapping - virtual addresses inside the VM are mapped to the same vaddrs on the host. This allows arbitrary syscalls to be forwarded to the host without pointer fixups (which may not always be possible without knowing the full struct layout of every single syscall).
    * Care must be taken to ensure any syscalls which modify the memory map of the host process also map the memory into the VM to prevent data aborts.
* The macOS dyld shared cache also must be manually walked and mapped into the VM since the global shared dyld cache XNU presents cannot be mapped into VMs. We have to do all this ourselves. See [dyld.rs](./src/dyld.rs).
    * Public `dyld` source is useful for reference if new cache versions (incl. slide versions) need to be implemented. See in particular [Apple's public dsc\_extractor.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/other-tools/dsc_extractor.cpp).
* We must also setup the initial stack, argv, thread-local storage, etc. that the kernel would for a normal program ourselves.

## Exports/Intended flow
* The public API is [`appbox::guest`](./src/guest/mod.rs). `Guest::builder(program)` loads a Mach-O (mapping the binary and shared cache, setting up the stack, argv, TLS, etc.) and `run()`s it, handling its syscalls, threads, exec, and the processes it spawns.
    * `appbox::guest::prepare()` must come first in `main`: it re-runs the process with an address space layout that leaves the guest room, and runs guests that a guest spawned.
    * Embedders observe and steer the guest through `Hooks` callbacks: before/after syscalls, preemptions, stops (hardware breakpoints, watchpoints, steps), faults, exec, and the guest ending. Each gets a `ThreadCx` with the thread's registers, memory, breakpoints/watchpoints, and checkpoints.
    * With time-shared threads (the default), a `Scheduler` decides which thread runs and for how long, down to exact points in its execution (`Slice::At`); `RoundRobin` is the default. `ThreadingModel::Parallel` gives each guest thread a vCPU and host thread of its own instead (no scheduler, so no record/replay).
* [gdb.rs](./src/gdb.rs) has `GdbHooks`, a ready-made GDB stub, and `GdbServer`, the connection itself for embedders with their own debugger logic (e.g. warpspeed's reverse debugging).
* The rest is internal: the VM and vCPUs ([vm/mod.rs](./src/vm/mod.rs)), loading ([loader.rs](./src/loader.rs)), syscall handling ([trap.rs](./src/trap.rs)), guest threads ([threads.rs](./src/threads.rs), [runner.rs](./src/runner.rs)), and the loop running each vCPU that calls the hooks and scheduler ([guest/drive.rs](./src/guest/drive.rs)).

For usage, see the [strace](./examples/strace/src/main.rs), [gdb\_stub](./examples/gdb_stub/src/main.rs) and [ebpf\_syscall\_guard](./examples/ebpf_syscall_guard/) examples, and warpspeed (record/replay, with its own scheduler).
