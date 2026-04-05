This is AppBox, a virtualization layer of sorts which allows macOS binaries to be run inside micro VMs to provide a hard isolation boundary for inspection, security, etc.
When a syscall is executed by the target application, the VM traps out to the AppBox runtime which can then forward the syscall to the host (see e.g. [examples/strace/](./examples/strace/)), deny the syscall before it hits the host (e.g. [examples/ebpf\_syscall\_guard/](./examples/ebpf_syscall_guard/)), or anything else.

## Implementation details
* A core idea is the idea of 1:1 memory mapping - virtual addresses inside the VM are mapped to the same vaddrs on the host. This allows arbitrary syscalls to be forwarded to the host without pointer fixups (which may not always be possible without knowing the full struct layout of every single syscall).
    * Care must be taken to ensure any syscalls which modify the memory map of the host process also map the memory into the VM to prevent data aborts.
* The macOS dyld shared cache also must be manually walked and mapped into the VM since the global shared dyld cache XNU presents cannot be mapped into VMs. We have to do all this ourselves. See [dyld.rs](./src/dyld.rs).
    * Public `dyld` source is useful for reference if new cache versions (incl. slide versions) need to be implemented. See in particular [Apple's public dsc\_extractor.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/other-tools/dsc_extractor.cpp).
* We must also setup the initial stack, argv, thread-local storage, etc. that the kernel would for a normal program ourselves.

## Exports/Intended flow
* AppBox's main library export is the `VmManager` which wraps the VM the program runs in. See [vm/mod.rs](./src/vm/mod.rs)
* MachO's are loaded via `appbox::loader::load_macho` which configures the VM, maps in the MachO, shared cache, configures stack/etc. See [loader.rs](./src/loader.rs)
* Once loaded, `VmManager.run()` is called in a loop to run the VM until syscall/trap exit.
    * The result of this is then switched on and handled as necessary for the intended use.
    * AppBox provides a `DefaultTrapHandler` which can be instantiated along with the VM and then invoked on every trap to handle syscalls formemory mappings to ensure these stay in-sync between the VM and host process and similar. See [trap.rs](./src/trap.rs).
* AppBox also includes the base code required for a GDB stub. Similar to the trap handler, this is expected to be extended by library users with the code in AppBox as the default/fallthrough case for core operations like memory read/write, CPU register introspection, breakpoint management, etc. See [gdb.rs](./src/gdb.rs).

For more specifics of the intended public interface/usage, see the [strace example implementation](./examples/strace/src/main.rs) which contains a full instantiation + run loop.
