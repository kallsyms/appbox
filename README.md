# AppBox
AppBox is a framework to load Mach-O executables into a VM and intercept/handle traps out from the app/VM.

This was originally created to be the foundation for [warpspeed](https://github.com/kallsyms/warpspeed), a record/replay debugger for macOS.

## Example
See the [examples](./examples) directory for a handful of examples of how AppBox is used.

## 10,000ft Overview
### Basic Flow
* A "blank" `VmManager` is created.
* An application (Mach-O) is loaded into the VM:
    * Loads the executable (and dyld) into memory.
    * Sets up the stack as required by the runtime.
    * Sets up the commpage.
    * Initializes thread local storage.
    * Maps the dyld shared cache.
* `VmManager.run()` is called in a loop:
    * `run()` returns when the program makes a syscall/mach trap
    * A `DefaultTrapHandler` can be instantiated and used to automatically handle forwarding syscalls, manage keeping memory  mappings inside the VM consistent, etc. or this can be implemented manually.

### 1:1 Mappings
One of the fundamentals of AppBox is that (nearly) all loads are mapped "1 to 1" into the VM.
That means, if a page of e.g. the target executable is mapped at 0x13370000 in the "host" process, the same page will be mapped into the VM at virtual address 0x13370000 as well.
This drastically simplifies the process of handlings traps from the VM, as there is no need to remap addresses, and pointers out of the VM can be dereferenced as-is.

## Notes
### dyld shared cache
One of the most difficult parts of creating isolated VMs for Mac binaries is mapping the dyld shared cache into the VM.
dyld is intertwined into the OS and changes not infrequently.
AppBox implements just enough to load an arm64 shared cache as of macOS Ventura (13.x), so run on/use a shared cache from Ventura if you run into issues.

## Credits
As noted, AppBox vendors part of [hyperpom](https://github.com/Impalabs/hyperpom) to manage VM setup, most notably handling the construction of the required page tables.
