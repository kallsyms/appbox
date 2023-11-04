# AppBox
AppBox is a framework to load Mach-O executables into a VM and intercept/handle traps out from the app/VM.

This was originally created to be the foundation for [warpspeed](https://github.com/kallsyms/warpspeed), a record/replay debugger for macOS.

## Example
```rust
pub struct Example { ... }

// AppBoxTrapHandler defines a single method, trap_handler, which is invoked
// whenever the VM traps out to the host when a syscall, mach trap, etc. is hit.
impl AppBoxTrapHandler for Example {
    fn trap_handler(
        &mut self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        load_info: &LoadInfo,
    ) -> Result<ExitKind> {
        let elr = vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
        debug!("ELR_EL1: {:#x}", elr);
        Ok(ExitKind::Continue)
    }
}

let handler = RefCell::new(Example{ ... });

// Create the AppBox with the executable, argv, envp, and the struct that implements `AppBoxTrapHandler`.
let mut app = appbox::AppBox::new(
    &PathBuf::from(&args.executable),
    &args.arguments,
    &env,
    handler.clone(),
)
.unwrap();

// And run!
let ret = app.run();
debug!("executor returned: {:?}", ret);
```

## 10,000ft Overview
### Basic Flow
When the `AppBox` is run:
* A "blank" VM is created.
* Hyperpom is configured with an `AppBoxLoader` which:
    * Loads the executable (and dyld) into memory.
    * Sets up the stack as required by the runtime.
    * Sets up the commpage.
    * Initializes thread local storage.
    * Maps the dyld shared cache.
* The Hyperpom `Executor` is then run which initializes registers, and starts the VM.

Then, when the guest/application traps out (usually due to a syscall or mach trap causing the VM to trap to EL1), the `AppBoxTrapHandler` passed into the `AppBox` is called back where it can decide what to do with the event (e.g. forward the syscall to the host), and then resume the guest.

### 1:1 Mappings
One of the fundamentals of AppBox is that (nearly) all loads are mapped "1 to 1" into the VM.
That means, if a page of e.g. the target executable is mapped at 0x13370000 in the "host" process, the same page will be mapped into the VM at virtual address 0x13370000 as well.
This drastically simplifies the process of handlings traps from the VM, as there is no need to remap addresses, and pointers out of the VM can be dereferenced as-is.

## Notes
### dyld shared cache
One of the most difficult parts of creating isolated VMs for Mac binaries is mapping the dyld shared cache into the VM.
dyld is intertwined into the OS and changes not infrequently.
AppBox implements just enough to load an arm64 shared cache as of macOS Ventura (13.x), so run on/use a shared cache from Ventura if you run into issues.

### Building on Hyperpom
Hyperpom was originally created for fuzzing, and has a very different intended usage pattern than AppBox.
AppBox intends a VM to be run once then be torn down, and cares about keeping state in a separate `AppBoxTrapHandler` outside of/independent from the Hyperpom `Executor`.

## Credits
As noted, AppBox uses a fork of [hyperpom](https://github.com/Impalabs/hyperpom) to manage VM setup, most notably handling the construction of the required page tables.