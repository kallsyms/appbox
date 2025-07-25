use clap::Parser;
use log::info;
use std::path::PathBuf;

use appbox::applevisor as av;
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::vm::VmManager;

#[derive(Parser)]
pub struct Args {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// Port to listen on for a gdb client
    #[clap(long)]
    pub gdb_port: Option<u16>,

    /// Wait for gdb connection before running
    #[clap(long)]
    pub gdb_wait: bool,

    /// Target executable
    #[clap(required = true)]
    pub executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let mut vm = VmManager::new()?;

    let loader = appbox::loader::load_macho(
        &mut vm,
        &PathBuf::from(args.executable.clone()),
        vec![args.executable],
        vec![],
    )?;

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;

    let (command_sender, command_receiver) = std::sync::mpsc::channel();
    let (response_sender, response_receiver) = std::sync::mpsc::channel();

    let notification_sender = if let Some(port) = args.gdb_port {
        Some(appbox::gdb::start_gdb_server(
            port,
            command_sender,
            response_receiver,
            None,
        )?)
    } else {
        None
    };

    if args.gdb_port.is_some() {
        if args.gdb_wait {
            info!("Waiting for GDB connection...");
            loop {
                if let Ok(cmd) = command_receiver.recv() {
                    if let appbox::gdb::GdbCommand::Continue = cmd {
                        break;
                    }
                    appbox::gdb::handle_command(cmd, &mut vm, &response_sender);
                }
            }
        }
    }

    let mut single_step_breakpoint: Option<u64> = None;

    loop {
        vm.vcpu.run()?;
        while let Ok(cmd) = command_receiver.try_recv() {
            match cmd {
                appbox::gdb::GdbCommand::Continue => {
                    // Remove single step breakpoint if it exists
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }
                    break;
                }
                appbox::gdb::GdbCommand::Step => {
                    // Get current instruction to determine next PC
                    let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                    let mut insn_bytes = [0; 4];
                    vm.vma.read(pc, &mut insn_bytes)?;

                    // Remove previous single step breakpoint if it exists
                    if let Some(addr) = single_step_breakpoint.take() {
                        let _ = vm.hooks.remove_breakpoint(addr, &mut vm.vma);
                    }

                    // For now, assume next instruction is at PC + 4
                    // TODO: Enhance this to handle branches properly by using instruction emulation
                    let next_pc = pc + 4;

                    // Set new single step breakpoint
                    vm.hooks.add_breakpoint(next_pc, &mut vm.vma)?;
                    single_step_breakpoint = Some(next_pc);
                    break;
                }
                _ => {
                    appbox::gdb::handle_command(cmd, &mut vm, &response_sender);
                }
            }
        }

        // https://github.com/kallsyms/hyperpom/blob/a1dd1aebd8f306bb8549595d9d1506c2a361f0d7/src/core.rs#L1535
        let exit_info = vm.vcpu.get_exit_info();
        let exit = match exit_info.reason {
            av::ExitReason::EXCEPTION => {
                match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                    ExceptionClass::HvcA64 => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                        println!("HVC call at {:#x}", pc);
                        ExitKind::Exit
                    }
                    ExceptionClass::BrkA64 => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC)?;

                        // Check if this is our single step breakpoint
                        if Some(pc) == single_step_breakpoint {
                            println!("Single step completed at {:#x}", pc);
                            // Remove the single step breakpoint
                            vm.hooks.remove_breakpoint(pc, &mut vm.vma)?;
                            single_step_breakpoint = None;
                            // Don't handle as normal breakpoint since we removed it
                            ExitKind::Continue
                        } else {
                            println!("Breakpoint hit at {:#x}", pc);
                            vm.hooks.handle(&mut vm.vcpu, &mut vm.vma)?;
                            ExitKind::Continue
                        }
                    }
                    ExceptionClass::InsAbortLowerEl => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                        println!("Instruction Abort (Lower EL) at {:#x}", pc);

                        // Send SIGSEGV signal to GDB to indicate fault
                        if let Some(ref sender) = notification_sender {
                            appbox::gdb::send_sigsegv(sender);
                        }

                        // Enter GDB evaluation loop for system state inspection
                        loop {
                            if let Ok(cmd) = command_receiver.recv() {
                                match cmd {
                                    appbox::gdb::GdbCommand::Continue => break,
                                    _ => {
                                        appbox::gdb::handle_command(cmd, &mut vm, &response_sender)
                                    }
                                }
                            }
                        }

                        // Always crash after inspection - no recovery possible
                        ExitKind::Crash("Instruction Abort".to_string())
                    }
                    _ => Err(ExceptionError::UnimplementedException(
                        exit_info.exception.syndrome,
                    ))?,
                }
            }
            av::ExitReason::CANCELED => ExitKind::Timeout,
            av::ExitReason::VTIMER_ACTIVATED => unimplemented!(),
            av::ExitReason::UNKNOWN => panic!(
                "Vcpu exited unexpectedly at address {:#x}",
                vm.vcpu.get_reg(av::Reg::PC)?
            ),
        };

        match exit {
            ExitKind::Continue => continue,
            _ => break,
        };
    }

    Ok(())
}
