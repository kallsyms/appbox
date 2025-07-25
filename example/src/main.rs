use clap::Parser;
use log::{info, trace};
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

    if let Some(port) = args.gdb_port {
        appbox::gdb::start_gdb_server(port, command_sender, response_receiver, None)?;
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

    loop {
        vm.vcpu.run()?;
        while let Ok(cmd) = command_receiver.try_recv() {
            if let appbox::gdb::GdbCommand::Continue = cmd {
                break;
            }
            appbox::gdb::handle_command(cmd, &mut vm, &response_sender);
        }

        // https://github.com/kallsyms/hyperpom/blob/a1dd1aebd8f306bb8549595d9d1506c2a361f0d7/src/core.rs#L1535
        let exit_info = vm.vcpu.get_exit_info();
        let exit = match exit_info.reason {
            av::ExitReason::EXCEPTION => {
                match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                    ExceptionClass::HvcA64 => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                        println!("HVC call at {:#x}", pc);
                        ExitKind::Continue
                    }
                    ExceptionClass::BrkA64 => {
                        let pc = vm.vcpu.get_reg(av::Reg::PC)?;
                        println!("Breakpoint hit at {:#x}", pc);
                        vm.hooks.handle(&mut vm.vcpu, &mut vm.vma)?;
                        ExitKind::Continue
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
