use appbox::VmManager;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
pub struct Args {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// Port to listen on for a gdb client
    #[clap(long)]
    pub gdb_port: Option<u16>,

    /// Target executable
    #[clap(required = true)]
    pub executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let mut vm = VmManager::new();

    let load_info = loader::load_macho(&mut vm, executable)?;

    let (command_sender, command_receiver) = std::sync::mpsc::channel();
    let (response_sender, response_receiver) = std::sync::mpsc::channel();

    if let Some(port) = gdb_port {
        gdb::start_gdb_server(port, command_sender, response_receiver)?;
    }

    vm.vcpu.set_reg(av::Reg::PC, load_info.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, load_info.stack_pointer)?;

    loop {
        vm.vcpu.run()?;
        if let Ok(cmd) = command_receiver.try_recv() {
            match cmd {
                gdb::GdbCommand::AddBreakpoint { addr, .. } => {
                    vm.hooks.add_breakpoint(addr, &mut vm.vma).unwrap();
                    response_sender.send(gdb::GdbResponse::Ok).unwrap();
                }
            }
        }

        // https://github.com/kallsyms/hyperpom/blob/a1dd1aebd8f306bb8549595d9d1506c2a361f0d7/src/core.rs#L1535
        let exit_info = vm.vcpu.get_exit_info();
        let exit = match exit_info.reason {
            av::ExitReason::EXCEPTION => {
                match ExceptionClass::from(exit.exception.syndrome >> 26) {
                    ExceptionClass::HvcA64 => Self::handle_hvc(executor),
                    ExceptionClass::BrkA64 => vm.hooks.handle(&mut vm.vcpu, &mut vm.vma),
                    _ => Err(ExceptionError::UnimplementedException(
                        exit.exception.syndrome,
                    ))?,
                }
            }
            av::ExitReason::CANCELED => ExitKind::Timeout,
            av::ExitReason::VTIMER_ACTIVATED => unimplemented!(),
            av::ExitReason::UNKNOWN => panic!(
                "Vcpu exited unexpectedly at address {:#x}",
                self.vcpu.get_reg(av::Reg::PC)?
            ),
        };

        match exit {
            ExitKind::Continue => continue,
            _ => break Ok(exit),
        };
    }

    Ok(())
}
