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

    let loader = appbox::loader::load_macho(&mut vm, &PathBuf::from(args.executable))?;

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
                    handle_gdb_command(cmd, &mut vm, &response_sender);
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
            handle_gdb_command(cmd, &mut vm, &response_sender);
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

fn handle_gdb_command(
    cmd: appbox::gdb::GdbCommand,
    vm: &mut VmManager,
    response_sender: &std::sync::mpsc::Sender<appbox::gdb::GdbResponse>,
) {
    trace!("Handling GDB command: {:?}", cmd);
    match cmd {
        appbox::gdb::GdbCommand::AddBreakpoint { addr, .. } => {
            vm.hooks.add_breakpoint(addr, &mut vm.vma).unwrap();
            response_sender.send(appbox::gdb::GdbResponse::Ok).unwrap();
        }
        appbox::gdb::GdbCommand::ReadMemory { addr, len } => {
            let mut data = vec![0; len];
            match vm.vma.read(addr, &mut data) {
                Ok(_) => response_sender
                    .send(appbox::gdb::GdbResponse::MemoryData(data))
                    .unwrap(),
                Err(_) => response_sender
                    .send(appbox::gdb::GdbResponse::Error(1))
                    .unwrap(),
            }
        }
        appbox::gdb::GdbCommand::WriteMemory { addr, data } => match vm.vma.write(addr, &data) {
            Ok(_) => response_sender.send(appbox::gdb::GdbResponse::Ok).unwrap(),
            Err(_) => response_sender
                .send(appbox::gdb::GdbResponse::Error(1))
                .unwrap(),
        },
        appbox::gdb::GdbCommand::ReadRegisters => {
            let regs = vec![
                vm.vcpu.get_reg(av::Reg::X0).unwrap(),
                vm.vcpu.get_reg(av::Reg::X1).unwrap(),
                vm.vcpu.get_reg(av::Reg::X2).unwrap(),
                vm.vcpu.get_reg(av::Reg::X3).unwrap(),
                vm.vcpu.get_reg(av::Reg::X4).unwrap(),
                vm.vcpu.get_reg(av::Reg::X5).unwrap(),
                vm.vcpu.get_reg(av::Reg::X6).unwrap(),
                vm.vcpu.get_reg(av::Reg::X7).unwrap(),
                vm.vcpu.get_reg(av::Reg::X8).unwrap(),
                vm.vcpu.get_reg(av::Reg::X9).unwrap(),
                vm.vcpu.get_reg(av::Reg::X10).unwrap(),
                vm.vcpu.get_reg(av::Reg::X11).unwrap(),
                vm.vcpu.get_reg(av::Reg::X12).unwrap(),
                vm.vcpu.get_reg(av::Reg::X13).unwrap(),
                vm.vcpu.get_reg(av::Reg::X14).unwrap(),
                vm.vcpu.get_reg(av::Reg::X15).unwrap(),
                vm.vcpu.get_reg(av::Reg::X16).unwrap(),
                vm.vcpu.get_reg(av::Reg::X17).unwrap(),
                vm.vcpu.get_reg(av::Reg::X18).unwrap(),
                vm.vcpu.get_reg(av::Reg::X19).unwrap(),
                vm.vcpu.get_reg(av::Reg::X20).unwrap(),
                vm.vcpu.get_reg(av::Reg::X21).unwrap(),
                vm.vcpu.get_reg(av::Reg::X22).unwrap(),
                vm.vcpu.get_reg(av::Reg::X23).unwrap(),
                vm.vcpu.get_reg(av::Reg::X24).unwrap(),
                vm.vcpu.get_reg(av::Reg::X25).unwrap(),
                vm.vcpu.get_reg(av::Reg::X26).unwrap(),
                vm.vcpu.get_reg(av::Reg::X27).unwrap(),
                vm.vcpu.get_reg(av::Reg::X28).unwrap(),
                vm.vcpu.get_reg(av::Reg::FP).unwrap(),
                vm.vcpu.get_reg(av::Reg::LR).unwrap(),
                vm.vcpu.get_sys_reg(av::SysReg::SP_EL0).unwrap(),
                vm.vcpu.get_reg(av::Reg::PC).unwrap(),
                vm.vcpu.get_reg(av::Reg::CPSR).unwrap(),
            ];
            response_sender
                .send(appbox::gdb::GdbResponse::RegisterData(regs))
                .unwrap();
        }
        appbox::gdb::GdbCommand::WriteRegister { reg, val } => {
            match reg {
                0 => vm.vcpu.set_reg(av::Reg::X0, val).unwrap(),
                1 => vm.vcpu.set_reg(av::Reg::X1, val).unwrap(),
                2 => vm.vcpu.set_reg(av::Reg::X2, val).unwrap(),
                3 => vm.vcpu.set_reg(av::Reg::X3, val).unwrap(),
                4 => vm.vcpu.set_reg(av::Reg::X4, val).unwrap(),
                5 => vm.vcpu.set_reg(av::Reg::X5, val).unwrap(),
                6 => vm.vcpu.set_reg(av::Reg::X6, val).unwrap(),
                7 => vm.vcpu.set_reg(av::Reg::X7, val).unwrap(),
                8 => vm.vcpu.set_reg(av::Reg::X8, val).unwrap(),
                9 => vm.vcpu.set_reg(av::Reg::X9, val).unwrap(),
                10 => vm.vcpu.set_reg(av::Reg::X10, val).unwrap(),
                11 => vm.vcpu.set_reg(av::Reg::X11, val).unwrap(),
                12 => vm.vcpu.set_reg(av::Reg::X12, val).unwrap(),
                13 => vm.vcpu.set_reg(av::Reg::X13, val).unwrap(),
                14 => vm.vcpu.set_reg(av::Reg::X14, val).unwrap(),
                15 => vm.vcpu.set_reg(av::Reg::X15, val).unwrap(),
                16 => vm.vcpu.set_reg(av::Reg::X16, val).unwrap(),
                17 => vm.vcpu.set_reg(av::Reg::X17, val).unwrap(),
                18 => vm.vcpu.set_reg(av::Reg::X18, val).unwrap(),
                19 => vm.vcpu.set_reg(av::Reg::X19, val).unwrap(),
                20 => vm.vcpu.set_reg(av::Reg::X20, val).unwrap(),
                21 => vm.vcpu.set_reg(av::Reg::X21, val).unwrap(),
                22 => vm.vcpu.set_reg(av::Reg::X22, val).unwrap(),
                23 => vm.vcpu.set_reg(av::Reg::X23, val).unwrap(),
                24 => vm.vcpu.set_reg(av::Reg::X24, val).unwrap(),
                25 => vm.vcpu.set_reg(av::Reg::X25, val).unwrap(),
                26 => vm.vcpu.set_reg(av::Reg::X26, val).unwrap(),
                27 => vm.vcpu.set_reg(av::Reg::X27, val).unwrap(),
                28 => vm.vcpu.set_reg(av::Reg::X28, val).unwrap(),
                29 => vm.vcpu.set_reg(av::Reg::FP, val).unwrap(),
                30 => vm.vcpu.set_reg(av::Reg::LR, val).unwrap(),
                31 => vm.vcpu.set_sys_reg(av::SysReg::SP_EL0, val).unwrap(),
                32 => vm.vcpu.set_reg(av::Reg::PC, val).unwrap(),
                33 => vm.vcpu.set_reg(av::Reg::CPSR, val).unwrap(),
                _ => {}
            }
            response_sender.send(appbox::gdb::GdbResponse::Ok).unwrap();
        }
        appbox::gdb::GdbCommand::ReadRegister { reg } => {
            let val = match reg {
                0 => vm.vcpu.get_reg(av::Reg::X0).unwrap(),
                1 => vm.vcpu.get_reg(av::Reg::X1).unwrap(),
                2 => vm.vcpu.get_reg(av::Reg::X2).unwrap(),
                3 => vm.vcpu.get_reg(av::Reg::X3).unwrap(),
                4 => vm.vcpu.get_reg(av::Reg::X4).unwrap(),
                5 => vm.vcpu.get_reg(av::Reg::X5).unwrap(),
                6 => vm.vcpu.get_reg(av::Reg::X6).unwrap(),
                7 => vm.vcpu.get_reg(av::Reg::X7).unwrap(),
                8 => vm.vcpu.get_reg(av::Reg::X8).unwrap(),
                9 => vm.vcpu.get_reg(av::Reg::X9).unwrap(),
                10 => vm.vcpu.get_reg(av::Reg::X10).unwrap(),
                11 => vm.vcpu.get_reg(av::Reg::X11).unwrap(),
                12 => vm.vcpu.get_reg(av::Reg::X12).unwrap(),
                13 => vm.vcpu.get_reg(av::Reg::X13).unwrap(),
                14 => vm.vcpu.get_reg(av::Reg::X14).unwrap(),
                15 => vm.vcpu.get_reg(av::Reg::X15).unwrap(),
                16 => vm.vcpu.get_reg(av::Reg::X16).unwrap(),
                17 => vm.vcpu.get_reg(av::Reg::X17).unwrap(),
                18 => vm.vcpu.get_reg(av::Reg::X18).unwrap(),
                19 => vm.vcpu.get_reg(av::Reg::X19).unwrap(),
                20 => vm.vcpu.get_reg(av::Reg::X20).unwrap(),
                21 => vm.vcpu.get_reg(av::Reg::X21).unwrap(),
                22 => vm.vcpu.get_reg(av::Reg::X22).unwrap(),
                23 => vm.vcpu.get_reg(av::Reg::X23).unwrap(),
                24 => vm.vcpu.get_reg(av::Reg::X24).unwrap(),
                25 => vm.vcpu.get_reg(av::Reg::X25).unwrap(),
                26 => vm.vcpu.get_reg(av::Reg::X26).unwrap(),
                27 => vm.vcpu.get_reg(av::Reg::X27).unwrap(),
                28 => vm.vcpu.get_reg(av::Reg::X28).unwrap(),
                29 => vm.vcpu.get_reg(av::Reg::FP).unwrap(),
                30 => vm.vcpu.get_reg(av::Reg::LR).unwrap(),
                31 => vm.vcpu.get_sys_reg(av::SysReg::SP_EL0).unwrap(),
                32 => vm.vcpu.get_reg(av::Reg::PC).unwrap(),
                33 => vm.vcpu.get_reg(av::Reg::CPSR).unwrap(),
                _ => 0,
            };
            response_sender
                .send(appbox::gdb::GdbResponse::RegisterValue(val))
                .unwrap();
        }
        appbox::gdb::GdbCommand::Continue => {}
    }
}
