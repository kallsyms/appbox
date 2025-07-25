use anyhow::Result;
use log::{debug, info, trace, warn};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::applevisor as av;
use crate::vm::VmManager;

#[derive(Debug)]
pub enum GdbCommand {
    AddBreakpoint { addr: u64, kind: u64 },
    Continue,
    ReadMemory { addr: u64, len: usize },
    WriteMemory { addr: u64, data: Vec<u8> },
    ReadRegisters,
    WriteRegister { reg: usize, val: u64 },
    ReadRegister { reg: usize },
}

#[derive(Debug)]
pub enum GdbResponse {
    Ok,
    Error(u8),
    MemoryData(Vec<u8>),
    RegisterData(Vec<u64>),
    RegisterValue(u64),
}

pub fn start_gdb_server(
    port: u16,
    command_sender: Sender<GdbCommand>,
    response_receiver: Receiver<GdbResponse>,
    wait_sender: Option<Sender<()>>,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    info!("GDB server listening on port {}", port);
    let response_receiver = Arc::new(Mutex::new(response_receiver));

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Some(ref sender) = wait_sender {
                sender.send(()).unwrap();
            }
            match stream {
                Ok(stream) => {
                    let command_sender = command_sender.clone();
                    let response_receiver = response_receiver.clone();
                    thread::spawn(move || {
                        handle_connection(stream, command_sender, response_receiver);
                    });
                }
                Err(e) => {
                    warn!("GDB connection failed: {}", e);
                }
            }
        }
    });

    Ok(())
}

const TARGET_XML: &str = r#"<target version="1.0">
<architecture>aarch64</architecture>
<feature name="org.gnu.gdb.aarch64.core">
<reg name="x0" bitsize="64" type="uint64"/>
<reg name="x1" bitsize="64" type="uint64"/>
<reg name="x2" bitsize="64" type="uint64"/>
<reg name="x3" bitsize="64" type="uint64"/>
<reg name="x4" bitsize="64" type="uint64"/>
<reg name="x5" bitsize="64" type="uint64"/>
<reg name="x6" bitsize="64" type="uint64"/>
<reg name="x7" bitsize="64" type="uint64"/>
<reg name="x8" bitsize="64" type="uint64"/>
<reg name="x9" bitsize="64" type="uint64"/>
<reg name="x10" bitsize="64" type="uint64"/>
<reg name="x11" bitsize="64" type="uint64"/>
<reg name="x12" bitsize="64" type="uint64"/>
<reg name="x13" bitsize="64" type="uint64"/>
<reg name="x14" bitsize="64" type="uint64"/>
<reg name="x15" bitsize="64" type="uint64"/>
<reg name="x16" bitsize="64" type="uint64"/>
<reg name="x17" bitsize="64" type="uint64"/>
<reg name="x18" bitsize="64" type="uint64"/>
<reg name="x19" bitsize="64" type="uint64"/>
<reg name="x20" bitsize="64" type="uint64"/>
<reg name="x21" bitsize="64" type="uint64"/>
<reg name="x22" bitsize="64" type="uint64"/>
<reg name="x23" bitsize="64" type="uint64"/>
<reg name="x24" bitsize="64" type="uint64"/>
<reg name="x25" bitsize="64" type="uint64"/>
<reg name="x26" bitsize="64" type="uint64"/>
<reg name="x27" bitsize="64" type="uint64"/>
<reg name="x28" bitsize="64" type="uint64"/>
<reg name="fp" bitsize="64" type="data_ptr"/>
<reg name="lr" bitsize="64" type="code_ptr"/>
<reg name="sp" bitsize="64" type="data_ptr"/>
<reg name="pc" bitsize="64" type="code_ptr"/>
<reg name="cpsr" bitsize="32" type="uint32"/>
</feature>
</target>"#;

fn send_packet(writer: &mut TcpStream, data: &str) {
    let checksum = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    let response = format!("${}#{:02x}", data, checksum);
    trace!("Sending packet: {}", response);
    writer.write_all(response.as_bytes()).unwrap();
}

fn handle_connection(
    stream: TcpStream,
    command_sender: Sender<GdbCommand>,
    response_receiver: Arc<Mutex<Receiver<GdbResponse>>>,
) {
    debug!("New GDB client connected: {}", stream.peer_addr().unwrap());
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;

    let mut no_ack_mode = false;

    // GDB handshake
    let mut handshake = [0; 1];
    if reader.read_exact(&mut handshake).is_err() {
        trace!("Connection closed during handshake");
        return;
    }
    if &handshake != b"+" {
        trace!("Handshake failed");
        return;
    }
    trace!("Handshake successful, sending ack");
    writer.write_all(b"+").unwrap();

    let mut buffer = Vec::new();
    loop {
        let mut read_buf = [0; 1024];
        match reader.read(&mut read_buf) {
            Ok(0) => {
                trace!("Connection closed");
                break;
            }
            Ok(n) => {
                buffer.extend_from_slice(&read_buf[..n]);
            }
            Err(e) => {
                warn!("GDB read error: {}", e);
                break;
            }
        }

        let mut processed_bytes = 0;
        while processed_bytes < buffer.len() {
            let current_buffer = &buffer[processed_bytes..];
            if current_buffer.is_empty() {
                break;
            }

            match current_buffer[0] {
                b'+' => {
                    trace!("Received ack");
                    processed_bytes += 1;
                    continue;
                }
                b'-' => {
                    trace!("Received nack");
                    processed_bytes += 1;
                    continue;
                }
                b'$' => {
                    if let Some(end_pos) = current_buffer.iter().position(|&b| b == b'#') {
                        if end_pos + 2 < current_buffer.len() {
                            let packet_end = end_pos + 3;
                            let packet_data = &current_buffer[1..end_pos];
                            let checksum_bytes = &current_buffer[end_pos + 1..packet_end];

                            let checksum_str = std::str::from_utf8(checksum_bytes).unwrap();
                            if let Ok(received_checksum) = u8::from_str_radix(checksum_str, 16) {
                                let calculated_checksum =
                                    packet_data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));

                                if calculated_checksum == received_checksum {
                                    if !no_ack_mode {
                                        trace!("Checksum correct, sending ack");
                                        writer.write_all(b"+").unwrap();
                                    }
                                    let command_str = std::str::from_utf8(packet_data).unwrap();
                                    trace!("Received command: {}", command_str);

                                    let core_command = command_str.split(';').next().unwrap_or("");

                                    if core_command.starts_with("qSupported") {
                                        send_packet(
                                            &mut writer,
                                            "PacketSize=4000;swbreak+;hwbreak+;qXfer:features:read+;QStartNoAckMode+",
                                        );
                                    } else if command_str == "QStartNoAckMode" {
                                        trace!("Entering No-Ack mode");
                                        no_ack_mode = true;
                                        send_packet(&mut writer, "OK");
                                    } else if command_str == "qC" {
                                        send_packet(&mut writer, "QC1");
                                    } else if command_str
                                        .starts_with("qXfer:features:read:target.xml")
                                    {
                                        let response = format!("l{}", TARGET_XML);
                                        send_packet(&mut writer, &response);
                                    } else if command_str == "?" {
                                        send_packet(&mut writer, "S05");
                                    } else if command_str == "qHostInfo" {
                                        send_packet(&mut writer, "cputype:16777228;cpusubtype:1;ostype:unknown;vendor:unknown;endian:little;ptrsize:8;");
                                    } else if command_str == "qProcessInfo" {
                                        send_packet(&mut writer, "pid:1;");
                                    } else if core_command == "qfThreadInfo" {
                                        send_packet(&mut writer, "m1");
                                    } else if core_command == "qsThreadInfo" {
                                        send_packet(&mut writer, "l");
                                    } else if core_command == "g" {
                                        command_sender.send(GdbCommand::ReadRegisters).unwrap();
                                        match response_receiver.lock().unwrap().recv().unwrap() {
                                            GdbResponse::RegisterData(regs) => {
                                                let mut reg_data = String::new();
                                                for reg in regs {
                                                    for byte in reg.to_le_bytes() {
                                                        reg_data.push_str(&format!("{:02x}", byte));
                                                    }
                                                }
                                                send_packet(&mut writer, &reg_data);
                                            }
                                            _ => send_packet(&mut writer, "E01"),
                                        }
                                    } else if core_command.starts_with('P') {
                                        let parts: Vec<&str> =
                                            core_command[1..].split('=').collect();
                                        if parts.len() == 2 {
                                            if let (Ok(reg), Ok(hex_val)) = (
                                                usize::from_str_radix(parts[0], 16),
                                                hex::decode(parts[1]),
                                            ) {
                                                let mut bytes = [0u8; 8];
                                                bytes.copy_from_slice(&hex_val);
                                                let val = u64::from_le_bytes(bytes);
                                                command_sender
                                                    .send(GdbCommand::WriteRegister { reg, val })
                                                    .unwrap();
                                                match response_receiver
                                                    .lock()
                                                    .unwrap()
                                                    .recv()
                                                    .unwrap()
                                                {
                                                    GdbResponse::Ok => {
                                                        send_packet(&mut writer, "OK")
                                                    }
                                                    _ => send_packet(&mut writer, "E01"),
                                                }
                                            } else {
                                                send_packet(&mut writer, "E01");
                                            }
                                        } else {
                                            send_packet(&mut writer, "E01");
                                        }
                                    } else if core_command.starts_with('p') {
                                        if let Ok(reg) =
                                            usize::from_str_radix(&core_command[1..], 16)
                                        {
                                            command_sender
                                                .send(GdbCommand::ReadRegister { reg })
                                                .unwrap();
                                            match response_receiver.lock().unwrap().recv().unwrap()
                                            {
                                                GdbResponse::RegisterValue(val) => {
                                                    let mut reg_data = String::new();
                                                    for byte in val.to_le_bytes() {
                                                        reg_data.push_str(&format!("{:02x}", byte));
                                                    }
                                                    send_packet(&mut writer, &reg_data);
                                                }
                                                _ => send_packet(&mut writer, "E01"),
                                            }
                                        } else {
                                            send_packet(&mut writer, "E01");
                                        }
                                    } else if core_command.starts_with('m') {
                                        let parts: Vec<&str> =
                                            core_command[1..].split(',').collect();
                                        if parts.len() == 2 {
                                            if let (Ok(addr), Ok(len)) = (
                                                u64::from_str_radix(parts[0], 16),
                                                usize::from_str_radix(parts[1], 16),
                                            ) {
                                                command_sender
                                                    .send(GdbCommand::ReadMemory { addr, len })
                                                    .unwrap();
                                                match response_receiver
                                                    .lock()
                                                    .unwrap()
                                                    .recv()
                                                    .unwrap()
                                                {
                                                    GdbResponse::MemoryData(data) => {
                                                        let hex_data = data
                                                            .iter()
                                                            .map(|b| format!("{:02x}", b))
                                                            .collect::<String>();
                                                        send_packet(&mut writer, &hex_data);
                                                    }
                                                    _ => send_packet(&mut writer, "E01"),
                                                }
                                            } else {
                                                send_packet(&mut writer, "E01");
                                            }
                                        } else {
                                            send_packet(&mut writer, "E01");
                                        }
                                    } else if core_command.starts_with('M') {
                                        let parts: Vec<&str> = core_command[1..]
                                            .split(|c| c == ',' || c == ':')
                                            .collect();
                                        if parts.len() == 3 {
                                            if let (Ok(addr), Ok(len)) = (
                                                u64::from_str_radix(parts[0], 16),
                                                usize::from_str_radix(parts[1], 16),
                                            ) {
                                                let data_str = parts[2];
                                                if let Ok(data) = hex::decode(data_str) {
                                                    if data.len() == len {
                                                        command_sender
                                                            .send(GdbCommand::WriteMemory {
                                                                addr,
                                                                data,
                                                            })
                                                            .unwrap();
                                                        match response_receiver
                                                            .lock()
                                                            .unwrap()
                                                            .recv()
                                                            .unwrap()
                                                        {
                                                            GdbResponse::Ok => {
                                                                send_packet(&mut writer, "OK")
                                                            }
                                                            _ => send_packet(&mut writer, "E01"),
                                                        }
                                                    } else {
                                                        send_packet(&mut writer, "E01");
                                                    }
                                                } else {
                                                    send_packet(&mut writer, "E01");
                                                }
                                            } else {
                                                send_packet(&mut writer, "E01");
                                            }
                                        } else {
                                            send_packet(&mut writer, "E01");
                                        }
                                    } else if core_command.starts_with('x') {
                                        send_packet(&mut writer, "E01");
                                    } else if core_command == "QThreadSuffixSupported"
                                        || core_command == "QListThreadsInStopReply"
                                        || core_command == "qVAttachOrWaitSupported"
                                        || core_command == "QEnableErrorStrings"
                                    {
                                        send_packet(&mut writer, "OK");
                                    } else if core_command == "c" {
                                        command_sender.send(GdbCommand::Continue).unwrap();
                                    } else if core_command.starts_with("Z0,") {
                                        let parts: Vec<&str> =
                                            core_command[3..].split(',').collect();
                                        if parts.len() == 2 {
                                            if let (Ok(addr), Ok(kind)) = (
                                                u64::from_str_radix(parts[0], 16),
                                                u64::from_str_radix(parts[1], 16),
                                            ) {
                                                command_sender
                                                    .send(GdbCommand::AddBreakpoint { addr, kind })
                                                    .unwrap();
                                                match response_receiver
                                                    .lock()
                                                    .unwrap()
                                                    .recv()
                                                    .unwrap()
                                                {
                                                    GdbResponse::Ok => {
                                                        trace!("Sending OK");
                                                        send_packet(&mut writer, "OK");
                                                    }
                                                    GdbResponse::Error(e) => {
                                                        let response = format!("E{:02x}", e);
                                                        send_packet(&mut writer, &response);
                                                    }
                                                    _ => {}
                                                }
                                            } else {
                                                trace!("Malformed Z0 command");
                                                send_packet(&mut writer, "E01");
                                            }
                                        } else {
                                            trace!("Malformed Z0 command");
                                            send_packet(&mut writer, "E01");
                                        }
                                    } else {
                                        trace!("Unhandled GDB command: {}", core_command);
                                        send_packet(&mut writer, "");
                                    }
                                } else {
                                    trace!("Checksum incorrect, sending nack");
                                    writer.write_all(b"-").unwrap();
                                }
                            }
                            processed_bytes += packet_end;
                        } else {
                            // Incomplete packet
                            break;
                        }
                    } else {
                        // Incomplete packet
                        break;
                    }
                }
                _ => {
                    // Invalid start of packet
                    processed_bytes += 1;
                }
            }
        }
        buffer.drain(..processed_bytes);
    }
    info!("GDB client disconnected: {}", writer.peer_addr().unwrap());
}

/// Handles core GDB commands sent by the client, including:
///   * Adding breakpoints
///   * Reading and writing memory
///   * Reading and writing registers
///   * Continuing execution
pub fn handle_command(
    cmd: GdbCommand,
    vm: &mut VmManager,
    response_sender: &std::sync::mpsc::Sender<GdbResponse>,
) {
    trace!("Handling GDB command: {:?}", cmd);
    match cmd {
        GdbCommand::AddBreakpoint { addr, .. } => {
            vm.hooks.add_breakpoint(addr, &mut vm.vma).unwrap();
            response_sender.send(GdbResponse::Ok).unwrap();
        }
        GdbCommand::ReadMemory { addr, len } => {
            let mut data = vec![0; len];
            match vm.vma.read(addr, &mut data) {
                Ok(_) => response_sender.send(GdbResponse::MemoryData(data)).unwrap(),
                Err(_) => response_sender.send(GdbResponse::Error(1)).unwrap(),
            }
        }
        GdbCommand::WriteMemory { addr, data } => match vm.vma.write(addr, &data) {
            Ok(_) => response_sender.send(GdbResponse::Ok).unwrap(),
            Err(_) => response_sender.send(GdbResponse::Error(1)).unwrap(),
        },
        GdbCommand::ReadRegisters => {
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
                .send(GdbResponse::RegisterData(regs))
                .unwrap();
        }
        GdbCommand::WriteRegister { reg, val } => {
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
            response_sender.send(GdbResponse::Ok).unwrap();
        }
        GdbCommand::ReadRegister { reg } => {
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
                .send(GdbResponse::RegisterValue(val))
                .unwrap();
        }
        GdbCommand::Continue => {}
    }
}
