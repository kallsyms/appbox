use anyhow::Result;
use log::{debug, info, trace, warn};
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::applevisor as av;
use crate::vm::VmManager;

// GDB Protocol Response Constants
const GDB_OK: &str = "OK";
const GDB_ERROR: &str = "E01";
const GDB_SUPPORTED: &str =
    "PacketSize=4000;swbreak+;hwbreak+;qXfer:features:read+;QStartNoAckMode+";
const GDB_CURRENT_THREAD: &str = "QC1";
const GDB_SIGNAL_TRAP: &str = "S05";
const GDB_HOST_INFO: &str =
    "cputype:16777228;cpusubtype:1;ostype:unknown;vendor:unknown;endian:little;ptrsize:8;";
const GDB_PROCESS_INFO: &str = "pid:1;";
const GDB_THREAD_LIST: &str = "m1";
const GDB_THREAD_LIST_END: &str = "l";
const GDB_EMPTY_RESPONSE: &str = "";

// Register indices for GDB protocol
#[repr(usize)]
#[derive(Debug, Clone, Copy)]
enum GdbRegister {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    FP = 29,
    LR = 30,
    SP = 31,
    PC = 32,
    CPSR = 33,
}

impl GdbRegister {
    fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::X0),
            1 => Some(Self::X1),
            2 => Some(Self::X2),
            3 => Some(Self::X3),
            4 => Some(Self::X4),
            5 => Some(Self::X5),
            6 => Some(Self::X6),
            7 => Some(Self::X7),
            8 => Some(Self::X8),
            9 => Some(Self::X9),
            10 => Some(Self::X10),
            11 => Some(Self::X11),
            12 => Some(Self::X12),
            13 => Some(Self::X13),
            14 => Some(Self::X14),
            15 => Some(Self::X15),
            16 => Some(Self::X16),
            17 => Some(Self::X17),
            18 => Some(Self::X18),
            19 => Some(Self::X19),
            20 => Some(Self::X20),
            21 => Some(Self::X21),
            22 => Some(Self::X22),
            23 => Some(Self::X23),
            24 => Some(Self::X24),
            25 => Some(Self::X25),
            26 => Some(Self::X26),
            27 => Some(Self::X27),
            28 => Some(Self::X28),
            29 => Some(Self::FP),
            30 => Some(Self::LR),
            31 => Some(Self::SP),
            32 => Some(Self::PC),
            33 => Some(Self::CPSR),
            _ => None,
        }
    }

    fn to_av_reg(self) -> Result<av::Reg, av::SysReg> {
        match self {
            Self::X0 => Ok(av::Reg::X0),
            Self::X1 => Ok(av::Reg::X1),
            Self::X2 => Ok(av::Reg::X2),
            Self::X3 => Ok(av::Reg::X3),
            Self::X4 => Ok(av::Reg::X4),
            Self::X5 => Ok(av::Reg::X5),
            Self::X6 => Ok(av::Reg::X6),
            Self::X7 => Ok(av::Reg::X7),
            Self::X8 => Ok(av::Reg::X8),
            Self::X9 => Ok(av::Reg::X9),
            Self::X10 => Ok(av::Reg::X10),
            Self::X11 => Ok(av::Reg::X11),
            Self::X12 => Ok(av::Reg::X12),
            Self::X13 => Ok(av::Reg::X13),
            Self::X14 => Ok(av::Reg::X14),
            Self::X15 => Ok(av::Reg::X15),
            Self::X16 => Ok(av::Reg::X16),
            Self::X17 => Ok(av::Reg::X17),
            Self::X18 => Ok(av::Reg::X18),
            Self::X19 => Ok(av::Reg::X19),
            Self::X20 => Ok(av::Reg::X20),
            Self::X21 => Ok(av::Reg::X21),
            Self::X22 => Ok(av::Reg::X22),
            Self::X23 => Ok(av::Reg::X23),
            Self::X24 => Ok(av::Reg::X24),
            Self::X25 => Ok(av::Reg::X25),
            Self::X26 => Ok(av::Reg::X26),
            Self::X27 => Ok(av::Reg::X27),
            Self::X28 => Ok(av::Reg::X28),
            Self::FP => Ok(av::Reg::FP),
            Self::LR => Ok(av::Reg::LR),
            Self::SP => Err(av::SysReg::SP_EL0),
            Self::PC => Ok(av::Reg::PC),
            Self::CPSR => Ok(av::Reg::CPSR),
        }
    }
}

// GDB Command Handlers
fn handle_qsupported(writer: &mut TcpStream) {
    send_packet(writer, GDB_SUPPORTED);
}

fn handle_qstartnoackmode(writer: &mut TcpStream) -> bool {
    trace!("Entering No-Ack mode");
    send_packet(writer, GDB_OK);
    true
}

fn handle_qc(writer: &mut TcpStream) {
    send_packet(writer, GDB_CURRENT_THREAD);
}

fn handle_qxfer_features(writer: &mut TcpStream) {
    let response = format!("l{}", TARGET_XML);
    send_packet(writer, &response);
}

fn handle_status_query(writer: &mut TcpStream) {
    send_packet(writer, GDB_SIGNAL_TRAP);
}

fn handle_qhostinfo(writer: &mut TcpStream) {
    send_packet(writer, GDB_HOST_INFO);
}

fn handle_qprocessinfo(writer: &mut TcpStream) {
    send_packet(writer, GDB_PROCESS_INFO);
}

fn handle_qfthreadinfo(writer: &mut TcpStream) {
    send_packet(writer, GDB_THREAD_LIST);
}

fn handle_qsthreadinfo(writer: &mut TcpStream) {
    send_packet(writer, GDB_THREAD_LIST_END);
}

fn handle_thread_suffix_commands(writer: &mut TcpStream) {
    send_packet(writer, GDB_OK);
}

fn handle_unknown_command(writer: &mut TcpStream) {
    send_packet(writer, GDB_EMPTY_RESPONSE);
}

// Register operation helpers
fn read_vm_register(vm: &mut VmManager, gdb_reg: GdbRegister) -> Result<u64, ()> {
    match gdb_reg.to_av_reg() {
        Ok(av_reg) => vm.vcpu.get_reg(av_reg).map_err(|_| ()),
        Err(sys_reg) => vm.vcpu.get_sys_reg(sys_reg).map_err(|_| ()),
    }
}

fn write_vm_register(vm: &mut VmManager, gdb_reg: GdbRegister, val: u64) -> Result<(), ()> {
    match gdb_reg.to_av_reg() {
        Ok(av_reg) => vm.vcpu.set_reg(av_reg, val).map_err(|_| ()),
        Err(sys_reg) => vm.vcpu.set_sys_reg(sys_reg, val).map_err(|_| ()),
    }
}

fn get_all_registers(vm: &mut VmManager) -> Vec<u64> {
    let mut regs = Vec::with_capacity(34);
    for i in 0..=33 {
        if let Some(gdb_reg) = GdbRegister::from_index(i) {
            if let Ok(val) = read_vm_register(vm, gdb_reg) {
                regs.push(val);
            } else {
                regs.push(0);
            }
        } else {
            regs.push(0);
        }
    }
    regs
}

// Complex command handlers
fn handle_register_write(
    writer: &mut TcpStream,
    command: &str,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    let parts: Vec<&str> = command[1..].split('=').collect();
    if parts.len() != 2 {
        send_packet(writer, GDB_ERROR);
        return;
    }

    let (reg_result, hex_result) = (usize::from_str_radix(parts[0], 16), hex::decode(parts[1]));

    if let (Ok(reg), Ok(hex_val)) = (reg_result, hex_result) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hex_val);
        let val = u64::from_le_bytes(bytes);

        command_sender
            .send(GdbCommand::WriteRegister { reg, val })
            .unwrap();
        match response_receiver.lock().unwrap().recv().unwrap() {
            GdbResponse::Ok => send_packet(writer, GDB_OK),
            _ => send_packet(writer, GDB_ERROR),
        }
    } else {
        send_packet(writer, GDB_ERROR);
    }
}

fn handle_register_read(
    writer: &mut TcpStream,
    command: &str,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    if let Ok(reg) = usize::from_str_radix(&command[1..], 16) {
        command_sender
            .send(GdbCommand::ReadRegister { reg })
            .unwrap();
        match response_receiver.lock().unwrap().recv().unwrap() {
            GdbResponse::RegisterValue(val) => {
                let mut reg_data = String::new();
                for byte in val.to_le_bytes() {
                    reg_data.push_str(&format!("{:02x}", byte));
                }
                send_packet(writer, &reg_data);
            }
            _ => send_packet(writer, GDB_ERROR),
        }
    } else {
        send_packet(writer, GDB_ERROR);
    }
}

fn handle_memory_read(
    writer: &mut TcpStream,
    command: &str,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    let parts: Vec<&str> = command[1..].split(',').collect();
    if parts.len() != 2 {
        send_packet(writer, GDB_ERROR);
        return;
    }

    let (addr_result, len_result) = (
        u64::from_str_radix(parts[0], 16),
        usize::from_str_radix(parts[1], 16),
    );

    if let (Ok(addr), Ok(len)) = (addr_result, len_result) {
        command_sender
            .send(GdbCommand::ReadMemory { addr, len })
            .unwrap();
        match response_receiver.lock().unwrap().recv().unwrap() {
            GdbResponse::MemoryData(data) => {
                let hex_data = data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                send_packet(writer, &hex_data);
            }
            _ => send_packet(writer, GDB_ERROR),
        }
    } else {
        send_packet(writer, GDB_ERROR);
    }
}

fn handle_memory_write(
    writer: &mut TcpStream,
    command: &str,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    let parts: Vec<&str> = command[1..].split(|c| c == ',' || c == ':').collect();
    if parts.len() != 3 {
        send_packet(writer, GDB_ERROR);
        return;
    }

    let (addr_result, len_result) = (
        u64::from_str_radix(parts[0], 16),
        usize::from_str_radix(parts[1], 16),
    );

    if let (Ok(addr), Ok(len)) = (addr_result, len_result) {
        if let Ok(data) = hex::decode(parts[2]) {
            if data.len() == len {
                command_sender
                    .send(GdbCommand::WriteMemory { addr, data })
                    .unwrap();
                match response_receiver.lock().unwrap().recv().unwrap() {
                    GdbResponse::Ok => send_packet(writer, GDB_OK),
                    _ => send_packet(writer, GDB_ERROR),
                }
            } else {
                send_packet(writer, GDB_ERROR);
            }
        } else {
            send_packet(writer, GDB_ERROR);
        }
    } else {
        send_packet(writer, GDB_ERROR);
    }
}

fn handle_all_registers(
    writer: &mut TcpStream,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    command_sender.send(GdbCommand::ReadRegisters).unwrap();
    match response_receiver.lock().unwrap().recv().unwrap() {
        GdbResponse::RegisterData(regs) => {
            let mut reg_data = String::new();
            for reg in regs {
                for byte in reg.to_le_bytes() {
                    reg_data.push_str(&format!("{:02x}", byte));
                }
            }
            send_packet(writer, &reg_data);
        }
        _ => send_packet(writer, GDB_ERROR),
    }
}

fn handle_breakpoint(
    writer: &mut TcpStream,
    command: &str,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    let parts: Vec<&str> = command[3..].split(',').collect();
    if parts.len() != 2 {
        trace!("Malformed Z0 command");
        send_packet(writer, GDB_ERROR);
        return;
    }

    let (addr_result, kind_result) = (
        u64::from_str_radix(parts[0], 16),
        u64::from_str_radix(parts[1], 16),
    );

    if let (Ok(addr), Ok(kind)) = (addr_result, kind_result) {
        command_sender
            .send(GdbCommand::AddBreakpoint { addr, kind })
            .unwrap();
        match response_receiver.lock().unwrap().recv().unwrap() {
            GdbResponse::Ok => {
                trace!("Sending OK");
                send_packet(writer, GDB_OK);
            }
            GdbResponse::Error(e) => {
                let response = format!("E{:02x}", e);
                send_packet(writer, &response);
            }
            _ => {}
        }
    } else {
        trace!("Malformed Z0 command");
        send_packet(writer, GDB_ERROR);
    }
}

#[derive(Debug)]
pub enum GdbCommand {
    AddBreakpoint { addr: u64, kind: u64 },
    Continue,
    Step,
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

#[derive(Debug)]
pub enum GdbNotification {
    Stop(u8), // Signal number (5 for SIGTRAP, 11 for SIGSEGV, etc.)
}

pub fn start_gdb_server(
    port: u16,
    command_sender: Sender<GdbCommand>,
    response_receiver: Receiver<GdbResponse>,
    wait_sender: Option<Sender<()>>,
) -> Result<Sender<GdbNotification>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    info!("GDB server listening on port {}", port);
    let response_receiver = Arc::new(Mutex::new(response_receiver));
    
    let (notification_sender, notification_receiver) = std::sync::mpsc::channel();
    let notification_receiver = Arc::new(Mutex::new(notification_receiver));

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Some(ref sender) = wait_sender {
                sender.send(()).unwrap();
            }
            match stream {
                Ok(stream) => {
                    let command_sender = command_sender.clone();
                    let response_receiver = response_receiver.clone();
                    let notification_receiver = notification_receiver.clone();
                    thread::spawn(move || {
                        handle_connection(stream, command_sender, response_receiver, notification_receiver);
                    });
                }
                Err(e) => {
                    warn!("GDB connection failed: {}", e);
                }
            }
        }
    });

    Ok(notification_sender)
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

fn process_gdb_command(
    command_str: &str,
    writer: &mut TcpStream,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
    no_ack_mode: &mut bool,
) {
    let core_command = command_str.split(';').next().unwrap_or("");

    if core_command.starts_with("qSupported") {
        handle_qsupported(writer);
    } else if command_str == "QStartNoAckMode" {
        *no_ack_mode = handle_qstartnoackmode(writer);
    } else if command_str == "qC" {
        handle_qc(writer);
    } else if command_str.starts_with("qXfer:features:read:target.xml") {
        handle_qxfer_features(writer);
    } else if command_str == "?" {
        handle_status_query(writer);
    } else if command_str == "qHostInfo" {
        handle_qhostinfo(writer);
    } else if command_str == "qProcessInfo" {
        handle_qprocessinfo(writer);
    } else if core_command == "qfThreadInfo" {
        handle_qfthreadinfo(writer);
    } else if core_command == "qsThreadInfo" {
        handle_qsthreadinfo(writer);
    } else if core_command == "g" {
        handle_all_registers(writer, command_sender, response_receiver);
    } else if core_command.starts_with('P') {
        handle_register_write(writer, core_command, command_sender, response_receiver);
    } else if core_command.starts_with('p') {
        handle_register_read(writer, core_command, command_sender, response_receiver);
    } else if core_command.starts_with('m') {
        handle_memory_read(writer, core_command, command_sender, response_receiver);
    } else if core_command.starts_with('M') {
        handle_memory_write(writer, core_command, command_sender, response_receiver);
    } else if core_command.starts_with('x') {
        send_packet(writer, GDB_ERROR);
    } else if core_command == "c" {
        command_sender.send(GdbCommand::Continue).unwrap();
    } else if core_command == "s" {
        command_sender.send(GdbCommand::Step).unwrap();
    } else if core_command == "QThreadSuffixSupported"
        || core_command == "QListThreadsInStopReply"
        || core_command == "qVAttachOrWaitSupported"
        || core_command == "QEnableErrorStrings"
    {
        handle_thread_suffix_commands(writer);
    } else if core_command.starts_with("Z0,") {
        handle_breakpoint(writer, core_command, command_sender, response_receiver);
    } else {
        trace!("Unhandled GDB command: {}", core_command);
        handle_unknown_command(writer);
    }
}

fn process_packet(
    current_buffer: &[u8],
    writer: &mut TcpStream,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
    no_ack_mode: &mut bool,
) -> Option<usize> {
    match current_buffer[0] {
        b'+' => {
            trace!("Received ack");
            Some(1)
        }
        b'-' => {
            trace!("Received nack");
            Some(1)
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
                            if !*no_ack_mode {
                                trace!("Checksum correct, sending ack");
                                writer.write_all(b"+").unwrap();
                            }
                            let command_str = std::str::from_utf8(packet_data).unwrap();
                            trace!("Received command: {}", command_str);

                            process_gdb_command(
                                command_str,
                                writer,
                                command_sender,
                                response_receiver,
                                no_ack_mode,
                            );
                        } else {
                            trace!("Checksum incorrect, sending nack");
                            writer.write_all(b"-").unwrap();
                        }
                    }
                    Some(packet_end)
                } else {
                    // Incomplete packet
                    None
                }
            } else {
                // Incomplete packet
                None
            }
        }
        _ => {
            // Invalid start of packet
            Some(1)
        }
    }
}

fn read_and_buffer_data(
    reader: &mut BufReader<TcpStream>,
    buffer: &mut Vec<u8>,
) -> Result<bool, std::io::Error> {
    let mut read_buf = [0; 1024];
    match reader.read(&mut read_buf) {
        Ok(0) => {
            trace!("Connection closed");
            Ok(false) // Connection closed
        }
        Ok(n) => {
            buffer.extend_from_slice(&read_buf[..n]);
            Ok(true) // Data read successfully
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => {
            // No data available, sleep briefly and continue
            thread::sleep(Duration::from_millis(10));
            Err(e)
        }
        Err(e) => {
            warn!("GDB read error: {}", e);
            Err(e)
        }
    }
}

fn handle_connection(
    stream: TcpStream,
    command_sender: Sender<GdbCommand>,
    response_receiver: Arc<Mutex<Receiver<GdbResponse>>>,
    notification_receiver: Arc<Mutex<Receiver<GdbNotification>>>,
) {
    debug!("New GDB client connected: {}", stream.peer_addr().unwrap());
    stream.set_nonblocking(true).unwrap();
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
        // Check for notifications first (non-blocking)
        if let Ok(notification) = notification_receiver.lock().unwrap().try_recv() {
            match notification {
                GdbNotification::Stop(signal) => {
                    let signal_packet = format!("S{:02x}", signal);
                    send_packet(&mut writer, &signal_packet);
                }
            }
        }
        
        match read_and_buffer_data(&mut reader, &mut buffer) {
            Ok(false) => {
                // Connection closed
                break;
            }
            Ok(true) => {
                // Data read successfully, continue to process packets
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // No data available, continue to check notifications
                continue;
            }
            Err(_) => {
                // Read error, close connection
                break;
            }
        }

        let mut processed_bytes = 0;
        while processed_bytes < buffer.len() {
            let current_buffer = &buffer[processed_bytes..];
            if current_buffer.is_empty() {
                break;
            }

            if let Some(bytes_consumed) = process_packet(
                current_buffer,
                &mut writer,
                &command_sender,
                &response_receiver,
                &mut no_ack_mode,
            ) {
                processed_bytes += bytes_consumed;
            } else {
                // Incomplete packet, need more data
                break;
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
            let regs = get_all_registers(vm);
            response_sender
                .send(GdbResponse::RegisterData(regs))
                .unwrap();
        }
        GdbCommand::WriteRegister { reg, val } => {
            if let Some(gdb_reg) = GdbRegister::from_index(reg) {
                let _ = write_vm_register(vm, gdb_reg, val);
            }
            response_sender.send(GdbResponse::Ok).unwrap();
        }
        GdbCommand::ReadRegister { reg } => {
            let val = if let Some(gdb_reg) = GdbRegister::from_index(reg) {
                read_vm_register(vm, gdb_reg).unwrap_or(0)
            } else {
                0
            };
            response_sender
                .send(GdbResponse::RegisterValue(val))
                .unwrap();
        }
        GdbCommand::Continue => {}
        GdbCommand::Step => {}
    }
}

/// Send a SIGSEGV signal to the GDB client to indicate a segmentation fault
pub fn send_sigsegv(sender: &Sender<GdbNotification>) {
    sender.send(GdbNotification::Stop(11)).unwrap();
}
