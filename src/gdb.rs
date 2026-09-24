use anyhow::Result;
use log::{debug, info, trace, warn};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::guest::{GuestEnd, GuestFault, Hooks, Resume, Stop, ThreadCx};
use crate::vm::{WatchKind, Watchpoint};
use applevisor as av;

#[derive(Debug, Clone)]
pub struct GdbFeatures {
    pub reverse_continue: bool,
    pub reverse_step: bool,
}

impl Default for GdbFeatures {
    fn default() -> Self {
        Self {
            reverse_continue: false,
            reverse_step: false,
        }
    }
}

// Bytes for each register in the order defined by TARGET_XML
// x0..x30 (31), sp, pc are 8 bytes; cpsr is 4 bytes
const GDB_REG_SIZES: [usize; 34] = [
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, // x0..x30
    8, // sp
    8, // pc
    4, // cpsr
];

// GDB Protocol Response Constants
const GDB_OK: &str = "OK";
const GDB_ERROR: &str = "E01";
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
fn build_supported_string(features: &GdbFeatures) -> String {
    let mut supported =
        "PacketSize=4000;swbreak+;hwbreak+;qXfer:features:read+;QStartNoAckMode+;vContSupported+"
            .to_string();

    if features.reverse_continue {
        supported.push_str(";ReverseContinue+");
    }

    if features.reverse_step {
        supported.push_str(";ReverseStep+");
    }

    supported
}

fn handle_qsupported(writer: &mut mio::net::TcpStream, features: &GdbFeatures) {
    let supported_string = build_supported_string(features);
    send_packet(writer, &supported_string);
}

fn handle_qstartnoackmode(writer: &mut mio::net::TcpStream) -> bool {
    trace!("Entering No-Ack mode");
    send_packet(writer, GDB_OK);
    true
}

fn handle_qc(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_CURRENT_THREAD);
}

fn handle_qxfer_features(writer: &mut mio::net::TcpStream) {
    let response = format!("l{}", TARGET_XML);
    send_packet(writer, &response);
}

fn handle_vcont_query(writer: &mut mio::net::TcpStream) {
    // Advertise minimal vCont actions we can map to existing handlers
    // Returning this enables LLDB to build a continue packet even if it ends up sending 'c'.
    // Include signal-carrying variants to avoid LLDB clearing packets when it wants to
    // deliver a signal along with continue/step.
    send_packet(writer, "vCont;c;C;s;S");
}

fn handle_vcont_run(command: &str, command_sender: &Sender<GdbCommand>) {
    // command examples:
    //  - "vCont;c" (all continue)
    //  - "vCont;c:1" (continue TID 1)
    //  - "vCont;s" or "vCont;s:1" (single step)
    //  - "vCont;C0b:1" (continue with signal)
    //  - "vCont;S0b:1" (step with signal)
    // For now we ignore thread ids and signals and choose the strongest action:
    // any ";s" or ";S" implies Step, otherwise any ";c" or ";C" implies Continue.
    if command.contains(";s")
        || command.starts_with("vCont;s")
        || command.contains(";S")
        || command.starts_with("vCont;S")
    {
        let _ = command_sender.send(GdbCommand::Step);
    } else {
        let _ = command_sender.send(GdbCommand::Continue);
    }
}

fn handle_status_query(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_SIGNAL_TRAP);
}

fn handle_qhostinfo(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_HOST_INFO);
}

fn handle_qprocessinfo(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_PROCESS_INFO);
}

fn handle_qfthreadinfo(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_THREAD_LIST);
}

fn handle_qsthreadinfo(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_THREAD_LIST_END);
}

fn handle_thread_suffix_commands(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_OK);
}

fn handle_unknown_command(writer: &mut mio::net::TcpStream) {
    send_packet(writer, GDB_EMPTY_RESPONSE);
}

// Register operation helpers
fn read_vm_register(vcpu: &av::Vcpu, gdb_reg: GdbRegister) -> Result<u64, ()> {
    match gdb_reg.to_av_reg() {
        Ok(av_reg) => vcpu.get_reg(av_reg).map_err(|_| ()),
        Err(sys_reg) => vcpu.get_sys_reg(sys_reg).map_err(|_| ()),
    }
}

fn write_vm_register(vcpu: &av::Vcpu, gdb_reg: GdbRegister, val: u64) -> Result<(), ()> {
    match gdb_reg.to_av_reg() {
        Ok(av_reg) => vcpu.set_reg(av_reg, val).map_err(|_| ()),
        Err(sys_reg) => vcpu.set_sys_reg(sys_reg, val).map_err(|_| ()),
    }
}

fn get_all_registers(vcpu: &av::Vcpu) -> Vec<u64> {
    let mut regs = Vec::with_capacity(34);
    for i in 0..=33 {
        if let Some(gdb_reg) = GdbRegister::from_index(i) {
            if let Ok(val) = read_vm_register(vcpu, gdb_reg) {
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
    writer: &mut mio::net::TcpStream,
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
        if hex_val.len() > 8 {
            send_packet(writer, GDB_ERROR);
            return;
        }
        let mut bytes = [0u8; 8];
        // GDB sends register contents in target endianness (little-endian here)
        // Accept variable sizes (e.g., cpsr is 4 bytes) and place into LSBs
        bytes[..hex_val.len()].copy_from_slice(&hex_val);
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
    writer: &mut mio::net::TcpStream,
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
                let size = if reg < GDB_REG_SIZES.len() {
                    GDB_REG_SIZES[reg]
                } else {
                    8
                };
                let mut reg_data = String::new();
                for byte in val.to_le_bytes()[..size].iter() {
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
    writer: &mut mio::net::TcpStream,
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
    writer: &mut mio::net::TcpStream,
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
    writer: &mut mio::net::TcpStream,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    command_sender.send(GdbCommand::ReadRegisters).unwrap();
    match response_receiver.lock().unwrap().recv().unwrap() {
        GdbResponse::RegisterData(regs) => {
            let mut reg_data = String::new();
            for (i, reg) in regs.iter().enumerate() {
                let size = if i < GDB_REG_SIZES.len() {
                    GDB_REG_SIZES[i]
                } else {
                    8
                };
                for byte in reg.to_le_bytes()[..size].iter() {
                    reg_data.push_str(&format!("{:02x}", byte));
                }
            }
            send_packet(writer, &reg_data);
        }
        _ => send_packet(writer, GDB_ERROR),
    }
}

/// `Z<type>,<addr>,<kind>` (insert) and `z<type>,<addr>,<kind>` (remove): breakpoints (types 0
/// and 1, both done however the target sees fit) and watchpoints (2 write, 3 read, 4 access,
/// with `kind` their length).
fn handle_breakpoint_packet(
    writer: &mut mio::net::TcpStream,
    command: &str,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
) {
    let insert = command.starts_with('Z');
    let parts: Vec<&str> = command[1..].split(',').collect();
    let parsed = match parts.as_slice() {
        [kind, addr, len] => (
            kind.parse::<u8>(),
            u64::from_str_radix(addr, 16),
            u64::from_str_radix(len, 16),
        ),
        _ => {
            trace!("Malformed breakpoint packet {command}");
            send_packet(writer, GDB_ERROR);
            return;
        }
    };
    let (Ok(kind), Ok(addr), Ok(len)) = parsed else {
        send_packet(writer, GDB_ERROR);
        return;
    };
    let watch_kind = match kind {
        2 => Some(WatchKind::Write),
        3 => Some(WatchKind::Read),
        4 => Some(WatchKind::Access),
        _ => None,
    };
    let command = match (kind, watch_kind, insert) {
        (0 | 1, _, true) => GdbCommand::AddBreakpoint { addr, kind: len },
        (0 | 1, _, false) => GdbCommand::RemoveBreakpoint { addr, kind: len },
        (_, Some(kind), true) => GdbCommand::AddWatchpoint { addr, len, kind },
        (_, Some(kind), false) => GdbCommand::RemoveWatchpoint { addr, len, kind },
        _ => {
            // Not supported: an empty reply says so.
            send_packet(writer, "");
            return;
        }
    };
    command_sender.send(command).unwrap();
    match response_receiver.lock().unwrap().recv().unwrap() {
        GdbResponse::Ok => send_packet(writer, GDB_OK),
        GdbResponse::Error(e) => send_packet(writer, &format!("E{:02x}", e)),
        _ => {}
    }
}

#[derive(Debug)]
pub enum GdbCommand {
    AddBreakpoint { addr: u64, kind: u64 },
    RemoveBreakpoint { addr: u64, kind: u64 },
    AddWatchpoint { addr: u64, len: u64, kind: WatchKind },
    RemoveWatchpoint { addr: u64, len: u64, kind: WatchKind },
    Continue,
    Step,
    Kill,
    BackwardsContinue,
    BackwardsStep,
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
    /// Stopped (with SIGTRAP) after an access to `addr`, watched with a `kind` watchpoint.
    Watchpoint { kind: WatchKind, addr: u64 },
    /// Going backwards, the beginning of the recording was reached.
    ReplayLogBegin,
    /// Going forwards, the end of the recording was reached.
    ReplayLogEnd,
    /// The guest exited with this status.
    Exited(u8),
}

/// Descriptors from here up are out of the way of a guest's, which share the host's table and
/// whose numbers must stay as they were recorded.
const HOST_FD_MIN: i32 = 1000;

/// Moves `socket`'s descriptor up out of the guest's way (see [`HOST_FD_MIN`]).
fn move_fd_high<T: std::os::fd::IntoRawFd + std::os::fd::FromRawFd>(socket: T) -> std::io::Result<T> {
    let fd = socket.into_raw_fd();
    let high = unsafe { nix::libc::fcntl(fd, nix::libc::F_DUPFD_CLOEXEC, HOST_FD_MIN) };
    let error = std::io::Error::last_os_error();
    unsafe { nix::libc::close(fd) };
    if high < 0 {
        return Err(error);
    }
    Ok(unsafe { T::from_raw_fd(high) })
}

fn start_gdb_server(
    port: u16,
    command_sender: Sender<GdbCommand>,
    response_receiver: Receiver<GdbResponse>,
    wait_sender: Option<Sender<()>>,
    features: GdbFeatures,
) -> Result<Sender<GdbNotification>> {
    let listener = move_fd_high(TcpListener::bind(("127.0.0.1", port))?)?;
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
                    let stream = match move_fd_high(stream) {
                        Ok(stream) => stream,
                        Err(e) => {
                            warn!("GDB connection failed: {}", e);
                            continue;
                        }
                    };
                    let command_sender = command_sender.clone();
                    let response_receiver = response_receiver.clone();
                    let notification_receiver = notification_receiver.clone();
                    let features_clone = features.clone();
                    thread::spawn(move || {
                        handle_connection(
                            stream,
                            command_sender,
                            response_receiver,
                            notification_receiver,
                            features_clone,
                        );
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
<reg name="x29" bitsize="64" type="uint64"/>
<reg name="x30" bitsize="64" type="uint64"/>
<reg name="sp" bitsize="64" type="uint64"/>
<reg name="pc" bitsize="64" type="uint64"/>
<reg name="cpsr" bitsize="32" type="uint32"/>
</feature>
</target>"#;

fn send_packet(writer: &mut mio::net::TcpStream, data: &str) {
    let checksum = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    let response = format!("${}#{:02x}", data, checksum);
    trace!("Sending packet: {}", response);
    writer.write_all(response.as_bytes()).unwrap();
}

fn process_gdb_command(
    command_str: &str,
    writer: &mut mio::net::TcpStream,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
    no_ack_mode: &mut bool,
    features: &GdbFeatures,
) {
    let core_command = command_str.split(';').next().unwrap_or("");

    if core_command.starts_with("qSupported") {
        handle_qsupported(writer, features);
    } else if command_str == "QStartNoAckMode" {
        *no_ack_mode = handle_qstartnoackmode(writer);
    } else if command_str == "qC" {
        handle_qc(writer);
    } else if command_str.starts_with("qXfer:features:read:target.xml") {
        handle_qxfer_features(writer);
    } else if core_command == "vCont?" {
        handle_vcont_query(writer);
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
    } else if core_command.starts_with("vCont") {
        // Use the full command string to inspect actions and thread qualifiers
        handle_vcont_run(command_str, command_sender);
    } else if core_command.starts_with('C') {
        // Legacy continue with signal, ignore signal value for now
        command_sender.send(GdbCommand::Continue).unwrap();
    } else if core_command.starts_with('S') {
        // Legacy step with signal, ignore signal value for now
        command_sender.send(GdbCommand::Step).unwrap();
    } else if core_command.starts_with('H') {
        // Handle thread selection commands (Hg / Hc). We don't track threads yet,
        // so just acknowledge to keep LLDB happy.
        // Examples: Hg0, Hg-1, Hc0, Hc-1, Hg<pid>, Hc<pid>
        send_packet(writer, GDB_OK);
    } else if core_command == "bc" {
        command_sender.send(GdbCommand::BackwardsContinue).unwrap();
    } else if core_command == "bs" {
        command_sender.send(GdbCommand::BackwardsStep).unwrap();
    } else if core_command == "k" {
        command_sender.send(GdbCommand::Kill).unwrap();
    } else if core_command == "QThreadSuffixSupported"
        || core_command == "QListThreadsInStopReply"
        || core_command == "qVAttachOrWaitSupported"
        || core_command == "QEnableErrorStrings"
    {
        handle_thread_suffix_commands(writer);
    } else if core_command.starts_with('Z') || core_command.starts_with('z') {
        handle_breakpoint_packet(writer, core_command, command_sender, response_receiver);
    } else {
        trace!("Unhandled GDB command: {}", core_command);
        handle_unknown_command(writer);
    }
}

fn process_packet(
    current_buffer: &[u8],
    writer: &mut mio::net::TcpStream,
    command_sender: &Sender<GdbCommand>,
    response_receiver: &Arc<Mutex<Receiver<GdbResponse>>>,
    no_ack_mode: &mut bool,
    features: &GdbFeatures,
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
                                features,
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
    stream: &mut mio::net::TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<bool, std::io::Error> {
    let mut read_buf = [0; 1024];
    match stream.read(&mut read_buf) {
        Ok(0) => {
            trace!("Connection closed");
            Ok(false) // Connection closed
        }
        Ok(n) => {
            buffer.extend_from_slice(&read_buf[..n]);
            Ok(true) // Data read successfully
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => {
            // No data available right now
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
    features: GdbFeatures,
) {
    debug!("New GDB client connected: {}", stream.peer_addr().unwrap());

    // Non-blocking, and polled rather than waited on with a kqueue: that would be a descriptor
    // where a guest's might be (see HOST_FD_MIN).
    if let Err(e) = stream.set_nonblocking(true) {
        warn!("GDB connection failed: {}", e);
        return;
    }
    let mut mio_stream = mio::net::TcpStream::from_std(stream);
    const POLL_INTERVAL: Duration = Duration::from_millis(1);

    let mut no_ack_mode = false;

    // GDB handshake - read the first byte (blocking behavior through polling)
    let mut handshake = [0; 1];
    loop {
        match mio_stream.read(&mut handshake) {
            Ok(0) => {
                trace!("Connection closed during handshake");
                return;
            }
            Ok(_) => break, // Got some data, continue
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(_) => {
                trace!("Handshake read error");
                return;
            }
        }
    }
    if &handshake != b"+" {
        trace!("Handshake failed");
        return;
    }
    trace!("Handshake successful, sending ack");
    mio_stream.write_all(b"+").unwrap();

    let mut buffer = Vec::new();

    loop {
        match read_and_buffer_data(&mut mio_stream, &mut buffer) {
            Ok(false) => {
                info!("GDB client disconnected");
                return;
            }
            Ok(true) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(_) => {
                info!("GDB connection error, closing");
                return;
            }
        }

        // Check for notifications (non-blocking)
        if let Ok(notification) = notification_receiver.lock().unwrap().try_recv() {
            match notification {
                GdbNotification::Stop(signal) => {
                    let signal_packet = format!("S{:02x}", signal);
                    send_packet(&mut mio_stream, &signal_packet);
                }
                GdbNotification::Watchpoint { kind, addr } => {
                    let reason = match kind {
                        WatchKind::Write => "watch",
                        WatchKind::Read => "rwatch",
                        WatchKind::Access => "awatch",
                    };
                    send_packet(&mut mio_stream, &format!("T05{reason}:{addr:x};"));
                }
                GdbNotification::ReplayLogBegin => {
                    send_packet(&mut mio_stream, "T05replaylog:begin;");
                }
                GdbNotification::ReplayLogEnd => {
                    send_packet(&mut mio_stream, "T05replaylog:end;");
                }
                GdbNotification::Exited(status) => {
                    send_packet(&mut mio_stream, &format!("W{status:02x}"));
                }
            }
        }

        // Process any buffered packets
        let mut processed_bytes = 0;
        while processed_bytes < buffer.len() {
            let current_buffer = &buffer[processed_bytes..];
            if current_buffer.is_empty() {
                break;
            }

            if let Some(bytes_consumed) = process_packet(
                current_buffer,
                &mut mio_stream,
                &command_sender,
                &response_receiver,
                &mut no_ack_mode,
                &features,
            ) {
                processed_bytes += bytes_consumed;
            } else {
                // Incomplete packet, need more data
                break;
            }
        }
        buffer.drain(..processed_bytes);
    }
}

/// A debugger connection: the commands it sends, and what to tell it.
pub struct GdbServer {
    commands: Receiver<GdbCommand>,
    responses: Sender<GdbResponse>,
    notifications: Sender<GdbNotification>,
}

impl GdbServer {
    /// Listens for a debugger on `port` (in the background).
    pub fn start(port: u16, features: GdbFeatures) -> Result<Self> {
        let (command_sender, commands) = std::sync::mpsc::channel();
        let (responses, response_receiver) = std::sync::mpsc::channel();
        let notifications =
            start_gdb_server(port, command_sender, response_receiver, None, features)?;
        Ok(Self {
            commands,
            responses,
            notifications,
        })
    }

    /// Waits for the debugger's next command; `None` once it's gone.
    pub fn recv(&self) -> Option<GdbCommand> {
        self.commands.recv().ok()
    }

    /// Tells the debugger the guest stopped (or ended).
    pub fn notify(&self, notification: GdbNotification) -> Result<()> {
        self.notifications
            .send(notification)
            .map_err(|_| anyhow::anyhow!("debugger connection gone"))
    }

    /// Answers a breakpoint, watchpoint, memory or register command from `t`'s thread, and
    /// returns true; returns false for anything else (e.g. resuming).
    pub fn handle(&self, command: &GdbCommand, t: &mut ThreadCx) -> bool {
        trace!("Handling GDB command: {:?}", command);
        let status = |result: Result<()>| match result {
            Ok(()) => GdbResponse::Ok,
            Err(err) => {
                debug!("GDB command failed: {err:#}");
                GdbResponse::Error(1)
            }
        };
        let response = match *command {
            GdbCommand::AddBreakpoint { addr, .. } => status(t.add_breakpoint(addr)),
            GdbCommand::RemoveBreakpoint { addr, .. } => status(t.remove_breakpoint(addr)),
            GdbCommand::AddWatchpoint { addr, len, kind } => {
                status(t.add_watchpoint(Watchpoint { addr, len, kind }))
            }
            GdbCommand::RemoveWatchpoint { addr, len, kind } => {
                status(t.remove_watchpoint(Watchpoint { addr, len, kind }))
            }
            GdbCommand::ReadMemory { addr, len } => {
                let mut data = vec![0; len];
                match t.memory().read(addr, &mut data) {
                    Ok(_) => GdbResponse::MemoryData(data),
                    Err(_) => GdbResponse::Error(1),
                }
            }
            GdbCommand::WriteMemory { addr, ref data } => status(t.memory().write_code(addr, data)),
            GdbCommand::ReadRegisters => GdbResponse::RegisterData(get_all_registers(t.vcpu())),
            GdbCommand::WriteRegister { reg, val } => {
                if let Some(gdb_reg) = GdbRegister::from_index(reg) {
                    let _ = write_vm_register(t.vcpu(), gdb_reg, val);
                }
                GdbResponse::Ok
            }
            GdbCommand::ReadRegister { reg } => GdbResponse::RegisterValue(
                GdbRegister::from_index(reg)
                    .and_then(|gdb_reg| read_vm_register(t.vcpu(), gdb_reg).ok())
                    .unwrap_or(0),
            ),
            GdbCommand::Continue
            | GdbCommand::Step
            | GdbCommand::Kill
            | GdbCommand::BackwardsContinue
            | GdbCommand::BackwardsStep => return false,
        };
        let _ = self.responses.send(response);
        true
    }
}

/// Hooks that let a debugger (see [`GdbServer`]) stop the guest at breakpoints, watchpoints and
/// faults, and step it (forwards).
pub struct GdbHooks {
    server: GdbServer,
    /// Stop before the guest's first instruction.
    wait_at_start: bool,
}

impl GdbHooks {
    pub fn new(port: u16, wait_at_start: bool) -> Result<Self> {
        Ok(Self {
            server: GdbServer::start(port, GdbFeatures::default())?,
            wait_at_start,
        })
    }

    /// Takes the debugger's commands until it resumes the guest.
    fn wait(&mut self, t: &mut ThreadCx) -> Result<Resume> {
        while let Some(command) = self.server.recv() {
            if self.server.handle(&command, t) {
                continue;
            }
            return Ok(match command {
                GdbCommand::Continue => Resume::Continue,
                GdbCommand::Step => Resume::Step,
                GdbCommand::Kill => Resume::End(killed()),
                _ => {
                    warn!("{command:?} isn't supported");
                    self.server.notify(GdbNotification::Stop(5))?;
                    continue;
                }
            });
        }
        Ok(Resume::Continue)
    }
}

fn killed() -> GuestEnd {
    GuestEnd::Crashed {
        signal: nix::sys::signal::Signal::SIGKILL,
        reason: "killed by the debugger".into(),
    }
}

impl Hooks for GdbHooks {
    fn start(&mut self, t: &mut ThreadCx) -> Result<Resume> {
        if !self.wait_at_start {
            return Ok(Resume::Continue);
        }
        info!("Waiting for GDB connection...");
        self.wait(t)
    }

    fn stopped(&mut self, t: &mut ThreadCx, stop: &Stop) -> Result<Resume> {
        self.server.notify(match *stop {
            Stop::Watchpoint { addr, kind } => GdbNotification::Watchpoint { kind, addr },
            Stop::Breakpoint { .. } | Stop::Step | Stop::Scheduled => GdbNotification::Stop(5),
        })?;
        self.wait(t)
    }

    fn fault(&mut self, t: &mut ThreadCx, fault: &GuestFault) -> Result<Resume> {
        self.server
            .notify(GdbNotification::Stop(fault.signal() as u8))?;
        // A debugger can inspect the guest, but not recover it.
        match self.wait(t)? {
            Resume::End(end) => Ok(Resume::End(end)),
            _ => Ok(Resume::End(fault.crash())),
        }
    }

    fn ending(&mut self, _t: &mut ThreadCx, end: &GuestEnd) -> Result<Resume> {
        let notification = match end {
            GuestEnd::Exited(status) => GdbNotification::Exited(*status as u8),
            GuestEnd::Crashed { signal, .. } => GdbNotification::Stop(*signal as u8),
        };
        let _ = self.server.notify(notification);
        Ok(Resume::End(end.clone()))
    }
}
