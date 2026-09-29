//! End-to-end tests of the examples besides strace (which runs the guest programs in
//! guests.rs).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn ebpf_syscall_guard_denies_what_its_policy_says() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ebpf_syscall_guard");
    std::fs::create_dir_all(&dir).unwrap();
    // The policy denies opening ./test.txt, and nothing else.
    std::fs::write(dir.join("test.txt"), "denied\n").unwrap();
    std::fs::write(dir.join("other.txt"), "allowed\n").unwrap();
    let policy =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/ebpf_syscall_guard/policy_open_deny.asm");
    let cat = |file: &str| {
        let child = common::spawn(
            Command::new(common::example("ebpf_syscall_guard"))
                .arg("--bpf-asm")
                .arg(&policy)
                .args(["/bin/cat", file])
                .current_dir(&dir),
        );
        common::wait_with_timeout(child)
    };

    let denied = cat("./test.txt");
    common::assert_stdout(&denied, 1, &[]);
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(stderr.contains("Operation not permitted"), "{stderr}");
    common::assert_stdout(&cat("./other.txt"), 0, &["allowed"]);
}

/// Just enough of a GDB remote protocol client.
struct Gdb {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Gdb {
    fn connect(port: u16) -> Self {
        let deadline = Instant::now() + common::TIMEOUT;
        let stream = loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(err) => panic!("connecting to the stub: {err}"),
            }
        };
        stream.set_read_timeout(Some(common::TIMEOUT)).unwrap();
        let mut gdb = Self {
            stream,
            buffer: Vec::new(),
        };
        gdb.stream.write_all(b"+").unwrap();
        assert_eq!(gdb.request("QStartNoAckMode"), "OK");
        gdb
    }

    fn send(&mut self, packet: &str) {
        let checksum = packet.bytes().fold(0u8, |sum, b| sum.wrapping_add(b));
        self.stream
            .write_all(format!("${packet}#{checksum:02x}").as_bytes())
            .unwrap();
    }

    fn recv(&mut self) -> String {
        loop {
            while matches!(self.buffer.first(), Some(b'+' | b'-')) {
                self.buffer.remove(0);
            }
            if let Some(end) = self.buffer.iter().position(|&b| b == b'#') {
                if self.buffer.len() >= end + 3 {
                    assert_eq!(self.buffer[0], b'$');
                    let packet = String::from_utf8(self.buffer[1..end].to_vec()).unwrap();
                    self.buffer.drain(..end + 3);
                    return packet;
                }
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).expect("reading from the stub");
            assert!(n > 0, "the stub hung up");
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }

    fn request(&mut self, packet: &str) -> String {
        self.send(packet);
        self.recv()
    }

    fn read_u64(&mut self, addr: u64) -> u64 {
        u64::from_le_bytes(hex_bytes(&self.request(&format!("m{addr:x},8"))))
    }

    fn register(&mut self, index: usize) -> u64 {
        u64::from_le_bytes(hex_bytes(&self.request(&format!("p{index:x}"))))
    }
}

fn hex_bytes<const N: usize>(hex: &str) -> [u8; N] {
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Where `symbol` is in `binary`, relative to its (__TEXT's) start.
fn symbol_offset(binary: &Path, symbol: &str) -> u64 {
    let output = Command::new("nm").arg(binary).output().unwrap();
    let nm = String::from_utf8(output.stdout).unwrap();
    let address = nm
        .lines()
        .find_map(|line| line.strip_suffix(&format!(" T {symbol}")))
        .unwrap_or_else(|| panic!("no {symbol} in {nm}"));
    const TEXT_BASE: u64 = 0x1_0000_0000;
    u64::from_str_radix(address, 16).unwrap() - TEXT_BASE
}

#[test]
fn gdb_stub_stops_at_breakpoints_and_steps() {
    const PC: usize = 32;
    const SP: usize = 31;
    let guest = common::guest("breakpoints");
    let port = free_port();
    let child = common::spawn(
        Command::new(common::example("gdb_stub"))
            .args(["--gdb-port", &port.to_string(), "--gdb-wait"])
            .arg(&guest),
    );
    let mut gdb = Gdb::connect(port);

    // Stopped before the first instruction, where (as from the kernel) the stack starts with the
    // executable's Mach-O header's address.
    let sp = gdb.register(SP);
    let header = gdb.read_u64(sp);
    assert_eq!(gdb.read_u64(header) as u32, 0xfeedfacf, "not a Mach-O header");
    let add_one = header + symbol_offset(&guest, "_add_one");

    assert_eq!(gdb.request(&format!("Z0,{add_one:x},4")), "OK");
    for expected in 0..3 {
        assert_eq!(gdb.request("c"), "S05");
        assert_eq!(gdb.register(PC), add_one);
        assert_eq!(gdb.register(0), expected);
    }
    assert_eq!(gdb.request("s"), "S05");
    assert_eq!(gdb.register(PC), add_one + 4);
    assert_eq!(gdb.request(&format!("z0,{add_one:x},4")), "OK");
    assert_eq!(gdb.request("c"), "W00");

    let output = common::wait_with_timeout(child);
    common::assert_stdout(&output, 0, &["value=3"]);
}
