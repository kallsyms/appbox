use anyhow::Result;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

#[derive(Debug)]
pub enum GdbCommand {
    AddBreakpoint { addr: u64, kind: u64 },
}

#[derive(Debug)]
pub enum GdbResponse {
    Ok,
    Error(u8),
}

pub fn start_gdb_server(
    port: u16,
    command_sender: Sender<GdbCommand>,
    response_receiver: Receiver<GdbResponse>,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("GDB server listening on port {}", port);

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let command_sender = command_sender.clone();
                    // This will move the receiver, so only one client is supported for now.
                    thread::spawn(move || {
                        handle_connection(stream, command_sender, response_receiver);
                    });
                }
                Err(e) => {
                    eprintln!("GDB connection failed: {}", e);
                }
            }
        }
    });

    Ok(())
}

fn handle_connection(
    stream: TcpStream,
    command_sender: Sender<GdbCommand>,
    response_receiver: Receiver<GdbResponse>,
) {
    println!("New GDB client connected: {}", stream.peer_addr().unwrap());
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;

    // GDB remote protocol starts with an ack
    writer.write_all(b"+").unwrap();

    loop {
        let mut packet = Vec::new();
        // Read until '#'
        if reader.read_until(b'#', &mut packet).unwrap() == 0 {
            break; // Connection closed
        }

        // Packet should start with '$'
        if packet.get(0) != Some(&b'$') {
            continue;
        }

        // Read checksum (2 bytes)
        let mut checksum_bytes = [0; 2];
        if reader.read_exact(&mut checksum_bytes).is_err() {
            break; // Connection closed
        }

        let data = &packet[1..packet.len() - 1];
        let checksum_str = std::str::from_utf8(&checksum_bytes).unwrap();
        if let Ok(received_checksum) = u8::from_str_radix(checksum_str, 16) {
            let calculated_checksum = data.iter().fold(0, |acc, &b| acc.wrapping_add(b));

            if calculated_checksum == received_checksum {
                writer.write_all(b"+").unwrap();
                let command_str = std::str::from_utf8(data).unwrap();
                if command_str.starts_with("Z0,") {
                    let parts: Vec<&str> = command_str[3..].split(',').collect();
                    if parts.len() == 2 {
                        if let (Ok(addr), Ok(kind)) = (
                            u64::from_str_radix(parts[0], 16),
                            u64::from_str_radix(parts[1], 16),
                        ) {
                            command_sender
                                .send(GdbCommand::AddBreakpoint { addr, kind })
                                .unwrap();
                            match response_receiver.recv().unwrap() {
                                GdbResponse::Ok => {
                                    writer.write_all(b"$OK#00").unwrap();
                                }
                                GdbResponse::Error(e) => {
                                    let response = format!("$E{:02x}", e);
                                    let checksum = response
                                        .bytes()
                                        .skip(1)
                                        .fold(0, |acc, b| acc.wrapping_add(b));
                                    let final_response = format!("{}#{:02x}", response, checksum);
                                    writer.write_all(final_response.as_bytes()).unwrap();
                                }
                            }
                        } else {
                            // Malformed command
                            writer.write_all(b"$E01#00").unwrap();
                        }
                    } else {
                        // Malformed command
                        writer.write_all(b"$E01#00").unwrap();
                    }
                }
            } else {
                writer.write_all(b"-").unwrap();
            }
        }
    }
    println!("GDB client disconnected: {}", writer.peer_addr().unwrap());
}
