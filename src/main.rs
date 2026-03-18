use pcap::{Capture, Device};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl+C handler");

    let device = Device::lookup()
        .expect("Failed to look up default device")
        .expect("No default device found");
    println!("Capturing on device: {}", device.name);

    let mut cap = Capture::from_device(device)
        .expect("Failed to open device")
        .promisc(true)
        .snaplen(96) // only need headers
        .timeout(100) // 100ms read timeout so we can check the running flag
        .open()
        .expect("Failed to start capture");

    let mut dest_ips: BTreeMap<IpAddr, u64> = BTreeMap::new();

    println!("Monitoring outbound destination IPs... Press Ctrl+C to stop.\n");

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(dest) = parse_dest_ip(packet.data) {
                    *dest_ips.entry(dest).or_insert(0) += 1;
                    print_table(&dest_ips);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Capture error: {e}");
                break;
            }
        }
    }

    println!("\n\n--- Final Summary ---");
    print_table(&dest_ips);
    println!("\nTotal unique IPs: {}", dest_ips.len());
}

/// Parse the destination IP from a raw Ethernet frame.
/// Supports IPv4 and IPv6.
fn parse_dest_ip(data: &[u8]) -> Option<IpAddr> {
    // Ethernet header is 14 bytes: [dst MAC 6][src MAC 6][EtherType 2]
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0800 => {
            // IPv4
            let ip_start = 14;
            if data.len() < ip_start + 20 {
                return None;
            }
            let dst: [u8; 4] = data[ip_start + 16..ip_start + 20].try_into().ok()?;
            Some(IpAddr::from(dst))
        }
        0x86DD => {
            // IPv6
            let ip_start = 14;
            if data.len() < ip_start + 40 {
                return None;
            }
            let dst: [u8; 16] = data[ip_start + 24..ip_start + 40].try_into().ok()?;
            Some(IpAddr::from(dst))
        }
        _ => None,
    }
}

fn print_table(ips: &BTreeMap<IpAddr, u64>) {
    // Move cursor up to overwrite previous table, then clear to end of screen
    let count = ips.len();
    if count > 0 {
        // Move up by (count + 1) lines (header + rows)
        print!("\x1b[{}A", count + 1);
    }
    print!("\x1b[J"); // clear from cursor to end of screen

    println!("{:<45} {:>10}", "Destination IP", "Packets");
    for (ip, pkt_count) in ips {
        println!("{:<45} {:>10}", ip, pkt_count);
    }
}
