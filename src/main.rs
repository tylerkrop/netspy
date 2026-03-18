use pcap::{Capture, Device};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
struct IpEntry {
    packets: u64,
    hostname: String,
    mapping: &'static str, // "dns" or "manual"
}

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
        .snaplen(65535) // full packet for DNS payloads
        .timeout(100)
        .open()
        .expect("Failed to start capture");

    // IP -> entry (packets, hostname, mapping type)
    let mut dest_ips: BTreeMap<IpAddr, IpEntry> = BTreeMap::new();
    // DNS-learned mappings: IP -> hostname
    let mut dns_map: BTreeMap<IpAddr, String> = BTreeMap::new();

    println!("Monitoring outbound destination IPs... Press Ctrl+C to stop.\n");

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                // Try to extract DNS answer records from this packet
                if let Some(mappings) = parse_dns_answers(packet.data) {
                    for (ip, hostname) in mappings {
                        dns_map.insert(ip, hostname.clone());
                        // Update any existing entry that was "manual" to "dns"
                        if let Some(entry) = dest_ips.get_mut(&ip) {
                            entry.hostname = hostname;
                            entry.mapping = "dns";
                        }
                    }
                }

                if let Some(dest) = parse_dest_ip(packet.data) {
                    let entry = dest_ips.entry(dest).or_insert_with(|| {
                        if let Some(name) = dns_map.get(&dest) {
                            IpEntry {
                                packets: 0,
                                hostname: name.clone(),
                                mapping: "dns",
                            }
                        } else {
                            // Reverse DNS lookup
                            let hostname = dns_lookup::lookup_addr(&dest)
                                .unwrap_or_else(|_| dest.to_string());
                            IpEntry {
                                packets: 0,
                                hostname,
                                mapping: "manual",
                            }
                        }
                    });
                    entry.packets += 1;
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
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0800 => {
            let ip_start = 14;
            if data.len() < ip_start + 20 {
                return None;
            }
            let dst: [u8; 4] = data[ip_start + 16..ip_start + 20].try_into().ok()?;
            Some(IpAddr::from(dst))
        }
        0x86DD => {
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

/// Parse DNS response packets and extract (IP, hostname) mappings from answer records.
fn parse_dns_answers(data: &[u8]) -> Option<Vec<(IpAddr, String)>> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Determine IP header length and check for UDP protocol
    let udp_start = match ethertype {
        0x0800 => {
            if data.len() < 14 + 20 {
                return None;
            }
            let ihl = (data[14] & 0x0F) as usize * 4;
            let protocol = data[14 + 9];
            if protocol != 17 {
                return None; // not UDP
            }
            14 + ihl
        }
        0x86DD => {
            if data.len() < 14 + 40 {
                return None;
            }
            let next_header = data[14 + 6];
            if next_header != 17 {
                return None; // not UDP (simplified, ignores extension headers)
            }
            14 + 40
        }
        _ => return None,
    };

    if data.len() < udp_start + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
    // DNS responses come from port 53
    if src_port != 53 {
        return None;
    }

    let dns_start = udp_start + 8;
    if data.len() < dns_start + 12 {
        return None;
    }

    let flags = u16::from_be_bytes([data[dns_start + 2], data[dns_start + 3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return None;
    }

    let qd_count = u16::from_be_bytes([data[dns_start + 4], data[dns_start + 5]]) as usize;
    let an_count = u16::from_be_bytes([data[dns_start + 6], data[dns_start + 7]]) as usize;

    if an_count == 0 {
        return None;
    }

    let dns_payload = &data[dns_start..];
    let mut offset = 12; // skip DNS header

    // Skip question section
    for _ in 0..qd_count {
        offset = skip_dns_name(dns_payload, offset)?;
        offset += 4; // QTYPE + QCLASS
        if offset > dns_payload.len() {
            return None;
        }
    }

    let mut results = Vec::new();

    // Parse answer section
    for _ in 0..an_count {
        // Read the name this answer is for
        let (name, new_offset) = read_dns_name(dns_payload, offset)?;
        offset = new_offset;

        if offset + 10 > dns_payload.len() {
            break;
        }

        let rtype = u16::from_be_bytes([dns_payload[offset], dns_payload[offset + 1]]);
        let rdlength =
            u16::from_be_bytes([dns_payload[offset + 8], dns_payload[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > dns_payload.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                // A record
                let ip = IpAddr::V4(Ipv4Addr::new(
                    dns_payload[offset],
                    dns_payload[offset + 1],
                    dns_payload[offset + 2],
                    dns_payload[offset + 3],
                ));
                results.push((ip, name.clone()));
            }
            28 if rdlength == 16 => {
                // AAAA record
                let b: [u8; 16] = dns_payload[offset..offset + 16].try_into().ok()?;
                let ip = IpAddr::V6(Ipv6Addr::from(b));
                results.push((ip, name.clone()));
            }
            5 => {
                // CNAME - read the canonical name but skip (the next A/AAAA will map it)
            }
            _ => {}
        }

        offset += rdlength;
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Skip over a DNS name (handling compression pointers) and return the new offset.
fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer - 2 bytes total
            return Some(offset + 2);
        }
        offset += 1 + len;
    }
}

/// Read a DNS name, following compression pointers, returning (name, new_offset).
/// The new_offset is the position after the name in the original location (not after following pointers).
fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut offset = start;
    let mut end_offset = None;
    let mut jumps = 0;

    loop {
        if jumps > 10 || offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        if len == 0 {
            if end_offset.is_none() {
                end_offset = Some(offset + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            if end_offset.is_none() {
                end_offset = Some(offset + 2);
            }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset = ptr;
            jumps += 1;
            continue;
        }
        offset += 1;
        if offset + len > data.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&data[offset..offset + len]).to_string());
        offset += len;
    }

    Some((parts.join("."), end_offset.unwrap_or(offset)))
}

fn print_table(ips: &BTreeMap<IpAddr, IpEntry>) {
    let count = ips.len();
    if count > 0 {
        print!("\x1b[{}A", count + 1);
    }
    print!("\x1b[J");

    println!(
        "{:<45} {:>10}  {:<50} {:<7}",
        "Destination IP", "Packets", "Hostname", "Source"
    );
    for (ip, entry) in ips {
        println!(
            "{:<45} {:>10}  {:<50} {:<7}",
            ip, entry.packets, entry.hostname, entry.mapping
        );
    }
}
