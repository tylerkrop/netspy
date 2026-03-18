use pcap::{Capture, Device};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Terminal,
};

#[derive(Clone)]
struct IpEntry {
    packets: u64,
    hostname: String,
    mapping: &'static str, // "dns" or "manual"
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = Device::lookup()?.expect("No default device found");
    let device_name = device.name.clone();

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1)
        .open()?
        .setnonblock()?;

    // Enter raw mode / alternate screen
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut dest_ips: BTreeMap<IpAddr, IpEntry> = BTreeMap::new();
    let mut dns_map: BTreeMap<IpAddr, String> = BTreeMap::new();
    let mut table_state = TableState::default();
    let mut scroll_offset: usize = 0;

    let result = run_loop(
        &mut cap,
        &mut terminal,
        &mut dest_ips,
        &mut dns_map,
        &mut table_state,
        &mut scroll_offset,
        &device_name,
    );

    // Restore terminal
    terminal::disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;

    if let Err(e) = result {
        eprintln!("Error: {e}");
    }

    // Print final summary to normal stdout
    let mut sorted: Vec<_> = dest_ips.iter().collect();
    sorted.sort_by(|a, b| b.1.packets.cmp(&a.1.packets));
    println!("\n--- Final Summary ---");
    println!(
        "{:<45} {:>10}  {:<50} {:<7}",
        "Destination IP", "Packets", "Hostname", "Source"
    );
    for (ip, entry) in &sorted {
        println!(
            "{:<45} {:>10}  {:<50} {:<7}",
            ip, entry.packets, entry.hostname, entry.mapping
        );
    }
    println!("\nTotal unique IPs: {}", dest_ips.len());

    Ok(())
}

fn run_loop(
    cap: &mut Capture<pcap::Active>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    dest_ips: &mut BTreeMap<IpAddr, IpEntry>,
    dns_map: &mut BTreeMap<IpAddr, String>,
    table_state: &mut TableState,
    scroll_offset: &mut usize,
    device_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_draw = Instant::now();
    let draw_interval = Duration::from_secs(1);
    let mut needs_redraw = true;
    let mut needs_data_refresh = true;
    // Cached sorted snapshot for rendering
    let mut cached_rows: Vec<(IpAddr, IpEntry)> = Vec::new();
    let mut threshold: u64 = 0;
    let mut threshold_input: Option<String> = None; // Some when typing threshold

    loop {
        // Poll for keyboard input (non-blocking)
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if let Some(ref mut input) = threshold_input {
                    // Threshold input mode
                    match key.code {
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            input.push(c);
                            needs_redraw = true;
                        }
                        KeyCode::Backspace => {
                            input.pop();
                            needs_redraw = true;
                        }
                        KeyCode::Enter => {
                            threshold = input.parse().unwrap_or(0);
                            threshold_input = None;
                            needs_data_refresh = true;
                            needs_redraw = true;
                        }
                        KeyCode::Esc => {
                            threshold_input = None;
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Char('q') => break,
                        KeyCode::Char('j') | KeyCode::Down => {
                            *scroll_offset = scroll_offset.saturating_add(1);
                            needs_redraw = true;
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            *scroll_offset = scroll_offset.saturating_sub(1);
                            needs_redraw = true;
                        }
                        KeyCode::Char('g') => {
                            *scroll_offset = 0;
                            needs_redraw = true;
                        }
                        KeyCode::Char('G') => {
                            *scroll_offset = dest_ips.len().saturating_sub(1);
                            needs_redraw = true;
                        }
                        KeyCode::Char('t') => {
                            threshold_input = Some(String::new());
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Read all available packets (non-blocking)
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(mappings) = parse_dns_answers(packet.data) {
                        for (ip, hostname) in mappings {
                            dns_map.insert(ip, hostname.clone());
                            // Add or update dest_ips immediately so DNS results are visible
                            let entry = dest_ips.entry(ip).or_insert(IpEntry {
                                packets: 0,
                                hostname: hostname.clone(),
                                mapping: "dns",
                            });
                            entry.hostname = hostname;
                            entry.mapping = "dns";
                        }
                    }

                    if let Some(dest) = parse_dest_ip(packet.data) {
                        let dns = dns_map.clone();
                        let entry = dest_ips.entry(dest).or_insert_with(|| {
                            if let Some(name) = dns.get(&dest) {
                                IpEntry {
                                    packets: 0,
                                    hostname: name.clone(),
                                    mapping: "dns",
                                }
                            } else {
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
                    }
                }
                Err(pcap::Error::TimeoutExpired) => break,
                Err(e) => return Err(e.into()),
            }
        }

        // Only redraw on key input or once per second
        let now = Instant::now();
        let timer_tick = now.duration_since(last_draw) >= draw_interval;
        if timer_tick {
            needs_data_refresh = true;
            needs_redraw = true;
        }
        if !needs_redraw {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        needs_redraw = false;

        // Rebuild sorted data only on timer ticks, not on key input
        if needs_data_refresh {
            needs_data_refresh = false;
            last_draw = now;
            cached_rows = dest_ips
                .iter()
                .map(|(ip, entry)| (*ip, entry.clone()))
                .collect();
            cached_rows.sort_by(|a, b| b.1.packets.cmp(&a.1.packets));
            if threshold > 0 {
                cached_rows.retain(|(_ip, entry)| entry.packets >= threshold);
            }
        }

        let total = cached_rows.len();

        // Clamp scroll offset
        if total > 0 {
            *scroll_offset = (*scroll_offset).min(total - 1);
        }

        // Select the row at scroll_offset so ratatui scrolls the table
        if total > 0 {
            table_state.select(Some(*scroll_offset));
        }

        let rows: Vec<Row> = cached_rows
            .iter()
            .map(|(ip, entry)| {
                Row::new(vec![
                    Cell::from(ip.to_string()),
                    Cell::from(entry.packets.to_string()),
                    Cell::from(entry.hostname.clone()),
                    Cell::from(entry.mapping.to_string()),
                ])
            })
            .collect();

        terminal.draw(|f| {
            let area = f.area();

            let chunks = Layout::vertical([
                Constraint::Length(1), // title bar
                Constraint::Min(0),    // table
            ])
            .split(area);

            let left = if let Some(ref input) = threshold_input {
                format!(" threshold: {}▏", input)
            } else {
                format!(
                    " netspy — {} | {} IPs | j/k scroll, g/G top/bottom, t threshold, q quit",
                    device_name, total
                )
            };
            let threshold_label = if threshold > 0 {
                format!("min: {} | ", threshold)
            } else {
                String::new()
            };
            let right = format!("{}poll: {}s ", threshold_label, draw_interval.as_secs());
            let bar_width = area.width as usize;
            let pad = bar_width.saturating_sub(left.len() + right.len());
            let title = format!("{}{:pad$}{}", left, "", right, pad = pad);
            f.render_widget(
                ratatui::widgets::Paragraph::new(title)
                    .style(Style::default().fg(Color::Black).bg(Color::Cyan)),
                chunks[0],
            );

            let header = Row::new(vec!["Destination IP", "Packets", "Hostname", "Source"])
                .style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(0);

            let widths = [
                Constraint::Min(20),
                Constraint::Length(12),
                Constraint::Min(30),
                Constraint::Length(8),
            ];

            let table = Table::new(rows, widths)
                .header(header)
                .block(Block::default().borders(Borders::NONE))
                .row_highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                );

            f.render_stateful_widget(table, chunks[1], table_state);
        })?;
    }
    Ok(())
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


