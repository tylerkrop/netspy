use pcap::{Capture, Device};
use std::collections::{BTreeMap, BTreeSet};
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
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Clear, Row, Table, TableState},
    Terminal,
};

#[derive(Clone)]
struct IpEntry {
    packets: u64,
    hostname: String,
    mapping: &'static str, // "dns" or "manual"
}

fn open_captures(selected: &BTreeSet<String>) -> Result<Vec<Capture<pcap::Active>>, Box<dyn std::error::Error>> {
    let mut captures = Vec::new();
    let all_devices = Device::list()?;
    for dev in all_devices {
        if selected.contains(&dev.name) {
            let is_loopback = dev.name == "lo0";
            let mut builder = Capture::from_device(dev)?
                .snaplen(65535)
                .timeout(1);
            if !is_loopback {
                builder = builder.promisc(true);
            }
            captures.push(builder.open()?.setnonblock()?);
        }
    }
    Ok(captures)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = Device::lookup()?.expect("No default device found");
    let default_name = device.name.clone();

    let all_iface_names: Vec<String> = Device::list()?
        .iter()
        .map(|d| d.name.clone())
        .collect();

    let mut selected_ifaces: BTreeSet<String> = BTreeSet::new();
    selected_ifaces.insert(default_name.clone());
    if default_name != "lo0" && all_iface_names.contains(&"lo0".to_string()) {
        selected_ifaces.insert("lo0".to_string());
    }

    let mut captures = open_captures(&selected_ifaces)?;
    let mut iface_display = selected_ifaces.iter().cloned().collect::<Vec<_>>().join(",");

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
        &mut captures,
        &mut terminal,
        &mut dest_ips,
        &mut dns_map,
        &mut table_state,
        &mut scroll_offset,
        &mut iface_display,
        &mut selected_ifaces,
        &all_iface_names,
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
    captures: &mut Vec<Capture<pcap::Active>>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    dest_ips: &mut BTreeMap<IpAddr, IpEntry>,
    dns_map: &mut BTreeMap<IpAddr, String>,
    table_state: &mut TableState,
    scroll_offset: &mut usize,
    iface_display: &mut String,
    selected_ifaces: &mut BTreeSet<String>,
    all_iface_names: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_draw = Instant::now();
    let draw_interval = Duration::from_secs(1);
    let mut needs_redraw = true;
    let mut needs_data_refresh = true;
    // Cached sorted snapshot for rendering
    let mut cached_rows: Vec<(IpAddr, IpEntry)> = Vec::new();
    let mut threshold: u64 = 0;
    let mut threshold_input: Option<String> = None; // Some when typing threshold

    // Interface picker state
    let mut iface_picker: Option<IfacePicker> = None;

    loop {
        // Poll for keyboard input (non-blocking)
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if let Some(ref mut picker) = iface_picker {
                    match key.code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            picker.cursor = (picker.cursor + 1).min(all_iface_names.len().saturating_sub(1));
                            needs_redraw = true;
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            picker.cursor = picker.cursor.saturating_sub(1);
                            needs_redraw = true;
                        }
                        KeyCode::Char(' ') => {
                            let name = &all_iface_names[picker.cursor];
                            if picker.selected.contains(name) {
                                picker.selected.remove(name);
                            } else {
                                picker.selected.insert(name.clone());
                            }
                            needs_redraw = true;
                        }
                        KeyCode::Enter => {
                            if !picker.selected.is_empty() {
                                *selected_ifaces = picker.selected.clone();
                                *captures = open_captures(selected_ifaces)?;
                                *iface_display = selected_ifaces.iter().cloned().collect::<Vec<_>>().join(",");
                            }
                            iface_picker = None;
                            needs_redraw = true;
                        }
                        KeyCode::Esc => {
                            iface_picker = None;
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                } else if let Some(ref mut input) = threshold_input {
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
                        KeyCode::Char('i') => {
                            iface_picker = Some(IfacePicker {
                                cursor: 0,
                                selected: selected_ifaces.clone(),
                            });
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Read all available packets from all captures (non-blocking)
        for cap in captures.iter_mut() {
            let link_type = cap.get_datalink();
            loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let data = packet.data;
                    // Parse based on link type
                    let frame = match link_type {
                        pcap::Linktype::ETHERNET => Some(data),
                        pcap::Linktype::NULL => {
                            // BSD loopback: 4-byte header with AF family
                            if data.len() >= 4 {
                                Some(data)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    let Some(frame) = frame else { continue };

                    if link_type == pcap::Linktype::ETHERNET {
                        if let Some(mappings) = parse_dns_answers(frame) {
                            for (ip, hostname) in mappings {
                                dns_map.insert(ip, hostname.clone());
                                let entry = dest_ips.entry(ip).or_insert(IpEntry {
                                    packets: 0,
                                    hostname: hostname.clone(),
                                    mapping: "dns",
                                });
                                entry.hostname = hostname;
                                entry.mapping = "dns";
                            }
                        }

                        if let Some(dest) = parse_dest_ip(frame) {
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
                    } else {
                        // Loopback: only extract DNS answers
                        if let Some(mappings) = parse_dns_answers_loopback(frame) {
                            for (ip, hostname) in mappings {
                                dns_map.insert(ip, hostname.clone());
                                let entry = dest_ips.entry(ip).or_insert(IpEntry {
                                    packets: 0,
                                    hostname: hostname.clone(),
                                    mapping: "dns",
                                });
                                entry.hostname = hostname;
                                entry.mapping = "dns";
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => break,
                Err(e) => return Err(e.into()),
            }
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

        // Compute column widths from data
        let ip_width = cached_rows
            .iter()
            .map(|(ip, _)| ip.to_string().len())
            .max()
            .unwrap_or(0)
            .max("Destination IP".len()) as u16;
        let pkt_width = cached_rows
            .iter()
            .map(|(_, entry)| entry.packets.to_string().len())
            .max()
            .unwrap_or(0)
            .max("Packets".len()) as u16;
        let source_width = "Source".len() as u16;

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
                Constraint::Length(1), // bottom bar
            ])
            .split(area);

            // Top bar: status info
            let top_left = if let Some(ref input) = threshold_input {
                format!(" threshold: {}▏", input)
            } else {
                format!(
                    " netspy — {} | {} IPs",
                    iface_display, total
                )
            };
            let threshold_label = if threshold > 0 {
                format!("min: {} | ", threshold)
            } else {
                String::new()
            };
            let right = format!("{}poll: {}s ", threshold_label, draw_interval.as_secs());
            let bar_width = area.width as usize;
            let pad = bar_width.saturating_sub(top_left.len() + right.len());
            let title = format!("{}{:pad$}{}", top_left, "", right, pad = pad);
            f.render_widget(
                ratatui::widgets::Paragraph::new(title)
                    .style(Style::default().fg(Color::Black).bg(Color::Cyan)),
                chunks[0],
            );

            // Bottom bar: hotkey hints
            let hints = " j/k scroll | g/G top/bottom | t threshold | i ifaces | q quit";
            f.render_widget(
                ratatui::widgets::Paragraph::new(hints)
                    .style(Style::default().fg(Color::Black).bg(Color::Cyan)),
                chunks[2],
            );

            let header = Row::new(vec!["Destination IP", "Packets", "Hostname", "Source"])
                .style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(0);

            let widths = [
                Constraint::Length(ip_width),
                Constraint::Length(pkt_width),
                Constraint::Min(8),
                Constraint::Length(source_width),
            ];

            let table = Table::new(rows, widths)
                .header(header)
                .column_spacing(2)
                .block(Block::default().borders(Borders::NONE))
                .row_highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                );

            f.render_stateful_widget(table, chunks[1], table_state);

            // Interface picker overlay
            if let Some(ref picker) = iface_picker {
                let picker_height = (all_iface_names.len() + 4).min(area.height as usize) as u16;
                let picker_width = 50.min(area.width);
                let x = (area.width.saturating_sub(picker_width)) / 2;
                let y = (area.height.saturating_sub(picker_height)) / 2;
                let popup_area = Rect::new(x, y, picker_width, picker_height);

                f.render_widget(Clear, popup_area);

                let picker_block = Block::default()
                    .title(" Interfaces: j/k move, space toggle, enter apply, esc cancel ")
                    .borders(Borders::ALL)
                    .style(Style::default().bg(Color::Black));

                let inner = picker_block.inner(popup_area);
                f.render_widget(picker_block, popup_area);

                let visible_height = inner.height as usize;
                let picker_scroll = if picker.cursor >= visible_height {
                    picker.cursor - visible_height + 1
                } else {
                    0
                };

                let lines: Vec<ratatui::text::Line> = all_iface_names
                    .iter()
                    .enumerate()
                    .map(|(i, name)| {
                        let check = if picker.selected.contains(name) { "[x]" } else { "[ ]" };
                        let style = if i == picker.cursor {
                            Style::default().fg(Color::Black).bg(Color::White)
                        } else {
                            Style::default().fg(Color::White)
                        };
                        ratatui::text::Line::styled(format!(" {} {}", check, name), style)
                    })
                    .collect();

                f.render_widget(
                    ratatui::widgets::Paragraph::new(lines)
                        .scroll((picker_scroll as u16, 0)),
                    inner,
                );
            }
        })?;
    }
    Ok(())
}

struct IfacePicker {
    cursor: usize,
    selected: BTreeSet<String>,
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
    let ip_start = 14;
    find_and_parse_dns(data, ip_start, ethertype)
}

/// Parse DNS answers from BSD loopback frames (4-byte AF header).
fn parse_dns_answers_loopback(data: &[u8]) -> Option<Vec<(IpAddr, String)>> {
    if data.len() < 4 {
        return None;
    }
    let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    let ethertype = match af {
        2 => 0x0800u16,  // AF_INET
        30 => 0x86DDu16, // AF_INET6 on macOS
        _ => return None,
    };
    find_and_parse_dns(data, 4, ethertype)
}

fn find_and_parse_dns(data: &[u8], ip_start: usize, ethertype: u16) -> Option<Vec<(IpAddr, String)>> {
    let udp_start = match ethertype {
        0x0800 => {
            if data.len() < ip_start + 20 {
                return None;
            }
            let ihl = (data[ip_start] & 0x0F) as usize * 4;
            let protocol = data[ip_start + 9];
            if protocol != 17 {
                return None;
            }
            ip_start + ihl
        }
        0x86DD => {
            if data.len() < ip_start + 40 {
                return None;
            }
            let next_header = data[ip_start + 6];
            if next_header != 17 {
                return None;
            }
            ip_start + 40
        }
        _ => return None,
    };

    if data.len() < udp_start + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
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


