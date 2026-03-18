# netspy

> **Warning:** Everything in this repository is AI-generated.

A terminal-based network monitoring tool that captures live traffic and displays destination IPs, packet counts, and resolved hostnames in a scrollable TUI table.

## Features

- **Live packet capture** across multiple network interfaces (including loopback)
- **Passive DNS snooping** — extracts hostnames from DNS response packets in real time, mapping IPs to domains without active lookups
- **Reverse DNS fallback** — resolves IPs that weren't seen in DNS traffic
- **Interactive TUI** built with [ratatui](https://github.com/ratatui/ratatui)
  - Scroll through results with `j`/`k`
  - Set a minimum packet threshold with `t`
  - Pick which interfaces to monitor with `i`
  - Quit with `q`
- **Summary on exit** — prints a final sorted table of all observed IPs to stdout

## Requirements

- Rust (2024 edition)
- `libpcap` development headers (`libpcap-dev` on Debian/Ubuntu, `libpcap` on macOS via Homebrew)
- Elevated privileges (e.g. `sudo`) or the `CAP_NET_RAW` capability for packet capture

## Build

```sh
cargo build --release
```

## Usage

```sh
sudo ./target/release/netspy
```

The tool automatically selects the default network interface plus loopback. Press `i` to open the interface picker and adjust.

## Keybindings

| Key       | Action                  |
|-----------|-------------------------|
| `j` / `↓` | Scroll down            |
| `k` / `↑` | Scroll up              |
| `g`       | Jump to top             |
| `G`       | Jump to bottom          |
| `t`       | Set packet threshold    |
| `i`       | Open interface picker   |
| `q`       | Quit                    |
