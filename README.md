# 🛠️ CTF Tools

A collection of small, efficient scripts I use while working on CTF challenges and security labs. These are primarily focused on reconnaissance, automation, and ease of use in time-limited or learning-focused environments.

---

## `nmap-scan.sh`

A wrapper around Nmap that automates a full TCP scan, extracts open ports, performs aggressive scanning on those ports, and finishes with a top 1000 UDP ports scan.

### Features

- Host availability check (non-ICMP)
- Full TCP port scan with `-p-`
- Auto-extract and scan open ports with `-A`
- Top 1000 UDP scan
- Optional input list with -iL <file>
- Live preview of aggressive scan results before long UDP scans
- Neatly organized output under `scans/<IP>/`
- Interactive option to view results immediately

### Usage

```bash
chmod +x nmap_scan.sh
./nmap_scan.sh <IP-ADDRESS>
./nmap_scan.sh -iL ip_list.txt
```
### Example

```bash
./nmap_scan.sh 10.10.10.10
```
Scans are saved under:
```bash
scans/10.10.10.10/
```

### Output Files

- `initial_port-scan_<timestamp>.nmap` — full TCP scan
- `open_ports_<timestamp>` — list of open TCP ports
- `aggressive_scan_<timestamp>.nmap` — detailed scan of open TCP ports
- `udp_scan_<timestamp>.nmap` — top 1000 UDP port scan

## `subnet-blaster`
A fast and lightweight Bash subnet scanner designed for quick network reconnaissance. It supports flexible IP prefix input, allowing you to scan entire /8, /16, or /24 subnets by specifying 1 to 3 octets. The tool uses concurrent pings with configurable concurrency limits to efficiently discover live hosts.

### Features
- Scan large IP ranges with ease: input prefixes like 172, 172.16, or 172.16.2
- Outputs responsive hosts to `live-hosts.txt`
- Limits concurrent ping jobs for system stability and speed
- Simple to customize and extend

### Usage
```bash
./subnet-blaster [prefix]
```
If no prefix is given, defaults to scanning 192.168.0.0/16.

### Examples
Scan a full /8 subnet (all IPs from 172.0.0.1 to 172.255.255.254):
```bash
./subnet-blaster 172
```
Scan a /16 subnet (all IPs from 172.16.0.1 to 172.16.255.254):
```bash
./subnet-blaster 172.16
```
Scan a /24 subnet (all IPs from 172.16.2.1 to 172.16.2.254):
```bash
./subnet-blaster 172.16.2
```

### Credits
Original script by [Jtgit4](https://github.com/Jtgit4).
Enhanced and documented by x7331.

🧠 License
MIT License — free to use, modify, and share.
