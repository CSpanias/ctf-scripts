# 🛠️ CTF Tools

A collection of small, efficient scripts I use while working on CTF challenges and security labs. These are primarily focused on reconnaissance, automation, and ease of use in time-limited or learning-focused environments.

---

## 📜 Included Tools

### `nmap_scan.sh`

A wrapper around Nmap that automates a full TCP scan, extracts open ports, performs aggressive scanning on open ports, and finishes with a top 1000 UDP ports scan.

#### 🔧 Features

- Host availability check (non-ICMP)
- Full TCP port scan with `-p-`
- Auto-extract and scan open ports with `-A`
- Top 1000 UDP scan
- Neatly organized output under `scans/<IP>/`
- Interactive option to view results immediately

#### 🧪 Usage

```bash
chmod +x nmap_scan.sh
./nmap_scan.sh <IP-ADDRESS>
```

Example:

```bash
./nmap_scan.sh 10.10.10.10
```

Scans are saved under:

```swift
scans/10.10.10.10/
```

#### 📦 Output Files

- `initial_port-scan_<timestamp>.nmap` — full TCP scan
- `open_ports_<timestamp>` — list of open TCP ports
- `aggressive_scan_<timestamp>.nmap` — detailed scan of open TCP ports
- `udp_scan_<timestamp>.nmap` — top 1000 UDP port scan

#### ⚠️ Requirements

- `nmap`
- `bash`
- `sudo` privileges for some scans

#### 📌 Notes
- Designed for learning, not stealth.
- Scans can be noisy; use responsibly.
- Results are timestamped for comparison and auditing.

💡 Planned Additions
- SMB/HTTP enumeration helpers
- Auto Fuff wrappers

🧠 License
MIT License — free to use, modify, and share.
