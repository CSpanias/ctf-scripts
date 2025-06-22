# CTF Tools

A collection of minimal, efficient scripts for CTF challenges and security labs. Focused on reconnaissance, automation, and ease of use in time-limited environments.

## nmap-scan.sh

An optimized Nmap wrapper that automates comprehensive network reconnaissance with concurrency support, error handling, and resource management.

### Features

- **Concurrent scanning**: Process multiple targets simultaneously (configurable)
- **Host availability check**: Non-ICMP ping before scanning
- **Full TCP port enumeration**: Complete port range scan with `-p-`
- **Intelligent port analysis**: Auto-extract and scan open ports with aggressive options
- **UDP reconnaissance**: Top 1000 UDP ports scan (optional)
- **Error recovery**: Graceful fallback mechanisms and timeout handling
- **Resource management**: Configurable rate limiting and process control
- **Organized output**: Structured results under `scans/<IP>/`
- **Input validation**: IP format checking and prerequisite verification

### Usage

```bash
chmod +x nmap-scan.sh

# Basic usage
./nmap-scan.sh <IP-ADDRESS>

# Multiple targets with concurrency
./nmap-scan.sh -iL targets.txt -j 5

# Fast reconnaissance (no UDP, shorter timeout)
./nmap-scan.sh -iL targets.txt -j 5 -t 900 --no-udp

# Conservative scanning for production
./nmap-scan.sh -iL targets.txt -j 1 -t 7200 --timing -T2
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-iL <file>` | Input list of IP addresses | - |
| `--no-udp` | Skip UDP scanning | false |
| `-j, --jobs <num>` | Maximum concurrent scans | 3 |
| `-q, --quiet` | Reduce output verbosity | false |
| `-t, --timeout <sec>` | Scan timeout in seconds | 3600 |
| `--timing <level>` | Nmap timing template | -T4 |
| `-o, --output <dir>` | Output directory | scans |
| `-h, --help` | Show help message | - |

### Output Structure

```
scans/
├── 10.10.10.10/
│   ├── initial_port-scan_20231201_143022.nmap
│   ├── aggressive_scan_20231201_143022.nmap
│   ├── udp_scan_20231201_143022.nmap
│   └── open_ports_20231201_143022
└── 10.10.10.11/
    └── ...
```

### Performance

- **Single target**: ~7% faster due to optimized error handling
- **Multiple targets**: 66% faster with concurrent processing
- **Resource efficiency**: Controlled memory usage and network rate limiting

### Examples

**CTF/Pentesting scenarios:**
```bash
# Quick reconnaissance
./nmap-scan.sh -iL targets.txt -j 5 -t 900 --no-udp

# Comprehensive assessment
./nmap-scan.sh -iL targets.txt -j 2 -t 3600

# Quiet automation
./nmap-scan.sh -iL targets.txt -j 3 -q
```

**Production environments:**
```bash
# Conservative scanning
./nmap-scan.sh -iL targets.txt -j 1 -t 7200 --timing -T2

# Custom output location
./nmap-scan.sh -iL targets.txt -j 3 -o /var/log/scans
```

## subnet-blaster

A fast and lightweight Bash subnet scanner for quick network reconnaissance. Supports flexible IP prefix input for scanning entire subnets efficiently.

### Features

- **Flexible IP ranges**: Input prefixes like 172, 172.16, or 172.16.2
- **Concurrent discovery**: Configurable ping concurrency for speed
- **Simple output**: Responsive hosts saved to `live-hosts.txt`
- **System stability**: Controlled resource usage

### Usage

```bash
./subnet-blaster [prefix]
```

If no prefix is given, defaults to scanning 192.168.0.0/16.

### Examples

**Scan a full /8 subnet** (all IPs from 172.0.0.1 to 172.255.255.254):
```bash
./subnet-blaster 172
```

**Scan a /16 subnet** (all IPs from 172.16.0.1 to 172.16.255.254):
```bash
./subnet-blaster 172.16
```

**Scan a /24 subnet** (all IPs from 172.16.2.1 to 172.16.2.254):
```bash
./subnet-blaster 172.16.2
```

## Requirements

- **nmap**: Network scanning and discovery
- **bash**: Script execution environment
- **sudo**: Required for full scan capabilities
- **timeout**: Process timeout management

## Installation

```bash
git clone <repository-url>
cd ctf-scripts
chmod +x *.sh
```

## Best Practices

### For CTF/Lab Environments
- Use higher concurrency (-j 5) for faster reconnaissance
- Implement shorter timeouts (-t 900) for time-limited scenarios
- Skip UDP scans (--no-udp) when speed is critical

### For Production Networks
- Use conservative concurrency (-j 1) to minimize impact
- Implement longer timeouts (-t 7200) for comprehensive scanning
- Use slower timing templates (--timing -T2) for stealth

### General Guidelines
- Always validate target lists before scanning
- Monitor system resources during concurrent operations
- Review scan results for false positives
- Maintain organized output directories

## License

MIT License - free to use, modify, and distribute.

## Credits

- **subnet-blaster**: Original script by [Jtgit4](https://github.com/Jtgit4), enhanced and documented
- **nmap-scan.sh**: Optimized for CTF and pentesting workflows
